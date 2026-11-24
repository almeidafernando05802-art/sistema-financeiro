/**
 * server.js — Backend completo do Sistema Financeiro
 * Node.js + Express + Supabase | Deploy: Vercel (zero-config Express)
 *
 * Seções:
 *  1. Configuração e validação do ambiente
 *  2. Clientes Supabase
 *  3. Middlewares globais (Helmet, CORS, JSON, cookies, CSRF, rate limit)
 *  4. Utilitários (erros, cookies, validação)
 *  5. Autenticação e autorização
 *  6. Rotas de autenticação
 *  7. Rotas de transações
 *  8. Rota de dashboard do usuário
 *  9. Rotas administrativas
 * 10. Health check, 404 e tratamento centralizado de erros
 * 11. Exportação (Vercel) e servidor local
 */

// =====================================================================
// 1. CONFIGURAÇÃO E VALIDAÇÃO DO AMBIENTE
// =====================================================================
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { z } = require('zod');
const { createClient } = require('@supabase/supabase-js');

// Lê e LIMPA as variáveis (espaços, aspas e barra final causam "fetch failed")
function readEnv(name, { required = true } = {}) {
  const raw = process.env[name];
  const value = (raw || '').trim().replace(/^["']|["']$/g, '');
  if (required && !value) {
    throw new Error(`[config] Variável de ambiente ausente: ${name}`);
  }
  return value;
}

const SUPABASE_URL = readEnv('SUPABASE_URL').replace(/\/+$/, '').replace(/\/(rest|auth)\/v1$/, '');
const SUPABASE_ANON_KEY = readEnv('SUPABASE_ANON_KEY');
const SUPABASE_SERVICE_ROLE_KEY = readEnv('SUPABASE_SERVICE_ROLE_KEY');
const ADMIN_EMAIL = readEnv('ADMIN_EMAIL').toLowerCase();
const NODE_ENV = readEnv('NODE_ENV', { required: false }) || 'development';
const IS_PROD = NODE_ENV === 'production';
const FRONTEND_ORIGINS = readEnv('FRONTEND_ORIGIN')
  .split(',')
  .map((o) => o.trim().replace(/\/+$/, ''))
  .filter(Boolean);
const FRONTEND_ORIGIN = FRONTEND_ORIGINS[0];

// Falha cedo e com mensagem clara se a URL estiver malformada
if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(SUPABASE_URL) && IS_PROD) {
  throw new Error(`[config] SUPABASE_URL inválida: "${SUPABASE_URL}". Formato esperado: https://SEU-PROJETO.supabase.co`);
}
if (IS_PROD && FRONTEND_ORIGINS.some((o) => o === '*' || !o.startsWith('https://'))) {
  throw new Error('[config] FRONTEND_ORIGIN deve ser um endereço https exato em produção (nunca "*").');
}

// =====================================================================
// 2. CLIENTES SUPABASE
// =====================================================================
const supabaseOptions = {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
};

// Cliente "público": login, cadastro, refresh, recuperação de senha
const supabaseAuth = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, supabaseOptions);

// Cliente privilegiado: SOMENTE operações administrativas (ignora RLS)
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, supabaseOptions);

// Cliente "como o usuário": o RLS do Postgres enxerga o usuário real
function supabaseAsUser(accessToken) {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    ...supabaseOptions,
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
  });
}

// =====================================================================
// 3. MIDDLEWARES GLOBAIS
// =====================================================================
const app = express();
app.set('trust proxy', 1); // Vercel fica atrás de proxy: necessário para IP real no rate limit
app.disable('x-powered-by');

// Helmet: cabeçalhos de segurança (CSP permite apenas o próprio domínio)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"], // index.html único tem <script> embutido
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: IS_PROD ? [] : null, // em http://localhost não pode forçar https
      },
    },
  })
);

// Bloqueia explicitamente origens não autorizadas (antes do CORS)
function isAllowedOrigin(origin) {
  if (!origin) return true; // mesma origem (GET), Postman, curl
  if (FRONTEND_ORIGINS.includes(origin)) return true;
  if (!IS_PROD && /^http:\/\/localhost:\d+$/.test(origin)) return true;
  return false;
}
app.use('/api', (req, res, next) => {
  const origin = req.get('Origin');
  if (!isAllowedOrigin(origin)) {
    return res.status(403).json({ error: 'Origem não autorizada', code: 'CORS_BLOCKED' });
  }
  next();
});

// CORS restritivo (nunca "*" com credentials)
app.use(
  '/api',
  cors({
    origin: (origin, cb) => cb(null, isAllowedOrigin(origin) ? origin || false : false),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 600,
    optionsSuccessStatus: 204,
  })
);

app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());

// CSRF: requisições que alteram dados exigem o cabeçalho customizado.
// Um formulário malicioso de outro site não consegue enviá-lo sem preflight,
// e o preflight é barrado pelo CORS. Somado a SameSite=Strict.
app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.get('X-Requested-With') !== 'fetch') {
    return res.status(403).json({ error: 'Requisição bloqueada (CSRF)', code: 'CSRF' });
  }
  next();
});

// Rate limiting
const json429 = (message) => (req, res) => res.status(429).json({ error: message, code: 'RATE_LIMIT' });
const emailKey = (req) => `${ipKeyGenerator(req.ip)}:${String(req.body?.email || '').toLowerCase()}`;
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false, handler: json429('Muitas requisições. Tente novamente em alguns minutos.') });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, keyGenerator: emailKey, handler: json429('Muitas tentativas de login. Aguarde 15 minutos.') });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, handler: json429('Muitos cadastros a partir deste endereço. Tente mais tarde.') });
const emailLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 3, keyGenerator: emailKey, handler: json429('Limite de solicitações atingido. Aguarde antes de pedir outro e-mail.') });
app.use('/api', apiLimiter);

// =====================================================================
// 4. UTILITÁRIOS
// =====================================================================
class HttpError extends Error {
  constructor(status, message, code, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

// Envolve rotas async para que erros caiam no handler central
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Converte erros do Supabase em respostas claras (NUNCA devolve "fetch failed" cru)
function fromSupabase(error, fallbackMessage = 'Erro ao processar a solicitação') {
  if (!error) return null;
  const msg = String(error.message || '');
  const code = error.code || '';

  // Falha de rede entre Vercel e Supabase
  if (msg.includes('fetch failed') || error.name === 'AuthRetryableFetchError' || error.status === 0) {
    console.error('[supabase] Falha de conexão:', msg, error.cause || '');
    return new HttpError(503, 'Serviço de autenticação/banco indisponível. Tente novamente em instantes.', 'SUPABASE_UNREACHABLE');
  }
  // Limite de e-mails do Supabase Auth
  if (code === 'over_email_send_rate_limit' || /email rate limit/i.test(msg)) {
    return new HttpError(429, 'Limite de envio de e-mails atingido. Aguarde alguns minutos e tente novamente.', 'EMAIL_RATE_LIMIT');
  }
  if (code === 'over_request_rate_limit' || error.status === 429) {
    return new HttpError(429, 'Muitas solicitações. Aguarde e tente novamente.', 'RATE_LIMIT');
  }
  if (code === 'email_address_not_authorized') {
    console.error('[supabase] SMTP padrão só envia para a equipe do projeto. Configure SMTP próprio.');
    return new HttpError(503, 'Envio de e-mail não configurado. Contate o suporte.', 'SMTP_NOT_CONFIGURED');
  }
  if (code === 'weak_password') return new HttpError(400, 'Senha fraca. Use ao menos 10 caracteres com letras e números.', 'WEAK_PASSWORD');
  if (code === 'email_not_confirmed') return new HttpError(403, 'Confirme seu e-mail antes de entrar.', 'EMAIL_NOT_CONFIRMED');
  if (code === '23505') return new HttpError(409, 'Registro duplicado.', 'DUPLICATE');
  if (code === '42501') return new HttpError(403, 'Operação não permitida.', 'FORBIDDEN');

  console.error('[supabase]', code, msg);
  return new HttpError(error.status && error.status < 500 ? error.status : 500, fallbackMessage, code || 'SUPABASE_ERROR');
}

// Valida com Zod; propriedades desconhecidas (ex.: role, user_id) são DESCARTADAS
function validate(schema, data) {
  const result = schema.safeParse(data);
  if (!result.success) {
    const details = result.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message }));
    throw new HttpError(400, 'Dados inválidos', 'VALIDATION', details);
  }
  return result.data;
}

const uuidSchema = z.string().uuid('ID inválido');

// Escapa curingas do LIKE (% _ \) para busca literal
const escapeLike = (s) => s.replace(/[\\%_]/g, (c) => `\\${c}`);
// Para filtros .or() do PostgREST: só caracteres seguros
const safeSearch = (s) => s.replace(/[^\p{L}\p{N}@.\-_ ]/gu, '').slice(0, 100);

// Cookies de sessão
const baseCookie = { httpOnly: true, secure: IS_PROD, sameSite: 'strict' };
const ACCESS_COOKIE = 'sb_access';
const REFRESH_COOKIE = 'sb_refresh';

function setSessionCookies(res, session) {
  res.cookie(ACCESS_COOKIE, session.access_token, { ...baseCookie, path: '/api', maxAge: (session.expires_in || 3600) * 1000 });
  res.cookie(REFRESH_COOKIE, session.refresh_token, { ...baseCookie, path: '/api/auth', maxAge: 30 * 24 * 60 * 60 * 1000 });
}
function clearSessionCookies(res) {
  res.clearCookie(ACCESS_COOKIE, { ...baseCookie, path: '/api' });
  res.clearCookie(REFRESH_COOKIE, { ...baseCookie, path: '/api/auth' });
}

const publicProfile = (p) => ({ id: p.id, name: p.name, email: p.email, role: p.role, status: p.status, created_at: p.created_at });

async function audit(userId, action, entity, entityId, metadata = {}) {
  const { error } = await supabaseAdmin.from('audit_logs').insert({ user_id: userId, action, entity, entity_id: entityId, metadata });
  if (error) console.error('[audit] falha ao registrar:', error.message);
}

// =====================================================================
// 5. AUTENTICAÇÃO E AUTORIZAÇÃO
// =====================================================================
function extractToken(req) {
  const header = req.get('Authorization') || '';
  if (header.startsWith('Bearer ')) return header.slice(7).trim(); // Postman/Insomnia
  return req.cookies?.[ACCESS_COOKIE] || null;
}

// Valida o JWT no Supabase Auth (assinatura, expiração e se o usuário ainda existe)
const requireAuth = asyncHandler(async (req, res, next) => {
  const token = extractToken(req);
  if (!token) throw new HttpError(401, 'Não autenticado', 'NO_TOKEN');

  const { data, error } = await supabaseAuth.auth.getUser(token);
  if (error || !data?.user) {
    if (error && fromSupabase(error)?.code === 'SUPABASE_UNREACHABLE') throw fromSupabase(error);
    throw new HttpError(401, 'Sessão inválida ou expirada', 'INVALID_TOKEN');
  }

  const { data: profile, error: pErr } = await supabaseAdmin
    .from('profiles')
    .select('id, name, email, role, status, created_at')
    .eq('id', data.user.id)
    .maybeSingle();
  if (pErr) throw fromSupabase(pErr);
  if (!profile) throw new HttpError(403, 'Perfil não encontrado', 'NO_PROFILE');
  if (profile.status !== 'active') throw new HttpError(403, 'Conta desativada. Contate o administrador.', 'INACTIVE');

  req.user = data.user;
  req.profile = profile;
  req.token = token;
  req.db = supabaseAsUser(token); // consultas sujeitas ao RLS
  next();
});

// Admin = role 'admin' no banco E e-mail igual a ADMIN_EMAIL
function requireAdmin(req, res, next) {
  const p = req.profile;
  if (!p || p.role !== 'admin' || p.email.toLowerCase() !== ADMIN_EMAIL) {
    return next(new HttpError(403, 'Acesso restrito ao administrador', 'NOT_ADMIN'));
  }
  next();
}

// =====================================================================
// 6. ROTAS DE AUTENTICAÇÃO
// =====================================================================
const emailField = z.string().trim().toLowerCase().max(254).email('E-mail inválido');
const passwordField = z
  .string()
  .min(10, 'A senha deve ter ao menos 10 caracteres')
  .max(72, 'A senha deve ter no máximo 72 caracteres')
  .regex(/[a-z]/, 'Inclua uma letra minúscula')
  .regex(/[A-Z]/, 'Inclua uma letra maiúscula')
  .regex(/[0-9]/, 'Inclua um número');

const registerSchema = z
  .object({
    name: z.string().trim().min(2, 'Informe o nome completo').max(120),
    email: emailField,
    password: passwordField,
    confirmPassword: z.string(),
  })
  .refine((d) => d.password === d.confirmPassword, { message: 'As senhas não coincidem', path: ['confirmPassword'] });

// POST /api/auth/register — cadastro público (SEMPRE role user)
app.post('/api/auth/register', registerLimiter, asyncHandler(async (req, res) => {
  // "role" enviado pelo cliente é descartado pelo Zod; o trigger grava 'user'
  const { name, email, password } = validate(registerSchema, req.body);

  const { data, error } = await supabaseAuth.auth.signUp({
    email,
    password,
    options: { data: { name }, emailRedirectTo: `${FRONTEND_ORIGIN}/?confirmado=1` },
  });

  if (error) {
    if (error.code === 'user_already_exists' || error.code === 'email_exists') {
      throw new HttpError(409, 'Este e-mail já está cadastrado', 'EMAIL_EXISTS');
    }
    throw fromSupabase(error, 'Não foi possível concluir o cadastro');
  }
  // Com confirmação de e-mail ativa, e-mail já existente volta sem identities
  if (data.user && Array.isArray(data.user.identities) && data.user.identities.length === 0) {
    throw new HttpError(409, 'Este e-mail já está cadastrado', 'EMAIL_EXISTS');
  }

  res.status(201).json({
    message: data.session
      ? 'Conta criada com sucesso.'
      : 'Conta criada. Enviamos um link de confirmação para o seu e-mail.',
    requiresEmailConfirmation: !data.session,
  });
}));

const loginSchema = z.object({ email: emailField, password: z.string().min(1).max(72) });

// POST /api/auth/login
app.post('/api/auth/login', loginLimiter, asyncHandler(async (req, res) => {
  const { email, password } = validate(loginSchema, req.body);

  const { data, error } = await supabaseAuth.auth.signInWithPassword({ email, password });
  if (error) {
    const mapped = fromSupabase(error);
    if (['SUPABASE_UNREACHABLE', 'EMAIL_NOT_CONFIRMED', 'RATE_LIMIT'].includes(mapped.code)) throw mapped;
    throw new HttpError(401, 'E-mail ou senha inválidos', 'INVALID_CREDENTIALS'); // mensagem genérica
  }

  const { data: profile, error: pErr } = await supabaseAdmin
    .from('profiles').select('id, name, email, role, status, created_at').eq('id', data.user.id).maybeSingle();
  if (pErr) throw fromSupabase(pErr);
  if (!profile || profile.status !== 'active') {
    await supabaseAdmin.auth.admin.signOut(data.session.access_token).catch(() => {});
    throw new HttpError(403, 'Conta desativada. Contate o administrador.', 'INACTIVE');
  }

  setSessionCookies(res, data.session);
  const isAdmin = profile.role === 'admin' && profile.email === ADMIN_EMAIL;
  res.json({ user: publicProfile(profile), area: isAdmin ? 'admin' : 'dashboard' });
}));

// POST /api/auth/logout — revoga refresh tokens no Supabase e limpa cookies
app.post('/api/auth/logout', asyncHandler(async (req, res) => {
  const token = extractToken(req);
  if (token) await supabaseAdmin.auth.admin.signOut(token).catch(() => {});
  clearSessionCookies(res);
  res.json({ message: 'Sessão encerrada' });
}));

// POST /api/auth/refresh — renova a sessão usando o cookie HttpOnly
app.post('/api/auth/refresh', asyncHandler(async (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE];
  if (!refreshToken) throw new HttpError(401, 'Sessão expirada', 'NO_REFRESH');

  const { data, error } = await supabaseAuth.auth.refreshSession({ refresh_token: refreshToken });
  if (error || !data?.session) {
    clearSessionCookies(res);
    const mapped = error && fromSupabase(error);
    if (mapped?.code === 'SUPABASE_UNREACHABLE') throw mapped;
    throw new HttpError(401, 'Sessão expirada. Faça login novamente.', 'REFRESH_FAILED');
  }
  setSessionCookies(res, data.session);
  res.json({ message: 'Sessão renovada' });
}));

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, (req, res) => {
  const isAdmin = req.profile.role === 'admin' && req.profile.email === ADMIN_EMAIL;
  res.json({ user: publicProfile(req.profile), area: isAdmin ? 'admin' : 'dashboard' });
});

// POST /api/auth/forgot-password — resposta sempre genérica (não revela se o e-mail existe)
app.post('/api/auth/forgot-password', emailLimiter, asyncHandler(async (req, res) => {
  const { email } = validate(z.object({ email: emailField }), req.body);

  const { error } = await supabaseAuth.auth.resetPasswordForEmail(email, {
    redirectTo: `${FRONTEND_ORIGIN}/?redefinir-senha=1`, // o Supabase acrescenta #access_token=...&type=recovery
  });
  if (error) {
    const mapped = fromSupabase(error);
    // Limites e falhas de infraestrutura são informados; o resto vira resposta genérica
    if (['EMAIL_RATE_LIMIT', 'RATE_LIMIT', 'SUPABASE_UNREACHABLE', 'SMTP_NOT_CONFIGURED'].includes(mapped.code)) throw mapped;
  }
  res.json({ message: 'Se o e-mail estiver cadastrado, você receberá um link para redefinir a senha.' });
}));

// POST /api/auth/reset-password — recebe o access_token do link de recuperação
const resetSchema = z
  .object({ accessToken: z.string().min(20), password: passwordField, confirmPassword: z.string() })
  .refine((d) => d.password === d.confirmPassword, { message: 'As senhas não coincidem', path: ['confirmPassword'] });

app.post('/api/auth/reset-password', asyncHandler(async (req, res) => {
  const { accessToken, password } = validate(resetSchema, req.body);

  const { data, error } = await supabaseAuth.auth.getUser(accessToken);
  if (error || !data?.user) throw new HttpError(401, 'Link inválido ou expirado. Solicite outro.', 'INVALID_RECOVERY');

  const { error: uErr } = await supabaseAdmin.auth.admin.updateUserById(data.user.id, { password });
  if (uErr) throw fromSupabase(uErr, 'Não foi possível redefinir a senha');

  await supabaseAdmin.auth.admin.signOut(accessToken, 'global').catch(() => {}); // derruba sessões antigas
  await audit(data.user.id, 'password_reset', 'auth', data.user.id);
  clearSessionCookies(res);
  res.json({ message: 'Senha redefinida. Faça login com a nova senha.' });
}));

// =====================================================================
// 7. ROTAS DE TRANSAÇÕES (dono = usuário autenticado; RLS como segunda barreira)
// =====================================================================
const PAYMENT_METHODS = ['pix', 'cash', 'debit', 'credit', 'transfer', 'boleto', 'other'];

const amountField = z
  .union([z.number(), z.string()])
  .transform((v) => String(v).trim().replace(',', '.'))
  .refine((v) => /^\d{1,12}(\.\d{1,2})?$/.test(v) && Number(v) > 0, 'Valor deve ser positivo com até 2 casas decimais');

const transactionSchema = z.object({
  description: z.string().trim().min(1, 'Informe a descrição').max(200),
  amount: amountField, // enviado como string ao NUMERIC: sem erro de ponto flutuante
  type: z.enum(['income', 'expense']),
  category: z.string().trim().min(1, 'Informe a categoria').max(60),
  transaction_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Data no formato AAAA-MM-DD'),
  payment_method: z.enum(PAYMENT_METHODS),
  notes: z.string().trim().max(1000).optional().nullable(),
});

const listSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(50).default(10),
  type: z.enum(['income', 'expense']).optional(),
  category: z.string().trim().max(60).optional(),
  search: z.string().trim().max(100).optional(),
  order: z.enum(['asc', 'desc']).default('desc'),
});

const TX_COLUMNS = 'id, description, amount, type, category, transaction_date, payment_method, notes, created_at, updated_at';

// GET /api/transactions
app.get('/api/transactions', requireAuth, asyncHandler(async (req, res) => {
  const q = validate(listSchema, req.query);
  const from = (q.page - 1) * q.pageSize;

  let query = req.db
    .from('transactions')
    .select(TX_COLUMNS, { count: 'exact' })
    .eq('user_id', req.user.id); // user_id vem do JWT, nunca do cliente

  if (q.type) query = query.eq('type', q.type);
  if (q.category) query = query.eq('category', q.category);
  if (q.search) query = query.ilike('description', `%${escapeLike(q.search)}%`);

  const { data, error, count } = await query
    .order('transaction_date', { ascending: q.order === 'asc' })
    .order('created_at', { ascending: q.order === 'asc' })
    .range(from, from + q.pageSize - 1);
  if (error) throw fromSupabase(error);

  res.json({ data, pagination: { page: q.page, pageSize: q.pageSize, total: count, totalPages: Math.ceil((count || 0) / q.pageSize) } });
}));

// GET /api/transactions/:id
app.get('/api/transactions/:id', requireAuth, asyncHandler(async (req, res) => {
  const id = validate(uuidSchema, req.params.id);
  const { data, error } = await req.db.from('transactions').select(TX_COLUMNS).eq('id', id).eq('user_id', req.user.id).maybeSingle();
  if (error) throw fromSupabase(error);
  if (!data) throw new HttpError(404, 'Transação não encontrada', 'NOT_FOUND');
  res.json({ data });
}));

// POST /api/transactions
app.post('/api/transactions', requireAuth, asyncHandler(async (req, res) => {
  const body = validate(transactionSchema, req.body); // user_id do corpo é descartado
  const { data, error } = await req.db.from('transactions').insert({ ...body, user_id: req.user.id }).select(TX_COLUMNS).single();
  if (error) throw fromSupabase(error);
  res.status(201).json({ data });
}));

// PUT /api/transactions/:id
app.put('/api/transactions/:id', requireAuth, asyncHandler(async (req, res) => {
  const id = validate(uuidSchema, req.params.id);
  const body = validate(transactionSchema, req.body);
  const { data, error } = await req.db.from('transactions').update(body).eq('id', id).eq('user_id', req.user.id).select(TX_COLUMNS).maybeSingle();
  if (error) throw fromSupabase(error);
  if (!data) throw new HttpError(404, 'Transação não encontrada', 'NOT_FOUND');
  res.json({ data });
}));

// DELETE /api/transactions/:id
app.delete('/api/transactions/:id', requireAuth, asyncHandler(async (req, res) => {
  const id = validate(uuidSchema, req.params.id);
  const { data, error } = await req.db.from('transactions').delete().eq('id', id).eq('user_id', req.user.id).select('id').maybeSingle();
  if (error) throw fromSupabase(error);
  if (!data) throw new HttpError(404, 'Transação não encontrada', 'NOT_FOUND');
  res.status(204).end();
}));

// =====================================================================
// 8. DASHBOARD DO USUÁRIO
// =====================================================================
// GET /api/dashboard/summary — somas feitas no Postgres (NUMERIC exato)
app.get('/api/dashboard/summary', requireAuth, asyncHandler(async (req, res) => {
  const { data, error } = await req.db.rpc('dashboard_summary');
  if (error) throw fromSupabase(error);
  const row = (Array.isArray(data) ? data[0] : data) || {};
  res.json({
    totalIncome: String(row.total_income ?? '0'),
    totalExpenses: String(row.total_expenses ?? '0'),
    balance: String(row.balance ?? '0'),
    transactionCount: Number(row.transaction_count ?? 0),
  });
}));

// =====================================================================
// 9. ROTAS ADMINISTRATIVAS (autenticação + requireAdmin; sem dados financeiros)
// =====================================================================
const adminListSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().trim().max(100).optional(),
  status: z.enum(['active', 'inactive']).optional(),
});

async function listUsers(req, res) {
  const q = validate(adminListSchema, req.query);
  const from = (q.page - 1) * q.pageSize;

  let query = supabaseAdmin.from('profiles').select('id, name, email, role, status, created_at', { count: 'exact' });
  if (q.status) query = query.eq('status', q.status);
  const term = q.search ? safeSearch(q.search) : '';
  if (term) query = query.or(`name.ilike.%${term}%,email.ilike.%${term}%`);

  const { data, error, count } = await query.order('created_at', { ascending: false }).range(from, from + q.pageSize - 1);
  if (error) throw fromSupabase(error);
  res.json({ data, pagination: { page: q.page, pageSize: q.pageSize, total: count, totalPages: Math.ceil((count || 0) / q.pageSize) } });
}

// GET /api/users e GET /api/admin/users
app.get('/api/users', requireAuth, requireAdmin, asyncHandler(listUsers));
app.get('/api/admin/users', requireAuth, requireAdmin, asyncHandler(listUsers));

// GET /api/users/:id
app.get('/api/users/:id', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const id = validate(uuidSchema, req.params.id);
  const { data, error } = await supabaseAdmin.from('profiles').select('id, name, email, role, status, created_at').eq('id', id).maybeSingle();
  if (error) throw fromSupabase(error);
  if (!data) throw new HttpError(404, 'Usuário não encontrado', 'NOT_FOUND');
  res.json({ data });
}));

// PATCH /api/users/:id/status — ativa/desativa (somente o campo status)
app.patch('/api/users/:id/status', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const id = validate(uuidSchema, req.params.id);
  const { status } = validate(z.object({ status: z.enum(['active', 'inactive']) }), req.body);
  if (id === req.user.id) throw new HttpError(400, 'Você não pode alterar o status da própria conta', 'SELF_CHANGE');

  const { data, error } = await supabaseAdmin.from('profiles').update({ status }).eq('id', id).select('id, name, email, role, status, created_at').maybeSingle();
  if (error) throw fromSupabase(error);
  if (!data) throw new HttpError(404, 'Usuário não encontrado', 'NOT_FOUND');

  // Bloqueia também no Supabase Auth: impede login e renovação de sessão
  const { error: banErr } = await supabaseAdmin.auth.admin.updateUserById(id, { ban_duration: status === 'inactive' ? '876000h' : 'none' });
  if (banErr) console.error('[admin] falha ao aplicar ban:', banErr.message);

  await audit(req.user.id, status === 'inactive' ? 'user_deactivated' : 'user_activated', 'profiles', id, { newStatus: status });
  res.json({ data });
}));

// GET /api/admin/dashboard — indicadores gerais
app.get('/api/admin/dashboard', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const count = (status) => {
    let q = supabaseAdmin.from('profiles').select('id', { count: 'exact', head: true });
    if (status) q = q.eq('status', status);
    return q;
  };
  const [total, active, inactive, recent] = await Promise.all([
    count(),
    count('active'),
    count('inactive'),
    supabaseAdmin.from('profiles').select('id, name, email, status, created_at').order('created_at', { ascending: false }).limit(5),
  ]);
  for (const r of [total, active, inactive, recent]) if (r.error) throw fromSupabase(r.error);
  res.json({ totalUsers: total.count, activeUsers: active.count, inactiveUsers: inactive.count, recentUsers: recent.data });
}));

// =====================================================================
// 10. HEALTH CHECK, 404 E ERROS
// =====================================================================
// GET /api/health — confirma que a Vercel alcança o Supabase (diagnóstico do "fetch failed")
app.get('/api/health', asyncHandler(async (req, res) => {
  const started = Date.now();
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/health`, { headers: { apikey: SUPABASE_ANON_KEY }, signal: AbortSignal.timeout(5000) });
    res.status(r.ok ? 200 : 502).json({ api: 'ok', supabase: r.ok ? 'ok' : `http ${r.status}`, ms: Date.now() - started, supabaseHost: new URL(SUPABASE_URL).host });
  } catch (err) {
    console.error('[health] Supabase inacessível:', err.message, err.cause?.code || '');
    res.status(503).json({ api: 'ok', supabase: 'inacessível', motivo: err.cause?.code || err.message, supabaseHost: new URL(SUPABASE_URL).host });
  }
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Rota não encontrada', code: 'NOT_FOUND' }));

// Tratamento centralizado: nada de stack trace para o cliente
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido', code: 'BAD_JSON' });
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'Corpo da requisição muito grande', code: 'TOO_LARGE' });
  const status = err instanceof HttpError ? err.status : 500;
  if (status >= 500) console.error('[erro]', err);
  res.status(status).json({
    error: err instanceof HttpError ? err.message : 'Erro interno do servidor',
    code: err instanceof HttpError ? err.code : 'INTERNAL',
    ...(err?.details ? { details: err.details } : {}),
  });
});

// =====================================================================
// 11. EXPORTAÇÃO (VERCEL) E SERVIDOR LOCAL
// =====================================================================
// Na Vercel, o arquivo public/index.html é servido pela CDN; localmente, pelo Express
if (!process.env.VERCEL) {
  app.use(express.static('public'));
}
// Rota inicial da API (para quem abrir o link do back-end)
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: 'API do Sistema Financeiro no ar. Use o sistema pelo link do front-end.'
  });
});
module.exports = app;

if (require.main === module) {
  const PORT = Number(process.env.PORT) || 3000;
  app.listen(PORT, () => console.log(`API rodando em http://localhost:${PORT}`));
}

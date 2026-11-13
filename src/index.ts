import type {AcademicPlugin, AuthState, Calendar, ErrorCode, HostSdk, HttpResponse, Result} from '../../../sdk/index';

// 西南林业大学（SWFU）统一身份认证接入正方新教务。
//
// 实测入口（2026-11，公网 GET）：
//   GET https://jw.swfu.edu.cn/jwglxt/xtgl/login_slogin.html
//     → 302 /sso/zfiotlogin
//     → 302 https://cas.swfu.edu.cn/cas/login?service=https%3A%2F%2Fjw.swfu.edu.cn%2Fsso%2Fzfiotlogin
// 登录页为正方定制 CAS（security.js，David Shapiro RSA）：
//   POST /cas/v1/getPubKey        → {"modulus":"…","exponent":"10001"}（模数随会话变化）
//   GET  /cas/getKaptchaStatus    → true 时需图片验证码，图片地址 /cas/kaptcha
//   POST /cas/login?service=…     → 密码 = 倒序密码 + 教科书式 RSA（16 位小端分块，无 PKCS#1 填充）
// 登录成功后 CAS 回跳教务 /sso/zfiotlogin?ticket=… 建立教务会话，再核验学号与姓名。
//
// 学期、课表、成绩、考试、选课由内置新正方协议（extends: builtin.zf）继续提供。

const academic = 'https://jw.swfu.edu.cn';
const cas = 'https://cas.swfu.edu.cn/cas';
const entry = academic + '/sso/zfiotlogin';
const profile = academic + '/jwglxt/xtgl/index_cxYhxxIndex.html?gnmkdm=index';
const completion = academic + '/jwglxt/xtgl/index_initMenu.html';
const service = academic + '/sso/zfiotlogin';

const ok = <T>(data: T): Result<T> => ({ok: true, data});
function fail(code: ErrorCode, message: string): never { throw Object.assign(new Error(message), {code}); }
const newId = () => Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
const pendingTtlMs = 5 * 60_000;
const webTtlMs = 20 * 60_000;

interface Pending {
  id: string;
  expires: number;
  kind: 'password' | 'web';
  account: string;
  url?: string;
  fields?: Record<string, string>;
  encryptedPassword?: string;
}

// ---- 正方定制 CAS 的密码加密（与学校 security.js 的 RSAUtils.encryptedString 一致） ----

function hexToBigInt(hex: string): bigint {
  if (!/^[0-9a-fA-F]+$/.test(hex)) fail('PAGE_CHANGED', '学校统一认证公钥格式发生变化');
  return BigInt('0x' + hex);
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let factor = base % modulus;
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) result = (result * factor) % modulus;
    factor = (factor * factor) % modulus;
    power >>= 1n;
  }
  return result;
}

function encryptCasPassword(password: string, modulusHex: string, exponentHex: string): string {
  const modulus = hexToBigInt(modulusHex);
  const exponent = hexToBigInt(exponentHex);
  const bitLength = (modulusHex.replace(/^0+/, '').length) * 4;
  const digitCount = Math.ceil(bitLength / 16);
  const chunkSize = 2 * (digitCount - 1);
  if (chunkSize <= 0) fail('PAGE_CHANGED', '学校统一认证公钥长度异常');
  const units = password.split('').reverse().map(ch => ch.charCodeAt(0));
  while (units.length % chunkSize !== 0) units.push(0);
  const blocks: string[] = [];
  for (let start = 0; start < units.length; start += chunkSize) {
    let value = 0n;
    for (let j = 0; j < chunkSize / 2; j++) {
      const low = units[start + 2 * j] ?? 0;
      const high = units[start + 2 * j + 1] ?? 0;
      value |= BigInt(low + (high << 8)) << BigInt(16 * j);
    }
    blocks.push(modPow(value, exponent, modulus).toString(16));
  }
  return blocks.join(' ');
}

// ---- 页面识别 ----

const isCasUrl = (url: string) => url === cas + '/login' || url.startsWith(cas + '/login?');
const isAcademicPage = (url: string) =>
  url.startsWith(academic + '/') && !/\/xtgl\/login_slogin\.html|\/sso\/zfiotlogin/.test(url);

function invalidCredentials(text: string): boolean {
  return /用户名或密码不正确|用户名或密码错误|账号或密码不正确|密码错误|Incorrect username or password|Invalid credentials/i.test(text);
}

function captchaProblem(text: string): boolean {
  return /验证码不正确|验证码错误|请输入验证码|验证码已过期|验证码失效|captcha (?:error|invalid|required)/i.test(text);
}

function secondFactor(text: string): boolean {
  return /二次认证|二次验证|短信验证码|动态码|手机验证|多因素|MFA|身份验证器/i.test(text);
}

function flowError(text: string): boolean {
  return /Error decoding flow execution|Application Error|authentication flow is misconfigured/i.test(text);
}

// ---- 请求辅助 ----

async function authGet(s: HostSdk, url: string, init: {method?: 'GET' | 'POST'; body?: string} = {}): Promise<HttpResponse> {
  const response = await s.http({
    url,
    purpose: 'auth',
    ...(init.method ? {method: init.method} : {}),
    ...(init.body !== undefined ? {body: init.body} : {}),
  });
  if (response.status >= 500) fail('NETWORK_RETRYABLE', '学校统一认证服务暂时不可用');
  return response;
}

function casForm(body: string, s: HostSdk, pending?: Pending): Record<string, string> {
  const fields = s.html.form(body, '#fm1');
  if (!fields.execution) fail('PAGE_CHANGED', '学校统一认证表单发生变化');
  delete fields.rememberMe;
  if (pending) {
    fields.username = pending.account;
    fields.password = pending.encryptedPassword || '';
  }
  return fields;
}

async function requirePending(s: HostSdk, id: string): Promise<Pending> {
  const saved = await s.state.get<Pending>('pending');
  if (saved && saved.expires <= Date.now()) await s.state.remove('pending');
  if (!saved || !id || saved.id !== id || saved.expires <= Date.now()) {
    await s.state.remove('pending');
    fail('SESSION_EXPIRED', '登录验证已过期，请重新登录');
  }
  return saved;
}

// ---- 身份核验 ----

function identity(html: string, s: HostSdk): {studentId: string; studentName: string} {
  if (s.html.select(html, '#fm1, input[name=yhm], input[name=mm]').length) return {studentId: '', studentName: ''};
  const value = (selector: string) => {
    const node = s.html.select(html, selector)[0];
    return (node?.attributes.value || node?.text || '').replace(/\s+/g, ' ').trim();
  };
  let studentId = value('input[name=xh],input[name=studentId],#studentId,#sessionUserKey');
  let studentName = value('input[name=xm],.media-heading,[name=studentName],#xhxm,.user-name,#studentName');
  if (studentName && !s.html.select(html, 'input[name=xm]')[0]?.attributes.value) {
    studentName = studentName.replace(/(?:同学|学生|教师|老师)$/, '').trim();
  }
  const labels = s.html.select(html, '.middletopdwxxtit');
  const contents = s.html.select(html, '.middletopdwxxtit + .middletopdwxxcont');
  if (labels.length === contents.length) {
    labels.forEach((label, n) => {
      const name = label.text.replace(/[\s:：]/g, '');
      if (name === '学号' && !studentId) studentId = contents[n].text.trim();
      if (name === '学生姓名' && !studentName) studentName = contents[n].text.trim();
    });
  }
  const title = s.html.select(html, '.infoContentTitle')[0]?.text.trim() || '';
  const titled = /^(.+?)[-\[（(]([A-Za-z0-9]{6,})\]?$/.exec(title);
  if (titled) {
    if (!studentName) studentName = titled[1].trim();
    if (!studentId) studentId = titled[2].trim();
  }
  return {studentId, studentName};
}

async function validate(s: HostSdk): Promise<Result<AuthState>> {
  const response = await s.http({url: profile, purpose: 'query'});
  if (response.status >= 500) fail('NETWORK_RETRYABLE', '学校教务暂时不可用');
  if (response.status !== 200 || !response.url.startsWith(profile)) {
    await s.state.remove('pending');
    fail('SESSION_EXPIRED', '西南林业大学教务登录已失效，请重新登录');
  }
  let info = identity(response.body, s);
  // 本校个人资料页只显示姓名（.media-heading），学号在首页 #sessionUserKey 里。
  if (!info.studentId) {
    const menu = await s.http({url: completion, purpose: 'query'});
    if (menu.status >= 500) fail('NETWORK_RETRYABLE', '学校教务暂时不可用');
    if (menu.status === 200 && menu.url.startsWith(completion)) {
      const other = identity(menu.body, s);
      info = {studentId: info.studentId || other.studentId, studentName: info.studentName || other.studentName};
    }
  }
  if (!info.studentId) {
    const account = await s.state.get<string>('account');
    if (account) info = {...info, studentId: account};
  }
  if (!info.studentId || !info.studentName) {
    await s.state.remove('pending');
    fail('SESSION_EXPIRED', '尚未取得教务学生身份，请重新登录');
  }
  const account = await s.state.get<string>('account');
  if (account && info.studentId && account !== info.studentId) {
    await s.state.remove('pending');
    fail('INVALID_CREDENTIALS', '登录账号与教务身份不一致');
  }
  await s.state.remove('pending');
  return ok({status: 'authenticated', studentId: info.studentId, studentName: info.studentName});
}

// ---- 验证码与网页登录交接 ----

async function captchaState(s: HostSdk, pending: Pending): Promise<Result<AuthState>> {
  const image = await s.http({url: cas + '/kaptcha?time=' + Date.now(), purpose: 'auth', responseType: 'base64'});
  if (image.status >= 500) fail('NETWORK_RETRYABLE', '学校统一认证服务暂时不可用');
  const mimeType = (image.headers['Content-Type'] ?? image.headers['content-type'] ?? '').split(';')[0].trim();
  if (image.status !== 200 || !image.body || !/^image\//.test(mimeType)) fail('PAGE_CHANGED', '学校未返回验证码图片');
  pending.expires = Date.now() + pendingTtlMs;
  await s.state.set('pending', pending);
  return ok({status: 'captcha', continuationId: pending.id, imageBase64: image.body, mimeType});
}

async function webState(s: HostSdk, pending: Pending): Promise<Result<AuthState>> {
  pending.kind = 'web';
  pending.expires = Date.now() + webTtlMs;
  await s.state.set('pending', pending);
  return ok({
    status: 'webLogin',
    continuationId: pending.id,
    url: cas + '/login?service=' + encodeURIComponent(service),
    completionUrl: completion,
  });
}

// ---- 提交登录 ----

async function submit(s: HostSdk, pending: Pending, retried = false): Promise<Result<AuthState>> {
  if (!pending.url || !pending.fields) fail('SESSION_EXPIRED', '认证表单已过期，请重新登录');
  const response = await s.http({
    url: pending.url,
    method: 'POST',
    purpose: 'auth',
    form: pending.fields,
  });
  if (response.status >= 500) fail('NETWORK_RETRYABLE', '学校统一认证服务暂时不可用');
  if (response.status === 423 || response.status === 429) {
    // 学校风控会锁定账号并短信通知「30 分钟后自动解锁」。归类为需要人工验证，
    // 让宿主停止自动续登重试，避免短时间内再次提交登录把锁定续期。
    await s.state.remove('pending');
    fail('WEB_LOGIN_REQUIRED', '学校统一认证提示账号登录异常并被临时锁定，约 30 分钟后自动解锁；请等待后再重新登录，期间不要连续重试');
  }
  if (isAcademicPage(response.url)) return validate(s);
  const body = response.body || '';
  if (response.status === 401 || response.status === 403 || invalidCredentials(body)) {
    await s.state.remove('pending');
    fail('INVALID_CREDENTIALS', '统一身份认证未接受学号或个人门户密码');
  }
  if (secondFactor(body)) return webState(s, pending);
  if (captchaProblem(body)) {
    if (retried) await s.state.remove('pending');
    const page = await s.http({url: pending.url, purpose: 'auth'});
    pending.fields = casForm(page.body, s, pending);
    return captchaState(s, pending);
  }
  if (flowError(body) && !retried) {
    const page = await s.http({url: pending.url, purpose: 'auth'});
    pending.fields = casForm(page.body, s, pending);
    return submit(s, pending, true);
  }
  if (isCasUrl(response.url)) {
    // CAS 多节点偶发 flow 状态解码失败时会把登录页退回并换发新的 execution，重新取一次再提交。
    if (!retried) {
      const page = await s.http({url: pending.url!, purpose: 'auth'});
      pending.fields = casForm(page.body, s, pending);
      return submit(s, pending, true);
    }
    return webState(s, pending);
  }
  fail('PAGE_CHANGED', '学校统一认证返回了无法识别的页面，请改用网页登录');
}

// ---- 登录入口 ----

async function start(s: HostSdk, username: string, password: string): Promise<Result<AuthState>> {
  await s.state.remove('pending');
  const account = (username || '').trim();
  if (!account) fail('INVALID_CREDENTIALS', '请输入学号');
  if (!password) fail('INVALID_CREDENTIALS', '请输入个人门户密码');
  await s.state.set('account', account);
  const page = await authGet(s, entry);
  if (page.status !== 200) fail('PAGE_CHANGED', '学校教务登录入口暂不可用');
  if (isAcademicPage(page.url)) return validate(s);
  if (!isCasUrl(page.url)) fail('PAGE_CHANGED', '学校统一认证入口发生变化');
  const fields = casForm(page.body, s);
  const keyResponse = await authGet(s, cas + '/v1/getPubKey', {method: 'POST', body: ''});
  if (keyResponse.status !== 200) fail('PAGE_CHANGED', '学校登录公钥接口发生变化');
  const parsed = ((): {modulus?: unknown; exponent?: unknown} => {
    try {
      return JSON.parse(keyResponse.body) as {modulus?: unknown; exponent?: unknown};
    } catch {
      fail('PAGE_CHANGED', '学校登录公钥格式发生变化');
    }
  })();
  const modulus = typeof parsed.modulus === 'string' ? parsed.modulus.trim() : '';
  const exponent = typeof parsed.exponent === 'string' ? parsed.exponent.trim() : '';
  if (!/^[0-9a-fA-F]+$/.test(modulus) || !/^[0-9a-fA-F]+$/.test(exponent)) fail('PAGE_CHANGED', '学校登录公钥格式发生变化');
  const encrypted = encryptCasPassword(password, modulus, exponent);
  const pending: Pending = {
    id: newId(),
    expires: Date.now() + pendingTtlMs,
    kind: 'password',
    account,
    url: page.url,
    fields: {...fields, username: account, password: encrypted},
    encryptedPassword: encrypted,
  };
  const status = await authGet(s, cas + '/getKaptchaStatus');
  if (status.status === 200 && status.body.trim() === 'true') return captchaState(s, pending);
  return submit(s, pending);
}


// ---- 校历与作息（按周次课表页面的接口，修正 App 默认节次时间） ----

const termXqm: Record<number, string> = {1: '3', 2: '12', 3: '16'};
const weeksUrl = academic + '/jwglxt/kbcx/xskbcxZccx_cxZcByXnxq.html';
const periodUrl = academic + '/jwglxt/jzgl/skxxMobile_cxRsdjc.html';
const mobileKbUrl = academic + '/jwglxt/kbcx/xskbcxMobile_cxXsKb.html';

function termOf(termId: string): {xnm: string; xqm: string} {
  const matched = /^(\d{4})-\d{4}-([123])$/.exec(termId);
  if (!matched) fail('VALIDATION_FAILED', '学期编号无效');
  return {xnm: matched[1], xqm: termXqm[Number(matched[2])]};
}

async function queryForm(s: HostSdk, url: string, form: Record<string, string>): Promise<HttpResponse> {
  const response = await s.http({url, method: 'POST', purpose: 'query', form});
  if (response.status >= 500) fail('NETWORK_RETRYABLE', '学校教务暂时不可用');
  return response;
}

/** 作息与校区号属于可降级数据：接口异常时返回 null，由 App 继续使用已有节次时间。 */
async function softQuery(s: HostSdk, url: string, form: Record<string, string>): Promise<HttpResponse | null> {
  try {
    const response = await s.http({url, method: 'POST', purpose: 'query', form});
    return response.status >= 500 ? null : response;
  } catch {
    return null;
  }
}

async function periodXqhId(s: HostSdk, xnm: string, xqm: string): Promise<string> {
  const cached = await s.state.get<string>('protocol:xqhId');
  if (cached) return cached;
  const response = await softQuery(s, mobileKbUrl, {xnm, xqm, doType: 'app', kblx: '2'});
  if (response && response.status === 200) {
    try {
      const parsed = JSON.parse(response.body) as {kbList?: Array<{xqh_id?: unknown}>};
      const found = (parsed.kbList || []).map(row => row && row.xqh_id).find(value => typeof value === 'string' && value);
      if (typeof found === 'string' && found) {
        await s.state.set('protocol:xqhId', found);
        return found;
      }
    } catch {
      // 没有课表时退化为默认校区为空，学校接口会按默认时段返回
    }
  }
  return '';
}

async function requestPeriods(s: HostSdk, xnm: string, xqm: string, xqhId: string): Promise<{number: number; start: string; end: string}[]> {
  const response = await softQuery(s, periodUrl, {xnm, xqm, xqh_id: xqhId});
  if (!response || response.status !== 200) return [];
  let rows: unknown;
  try {
    rows = JSON.parse(response.body);
  } catch {
    return [];
  }
  if (!Array.isArray(rows)) return [];
  const periods: {number: number; start: string; end: string}[] = [];
  for (const row of rows as Array<{jcmc?: unknown; qssj?: unknown; jssj?: unknown}>) {
    const number = Number(row?.jcmc);
    const start = typeof row?.qssj === 'string' ? row.qssj.slice(0, 5) : '';
    const end = typeof row?.jssj === 'string' ? row.jssj.slice(0, 5) : '';
    if (!Number.isInteger(number) || number < 1 || number > 30) continue;
    if (!/^\d{2}:\d{2}$/.test(start) || !/^\d{2}:\d{2}$/.test(end)) continue;
    periods.push({number, start, end});
  }
  return periods.sort((a, b) => a.number - b.number);
}

/** 校区号默认取校本部 '1'（2026-11 实测两个账号的 kbList 均为 1）；取不到时段时才查课表接口。 */
async function periodList(s: HostSdk, xnm: string, xqm: string): Promise<{number: number; start: string; end: string}[]> {
  const cached = await s.state.get<string>('protocol:xqhId');
  const first = cached || '1';
  const direct = await requestPeriods(s, xnm, xqm, first);
  if (direct.length) return direct;
  const xqh = await periodXqhId(s, xnm, xqm);
  if (xqh && xqh !== first) {
    const resolved = await requestPeriods(s, xnm, xqm, xqh);
    if (resolved.length) return resolved;
  }
  for (const candidate of ['', '1']) {
    if (candidate === first || candidate === xqh) continue;
    const fallback = await requestPeriods(s, xnm, xqm, candidate);
    if (fallback.length) return fallback;
  }
  return [];
}

/** 学校 2026-11 实测的公开作息：接口不可用时用于兜底，避免课表退回 08:00 默认值。 */
const fallbackPeriods = [
  {number: 1, start: '08:20', end: '09:05'}, {number: 2, start: '09:10', end: '09:55'},
  {number: 3, start: '10:25', end: '11:10'}, {number: 4, start: '11:15', end: '12:00'},
  {number: 5, start: '14:00', end: '14:45'}, {number: 6, start: '14:50', end: '15:35'},
  {number: 7, start: '16:05', end: '16:50'}, {number: 8, start: '16:55', end: '17:40'},
  {number: 9, start: '18:30', end: '19:15'}, {number: 10, start: '19:20', end: '20:05'},
  {number: 11, start: '20:25', end: '21:10'}, {number: 12, start: '21:15', end: '22:00'},
];

async function calendar(s: HostSdk, termId: string): Promise<Result<Calendar>> {
  const {xnm, xqm} = termOf(termId);
  const [weeks, periods] = await Promise.all([
    queryForm(s, weeksUrl, {xnm, xqm}),
    periodList(s, xnm, xqm),
  ]);
  if (weeks.status !== 200) fail('PAGE_CHANGED', '学校未返回该学期的周次信息');
  let rows: unknown;
  try {
    rows = JSON.parse(weeks.body);
  } catch {
    fail('PAGE_CHANGED', '学校周次信息格式发生变化');
  }
  if (!Array.isArray(rows) || !rows.length) fail('NOT_OPEN', '该学期尚未开放教学周次');
  const first = (rows as Array<{zcrq?: unknown}>)[0];
  const date = typeof first?.zcrq === 'string' ? /\((\d{4}-\d{2}-\d{2})/.exec(first.zcrq)?.[1] : undefined;
  if (!date) fail('PAGE_CHANGED', '学校周次日期格式发生变化');
  return ok({termId, startDate: date, periods: periods.length ? periods : fallbackPeriods});
}

const plugin = {
  study: {
    calendar: (a, _c, s) => calendar(s, a.termId),
  },
  auth: {
    start: (a, _c, s) => start(s, a.username, a.password),
    resume: async (a, _c, s) => {
      const pending = await requirePending(s, a.continuationId);
      if (pending.kind === 'web') {
        if (!a.webLoginCompleted) fail('WEB_LOGIN_REQUIRED', '请先在学校统一认证页面完成登录');
        return validate(s);
      }
      const code = (a.captcha || '').trim();
      if (!code) return captchaState(s, pending);
      pending.fields = {...(pending.fields || {}), authcode: code};
      return submit(s, pending);
    },
    refreshCaptcha: async (a, _c, s) => captchaState(s, await requirePending(s, a.continuationId)),
    validate: async (_a, _c, s) => validate(s),
  },
} satisfies AcademicPlugin;

export default plugin;

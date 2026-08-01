export const OPERATOR_CONSOLE_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Otto Control</title>
  <link rel="stylesheet" href="/admin/assets/app.css">
</head>
<body>
  <header class="topbar">
    <div>
      <p class="product-kicker">OTTO CONTROL</p>
      <h1>商业运营控制台</h1>
    </div>
    <div class="topbar-actions">
      <span id="service-state" class="status-pill neutral">等待连接</span>
      <button id="refresh-button" class="secondary hidden" type="button">刷新</button>
      <button id="logout-button" class="secondary hidden" type="button">退出</button>
    </div>
  </header>

  <main>
    <section id="login-view" class="login-layout">
      <div class="login-copy">
        <p class="section-label">SECURE ADMIN ACCESS</p>
        <h2>管理员登录</h2>
        <p>使用管理员账号和第二验证因素进入。所有读取与操作仍由服务端 RBAC、MFA 和审批规则校验。</p>
      </div>
      <form id="login-form" class="login-form" autocomplete="on">
        <label>账号<input id="username" name="username" autocomplete="username" required></label>
        <label>密码<input id="password" name="password" type="password" autocomplete="current-password" required></label>
        <div class="mode-switch" role="group" aria-label="验证方式">
          <button class="mode-button active" data-mode="totp" type="button">动态验证码</button>
          <button class="mode-button" data-mode="recovery" type="button">恢复码</button>
        </div>
        <label><span id="mfa-label">6 位动态验证码</span><input id="mfa-code" inputmode="numeric" autocomplete="one-time-code" required></label>
        <p id="login-error" class="error-text" role="alert"></p>
        <button id="login-button" class="primary" type="submit">进入控制台</button>
      </form>
    </section>

    <section id="dashboard-view" class="hidden">
      <div class="identity-band">
        <div><span class="section-label">CURRENT SESSION</span><strong id="admin-name">管理员</strong></div>
        <div><span>角色</span><strong id="admin-roles">-</strong></div>
        <div><span>会话有效期</span><strong id="session-expiry">-</strong></div>
        <div><span>数据更新时间</span><strong id="generated-at">-</strong></div>
      </div>

      <section class="section-block">
        <div class="section-heading">
          <div><p class="section-label">COMMERCIAL INVENTORY</p><h2>客户与授权</h2></div>
          <div class="write-actions">
            <button id="create-customer-button" class="secondary hidden" type="button">新建客户</button>
            <button id="create-deployment-button" class="secondary hidden" type="button">登记部署</button>
            <button id="issue-license-button" class="primary compact hidden" type="button">签发 License</button>
          </div>
        </div>
        <div class="metric-grid">
          <article><span>客户</span><strong id="customer-total">0</strong><small id="customer-detail">0 家正常</small></article>
          <article><span>部署</span><strong id="deployment-total">0</strong><small id="deployment-detail">0 个在线管理</small></article>
          <article><span>有效 License</span><strong id="license-active">0</strong><small id="license-expiring">0 个即将到期</small></article>
          <article class="attention"><span>宽限 / 失效</span><strong id="license-risk">0</strong><small id="license-risk-detail">0 个已吊销</small></article>
        </div>

        <div class="tabs" role="tablist" aria-label="运营清单">
          <button class="tab active" data-tab="licenses" role="tab" type="button">License</button>
          <button class="tab" data-tab="deployments" role="tab" type="button">部署</button>
          <button class="tab" data-tab="customers" role="tab" type="button">客户</button>
        </div>
        <div id="licenses-panel" class="table-panel" role="tabpanel"><table><thead><tr><th>客户</th><th>方案</th><th>席位</th><th>方式</th><th>状态</th><th>到期时间</th></tr></thead><tbody id="licenses-body"></tbody></table></div>
        <div id="deployments-panel" class="table-panel hidden" role="tabpanel"><table><thead><tr><th>部署</th><th>客户</th><th>企业 ID</th><th>状态</th><th>更新时间</th></tr></thead><tbody id="deployments-body"></tbody></table></div>
        <div id="customers-panel" class="table-panel hidden" role="tabpanel"><table><thead><tr><th>客户</th><th>客户 ID</th><th>状态</th><th>更新时间</th></tr></thead><tbody id="customers-body"></tbody></table></div>
      </section>

      <section class="operations-grid">
        <div class="section-block">
          <div class="section-heading"><div><p class="section-label">RECOVERY READINESS</p><h2>备份状态</h2></div><span id="backup-state" class="status-pill neutral">读取中</span></div>
          <dl class="detail-list"><div><dt>最新备份</dt><dd id="backup-name">-</dd></div><div><dt>距今</dt><dd id="backup-age">-</dd></div><div><dt>异地副本</dt><dd id="backup-offsite">-</dd></div><div><dt>检查时间</dt><dd id="backup-checked">-</dd></div></dl>
          <p id="backup-message" class="inline-message"></p>
        </div>

        <div class="section-block">
          <div class="section-heading"><div><p class="section-label">ALERT DELIVERY</p><h2>运维告警</h2></div><button id="poll-alerts" class="secondary" type="button">立即检测</button></div>
          <div class="alert-summary"><strong id="alert-pending">0</strong><span>待投递或重试</span><strong id="alert-failed">0</strong><span>最终失败</span></div>
          <div id="alert-list" class="alert-list"></div>
        </div>
      </section>
    </section>
  </main>

  <datalist id="customer-options"></datalist>
  <datalist id="deployment-options"></datalist>

  <dialog id="customer-dialog" class="action-dialog">
    <form id="customer-form">
      <div class="dialog-heading"><div><p class="section-label">CUSTOMER</p><h2>新建客户</h2></div><button class="icon-close" data-close="customer-dialog" type="button" aria-label="关闭">×</button></div>
      <label>客户名称<input id="customer-name" maxlength="160" autocomplete="organization" required></label>
      <p class="form-error" role="alert"></p>
      <div class="dialog-actions"><button class="secondary" data-close="customer-dialog" type="button">取消</button><button class="primary compact" type="submit">创建客户</button></div>
    </form>
  </dialog>

  <dialog id="deployment-dialog" class="action-dialog">
    <form id="deployment-form">
      <div class="dialog-heading"><div><p class="section-label">DEPLOYMENT</p><h2>登记客户服务器</h2></div><button class="icon-close" data-close="deployment-dialog" type="button" aria-label="关闭">×</button></div>
      <div class="form-grid">
        <label>所属客户 ID<input id="deployment-customer" list="customer-options" maxlength="128" required></label>
        <label>部署名称<input id="deployment-name" maxlength="160" required></label>
        <label>企业 ID<input id="deployment-organization" maxlength="128" required></label>
        <label>部署 ID<input id="deployment-id" readonly required></label>
      </div>
      <label>机器指纹（SHA-256）<input id="deployment-fingerprint" maxlength="64" pattern="[a-fA-F0-9]{64}" spellcheck="false" required></label>
      <p class="form-error" role="alert"></p>
      <div class="dialog-actions"><button class="secondary" data-close="deployment-dialog" type="button">取消</button><button class="primary compact" type="submit">登记部署</button></div>
    </form>
  </dialog>

  <dialog id="license-dialog" class="action-dialog wide">
    <form id="license-form">
      <div class="dialog-heading"><div><p class="section-label">LICENSE</p><h2>签发企业授权</h2></div><button class="icon-close" data-close="license-dialog" type="button" aria-label="关闭">×</button></div>
      <div class="form-grid">
        <label>部署 ID<input id="license-deployment" list="deployment-options" required></label>
        <label>版本方案<select id="license-plan"><option value="basic">基础版</option><option value="enterprise" selected>企业版</option><option value="park">产业园版</option><option value="government">政企版</option></select></label>
        <label>到期日期<input id="license-expiry" type="date" required></label>
        <label>授权席位<input id="license-seats" type="number" min="1" max="1000000" value="50" required></label>
        <label>宽限期（天）<input id="license-grace" type="number" min="0" max="30" value="7" required></label>
        <label>席位策略<select id="license-seat-enforcement"><option value="monitor">仅监测</option><option value="enforce">超额限制</option></select></label>
      </div>
      <fieldset><legend>授权模块</legend><div class="module-grid">
        <label><input type="checkbox" name="license-module" value="enterprise_tree" checked>企业组织</label>
        <label><input type="checkbox" name="license-module" value="direct_messages" checked>企业私聊</label>
        <label><input type="checkbox" name="license-module" value="park_service">产业园服务</label>
        <label><input type="checkbox" name="license-module" value="atoa">A2A 协作</label>
        <label><input type="checkbox" name="license-module" value="feishu_auto_reply">飞书自动回复</label>
        <label><input type="checkbox" name="license-module" value="knowledge">企业知识</label>
        <label><input type="checkbox" name="license-module" value="skill_market">Skill 市场</label>
      </div></fieldset>
      <div class="toggle-row"><label><input id="license-offline" type="checkbox">离线 License</label><label><input id="license-telemetry" type="checkbox" checked>允许匿名运行遥测</label></div>
      <p class="form-error" role="alert"></p>
      <div class="dialog-actions"><button class="secondary" data-close="license-dialog" type="button">取消</button><button class="primary compact" type="submit">签发授权</button></div>
    </form>
  </dialog>

  <dialog id="license-result-dialog" class="action-dialog">
    <div class="dialog-heading"><div><p class="section-label">ISSUED</p><h2>授权签发成功</h2></div><button class="icon-close" data-close="license-result-dialog" type="button" aria-label="关闭">×</button></div>
    <div class="issued-summary"><span>License ID</span><strong id="issued-license-id">-</strong><span>客户</span><strong id="issued-customer">-</strong><span>到期时间</span><strong id="issued-expiry">-</strong></div>
    <p class="sensitive-note">授权文件包含部署凭证，仅在本次页面会话中保留。请下载后交付给对应客户。</p>
    <div class="dialog-actions"><button class="secondary" data-close="license-result-dialog" type="button">关闭</button><button id="download-license" class="primary compact" type="button">下载授权文件</button></div>
  </dialog>

  <div id="toast" class="toast hidden" role="status"></div>
  <script type="module" src="/admin/assets/app.js"></script>
</body>
</html>`;

export const OPERATOR_CONSOLE_CSS = `:root {
  color-scheme: light;
  font-family: Inter, "Segoe UI", "Microsoft YaHei", sans-serif;
  background: #f4f7f6;
  color: #14231d;
  letter-spacing: 0;
}
* { box-sizing: border-box; }
body { margin: 0; min-width: 320px; background: #f4f7f6; }
button, input { font: inherit; letter-spacing: 0; }
button { cursor: pointer; }
.hidden { display: none !important; }
.topbar { min-height: 88px; padding: 18px clamp(20px, 4vw, 56px); display: flex; align-items: center; justify-content: space-between; gap: 24px; background: #ffffff; border-bottom: 1px solid #dbe4e0; }
.topbar h1 { margin: 3px 0 0; font-size: 24px; line-height: 1.25; }
.product-kicker, .section-label { margin: 0; color: #087a61; font-size: 11px; font-weight: 800; text-transform: uppercase; }
.topbar-actions { display: flex; align-items: center; gap: 10px; }
main { width: min(1440px, 100%); margin: 0 auto; padding: 28px clamp(16px, 4vw, 48px) 56px; }
.login-layout { min-height: calc(100vh - 172px); display: grid; grid-template-columns: minmax(260px, 0.9fr) minmax(320px, 520px); align-items: center; gap: clamp(36px, 8vw, 120px); }
.login-copy h2 { margin: 10px 0 16px; font-size: 42px; line-height: 1.1; }
.login-copy p:last-child { max-width: 560px; color: #5d6c66; font-size: 16px; line-height: 1.8; }
.login-form { padding: 28px; background: #ffffff; border: 1px solid #dbe4e0; border-radius: 8px; box-shadow: 0 18px 48px rgba(20, 35, 29, 0.08); }
label { display: grid; gap: 8px; margin-bottom: 18px; color: #43524c; font-size: 13px; font-weight: 700; }
input { width: 100%; min-height: 48px; padding: 11px 13px; color: #14231d; background: #fff; border: 1px solid #bfcac5; border-radius: 6px; outline: none; }
input:focus { border-color: #07805f; box-shadow: 0 0 0 3px rgba(7, 128, 95, 0.12); }
.mode-switch { display: grid; grid-template-columns: 1fr 1fr; gap: 4px; margin: 2px 0 18px; padding: 4px; background: #eef3f1; border-radius: 6px; }
.mode-button { min-height: 38px; border: 0; border-radius: 4px; color: #61706a; background: transparent; }
.mode-button.active { color: #0b503f; background: #ffffff; box-shadow: 0 1px 5px rgba(20,35,29,.1); font-weight: 700; }
.primary, .secondary { min-height: 42px; padding: 9px 16px; border-radius: 6px; font-weight: 700; }
.primary { width: 100%; color: #fff; background: #0b6f57; border: 1px solid #0b6f57; }
.primary:hover { background: #075f4a; }
.secondary { color: #27443a; background: #fff; border: 1px solid #c7d2cd; }
.secondary:hover { border-color: #6d8178; }
.error-text { min-height: 20px; margin: -4px 0 12px; color: #b42318; font-size: 13px; }
.identity-band { display: grid; grid-template-columns: 1.3fr 1fr 1fr 1fr; gap: 1px; background: #dbe4e0; border: 1px solid #dbe4e0; border-radius: 7px; overflow: hidden; }
.identity-band > div { min-width: 0; padding: 15px 18px; background: #fff; }
.identity-band span:not(.section-label) { display: block; color: #75827d; font-size: 12px; }
.identity-band strong { display: block; margin-top: 5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.section-block { margin-top: 22px; padding: 22px; background: #fff; border: 1px solid #dbe4e0; border-radius: 7px; }
.section-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
.section-heading h2 { margin: 4px 0 0; font-size: 20px; }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid #dbe4e0; border-radius: 6px; overflow: hidden; }
.metric-grid article { min-width: 0; padding: 18px; border-right: 1px solid #dbe4e0; }
.metric-grid article:last-child { border-right: 0; }
.metric-grid span, .metric-grid small { display: block; color: #697770; }
.metric-grid strong { display: block; margin: 8px 0 5px; font-size: 30px; }
.metric-grid .attention strong { color: #a15c00; }
.tabs { display: flex; gap: 20px; margin-top: 24px; border-bottom: 1px solid #dbe4e0; }
.tab { padding: 10px 2px; color: #66746e; background: none; border: 0; border-bottom: 2px solid transparent; }
.tab.active { color: #075f4a; border-bottom-color: #0b8062; font-weight: 800; }
.table-panel { overflow-x: auto; }
table { width: 100%; min-width: 700px; border-collapse: collapse; }
th, td { padding: 13px 10px; text-align: left; border-bottom: 1px solid #e7ecea; font-size: 13px; }
th { color: #6b7873; font-weight: 700; }
td { color: #24372f; }
.empty-row td { padding: 32px 10px; color: #82908a; text-align: center; }
.badge { display: inline-flex; align-items: center; min-height: 25px; padding: 3px 8px; border-radius: 999px; color: #245548; background: #e4f3ed; font-size: 12px; font-weight: 700; }
.badge.warning { color: #825100; background: #fff1d6; }
.badge.danger { color: #9f231d; background: #fee9e7; }
.badge.neutral { color: #586761; background: #edf1ef; }
.operations-grid { display: grid; grid-template-columns: minmax(0, .9fr) minmax(0, 1.1fr); gap: 22px; }
.status-pill { display: inline-flex; align-items: center; min-height: 30px; padding: 5px 10px; border-radius: 999px; font-size: 12px; font-weight: 800; }
.status-pill.good { color: #14624d; background: #dff4eb; }
.status-pill.warning { color: #825100; background: #fff0cf; }
.status-pill.danger { color: #9f231d; background: #fee5e2; }
.status-pill.neutral { color: #53615c; background: #e9eeec; }
.detail-list { margin: 0; }
.detail-list div { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 14px; padding: 11px 0; border-bottom: 1px solid #e7ecea; }
.detail-list dt { color: #74817b; }
.detail-list dd { margin: 0; text-align: right; overflow-wrap: anywhere; }
.inline-message { min-height: 22px; margin: 16px 0 0; color: #a15c00; font-size: 13px; }
.alert-summary { display: grid; grid-template-columns: auto 1fr auto 1fr; align-items: baseline; gap: 8px; padding: 12px 14px; background: #f4f7f6; border-radius: 6px; }
.alert-summary strong { font-size: 22px; }
.alert-summary span { color: #6c7974; font-size: 12px; }
.alert-list { margin-top: 12px; }
.alert-item { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; align-items: center; padding: 12px 0; border-bottom: 1px solid #e7ecea; }
.alert-item:last-child { border-bottom: 0; }
.alert-item strong, .alert-item small { display: block; }
.alert-item small { margin-top: 4px; color: #74817b; }
.retry-button { min-height: 34px; padding: 6px 10px; color: #8f251f; background: #fff; border: 1px solid #e2aaa6; border-radius: 5px; }
.toast { position: fixed; right: 22px; bottom: 22px; max-width: min(420px, calc(100vw - 44px)); padding: 13px 16px; color: #fff; background: #18342a; border-radius: 6px; box-shadow: 0 12px 32px rgba(20,35,29,.2); }
@media (max-width: 900px) {
  .login-layout { grid-template-columns: 1fr; align-content: center; gap: 24px; }
  .login-copy h2 { font-size: 34px; }
  .identity-band, .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .metric-grid article:nth-child(2) { border-right: 0; }
  .metric-grid article:nth-child(-n+2) { border-bottom: 1px solid #dbe4e0; }
  .operations-grid { grid-template-columns: 1fr; }
}
@media (max-width: 560px) {
  .topbar { align-items: flex-start; }
  .topbar h1 { font-size: 19px; }
  .topbar-actions { flex-wrap: wrap; justify-content: flex-end; }
  main { padding-top: 18px; }
  .identity-band, .metric-grid { grid-template-columns: 1fr; }
  .metric-grid article { border-right: 0; border-bottom: 1px solid #dbe4e0; }
  .metric-grid article:last-child { border-bottom: 0; }
  .section-block { padding: 17px; }
  .alert-summary { grid-template-columns: auto 1fr; }
}`;

export const OPERATOR_CONSOLE_JS = `const sessionKey = 'otto.control.admin.session';
const state = { token: sessionStorage.getItem(sessionKey), principal: null, expiresAt: null, mfaMode: 'totp' };
const byId = (id) => document.getElementById(id);

function setText(id, value) { byId(id).textContent = value == null ? '-' : String(value); }
function localTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : '-';
}
function setStatus(element, text, tone) {
  element.textContent = text;
  element.className = 'status-pill ' + tone;
}
function toast(message) {
  const element = byId('toast');
  element.textContent = message;
  element.classList.remove('hidden');
  window.setTimeout(() => element.classList.add('hidden'), 3200);
}
function showLogin(message) {
  state.token = null;
  state.principal = null;
  state.expiresAt = null;
  sessionStorage.removeItem(sessionKey);
  sessionStorage.removeItem(sessionKey + '.expiresAt');
  byId('dashboard-view').classList.add('hidden');
  byId('login-view').classList.remove('hidden');
  byId('refresh-button').classList.add('hidden');
  byId('logout-button').classList.add('hidden');
  byId('login-error').textContent = message || '';
  setStatus(byId('service-state'), '需要登录', 'neutral');
}
function showDashboard() {
  byId('login-view').classList.add('hidden');
  byId('dashboard-view').classList.remove('hidden');
  byId('refresh-button').classList.remove('hidden');
  byId('logout-button').classList.remove('hidden');
  setText('admin-name', state.principal.displayName || state.principal.username);
  setText('admin-roles', state.principal.roles.join(' / '));
  setText('session-expiry', localTime(state.expiresAt));
  configureWriteActions();
}
async function request(path, options) {
  const settings = Object.assign({ headers: {} }, options || {});
  settings.headers = Object.assign({}, settings.headers, { authorization: 'Bearer ' + state.token });
  if (settings.body) settings.headers['content-type'] = 'application/json';
  const response = await fetch(path, settings);
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  if (response.status === 401) {
    showLogin('会话已过期，请重新登录。');
    throw new Error('登录已过期');
  }
  if (!response.ok) throw new Error(body && body.error ? body.error.message : '请求失败（' + response.status + '）');
  return body;
}
function badge(text, tone) {
  const element = document.createElement('span');
  element.className = 'badge' + (tone ? ' ' + tone : '');
  element.textContent = text;
  return element;
}
function emptyRow(body, columns, message) {
  const row = document.createElement('tr');
  row.className = 'empty-row';
  const cell = document.createElement('td');
  cell.colSpan = columns;
  cell.textContent = message;
  row.append(cell);
  body.replaceChildren(row);
}
function addCells(row, values) {
  values.forEach((value) => {
    const cell = document.createElement('td');
    if (value instanceof Node) cell.append(value); else cell.textContent = String(value);
    row.append(cell);
  });
}
function licenseTone(value) {
  if (value === 'active') return '';
  if (value === 'expiring' || value === 'grace') return 'warning';
  return 'danger';
}
const licenseLabels = { active: '有效', expiring: '即将到期', grace: '宽限期', expired: '已过期', revoked: '已吊销' };
function renderOverview(data) {
  const counts = data.counts;
  setText('customer-total', counts.customers.total);
  setText('customer-detail', counts.customers.active + ' 家正常，' + counts.customers.suspended + ' 家停用');
  setText('deployment-total', counts.deployments.total);
  setText('deployment-detail', counts.deployments.active + ' 个有效，' + counts.deployments.suspended + ' 个停用');
  setText('license-active', counts.licenses.active);
  setText('license-expiring', counts.licenses.expiringSoon + ' 个将在 30 天内到期');
  setText('license-risk', counts.licenses.grace + counts.licenses.expired);
  setText('license-risk-detail', counts.licenses.revoked + ' 个已吊销');
  setText('generated-at', localTime(data.generatedAt));

  const licenseBody = byId('licenses-body');
  licenseBody.replaceChildren();
  data.recent.licenses.slice(0, 12).forEach((license) => {
    const row = document.createElement('tr');
    addCells(row, [license.customerName, license.plan, license.seatLimit, license.offline ? '离线' : '在线', badge(licenseLabels[license.state], licenseTone(license.state)), localTime(license.expiresAt)]);
    licenseBody.append(row);
  });
  if (!data.recent.licenses.length) emptyRow(licenseBody, 6, '暂无 License');

  const deploymentBody = byId('deployments-body');
  deploymentBody.replaceChildren();
  data.recent.deployments.slice(0, 12).forEach((deployment) => {
    const row = document.createElement('tr');
    addCells(row, [deployment.name, deployment.customerName, deployment.organizationId, badge(deployment.status === 'active' ? '有效' : '停用', deployment.status === 'active' ? '' : 'warning'), localTime(deployment.updatedAt)]);
    deploymentBody.append(row);
  });
  if (!data.recent.deployments.length) emptyRow(deploymentBody, 5, '暂无部署');

  const customerBody = byId('customers-body');
  customerBody.replaceChildren();
  data.recent.customers.slice(0, 12).forEach((customer) => {
    const row = document.createElement('tr');
    addCells(row, [customer.name, customer.id, badge(customer.status === 'active' ? '正常' : '停用', customer.status === 'active' ? '' : 'warning'), localTime(customer.updatedAt)]);
    customerBody.append(row);
  });
  if (!data.recent.customers.length) emptyRow(customerBody, 4, '暂无客户');
  populateWriteOptions(data);
}
function renderBackup(data) {
  const tones = { healthy: 'good', degraded: 'warning', failed: 'danger', missing: 'danger', not_configured: 'neutral' };
  const labels = { healthy: '健康', degraded: '需关注', failed: '失败', missing: '无报告', not_configured: '未配置' };
  setStatus(byId('backup-state'), labels[data.status] || data.status, tones[data.status] || 'neutral');
  setText('backup-name', data.latest ? data.latest.backup.name : '-');
  setText('backup-age', data.ageHours == null ? '-' : data.ageHours.toFixed(1) + ' 小时');
  setText('backup-offsite', data.latest ? data.latest.offsite.status : '-');
  setText('backup-checked', localTime(data.checkedAt));
  setText('backup-message', data.alerts.length ? data.alerts.map((item) => item.message).join('；') : '备份与恢复指标正常。');
}
function renderAlerts(data) {
  const pending = data.deliveries.filter((item) => ['pending', 'delivering', 'retrying'].includes(item.status)).length;
  const failed = data.deliveries.filter((item) => item.status === 'failed').length;
  setText('alert-pending', pending);
  setText('alert-failed', failed);
  const list = byId('alert-list');
  list.replaceChildren();
  data.deliveries.slice(0, 6).forEach((delivery) => {
    const item = document.createElement('div');
    item.className = 'alert-item';
    const copy = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = delivery.payload.condition.reason + ' · ' + delivery.status;
    const meta = document.createElement('small');
    meta.textContent = localTime(delivery.updatedAt) + ' · 已尝试 ' + delivery.attempts + ' 次';
    copy.append(title, meta);
    item.append(copy);
    if (delivery.status === 'failed') {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'retry-button';
      button.textContent = '重新投递';
      button.addEventListener('click', async () => {
        button.disabled = true;
        try {
          await request('/v1/admin/alerts/deliveries/' + encodeURIComponent(delivery.id) + '/retry', { method: 'POST' });
          toast('已进入重试队列');
          await refreshDashboard();
        } catch (error) { toast(error.message); } finally { button.disabled = false; }
      });
      item.append(button);
    }
    list.append(item);
  });
  if (!data.deliveries.length) {
    const empty = document.createElement('p');
    empty.className = 'inline-message';
    empty.textContent = data.enabled ? '暂无告警投递记录。' : '告警 Webhook 尚未启用。';
    list.append(empty);
  }
}
async function permissionAware(path, render, fallback) {
  try { render(await request(path)); }
  catch (error) {
    if (error.message !== '登录已过期') fallback(error.message);
  }
}
async function refreshDashboard() {
  if (!state.token) return;
  setStatus(byId('service-state'), '正在刷新', 'neutral');
  await Promise.all([
    permissionAware('/v1/admin/overview?limit=50', renderOverview, (message) => {
      setText('generated-at', '无查看权限'); toast(message);
    }),
    permissionAware('/v1/admin/backups/status?limit=8', renderBackup, (message) => {
      setStatus(byId('backup-state'), '不可用', 'neutral'); setText('backup-message', message);
    }),
    permissionAware('/v1/admin/alerts/deliveries?limit=20', renderAlerts, (message) => {
      const list = byId('alert-list'); list.textContent = message;
    }),
  ]);
  if (state.token) setStatus(byId('service-state'), '已连接', 'good');
}
async function restoreSession() {
  if (!state.token) return showLogin('');
  try {
    const result = await request('/v1/admin-auth/me');
    state.principal = result.principal;
    state.expiresAt = sessionStorage.getItem(sessionKey + '.expiresAt');
    showDashboard();
    await refreshDashboard();
  } catch { showLogin('会话已失效，请重新登录。'); }
}
document.querySelectorAll('.mode-button').forEach((button) => button.addEventListener('click', () => {
  state.mfaMode = button.dataset.mode;
  document.querySelectorAll('.mode-button').forEach((candidate) => candidate.classList.toggle('active', candidate === button));
  setText('mfa-label', state.mfaMode === 'totp' ? '6 位动态验证码' : '一次性恢复码');
  byId('mfa-code').value = '';
  byId('mfa-code').inputMode = state.mfaMode === 'totp' ? 'numeric' : 'text';
}));
document.querySelectorAll('.tab').forEach((button) => button.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach((candidate) => candidate.classList.toggle('active', candidate === button));
  ['licenses', 'deployments', 'customers'].forEach((name) => byId(name + '-panel').classList.toggle('hidden', name !== button.dataset.tab));
}));
byId('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = byId('login-button');
  button.disabled = true;
  byId('login-error').textContent = '';
  const payload = { username: byId('username').value, password: byId('password').value };
  payload[state.mfaMode === 'totp' ? 'totpCode' : 'recoveryCode'] = byId('mfa-code').value;
  try {
    const response = await fetch('/v1/admin-auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ? result.error.message : '登录失败');
    state.token = result.token;
    state.principal = result.principal;
    state.expiresAt = result.expiresAt;
    sessionStorage.setItem(sessionKey, result.token);
    sessionStorage.setItem(sessionKey + '.expiresAt', result.expiresAt);
    byId('password').value = '';
    byId('mfa-code').value = '';
    showDashboard();
    await refreshDashboard();
  } catch (error) { byId('login-error').textContent = error.message; } finally { button.disabled = false; }
});
byId('refresh-button').addEventListener('click', refreshDashboard);
byId('poll-alerts').addEventListener('click', async () => {
  try { await request('/v1/admin/alerts/poll', { method: 'POST' }); toast('告警检测已完成'); await refreshDashboard(); }
  catch (error) { toast(error.message); }
});
byId('logout-button').addEventListener('click', async () => {
  try { await request('/v1/admin-auth/logout', { method: 'POST' }); } catch {}
  sessionStorage.removeItem(sessionKey + '.expiresAt');
  showLogin('已安全退出。');
});
window.setInterval(() => {
  if (state.token && !document.hidden) void refreshDashboard();
}, 60_000);
void restoreSession();`;

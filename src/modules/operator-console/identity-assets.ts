import type { AdminPermission } from '../../contracts/admin-identity.js';

const PERMISSION_LABELS = {
  'commercial.read': '查看商业概览',
  'customer.create': '创建客户',
  'deployment.create': '登记部署',
  'license.issue': '签发 License',
  'license.read': '查看 License',
  'license.export': '导出 License',
  'license.revoke': '吊销 License',
  'license.manage': '管理 License',
  'license.transfer': '迁移 License',
  'license.usage.read': '查看席位用量',
  'signing_key.read': '查看签名密钥',
  'signing_key.manage': '管理签名密钥',
  'telemetry.read': '查看遥测',
  'backup.read': '查看备份',
  'alert.read': '查看告警',
  'alert.manage': '管理告警',
  'update_distribution.manage': '管理更新分发',
  'update_release.create': '创建更新版本',
  'update_release.read': '查看更新版本',
  'update_release.publish': '发布更新版本',
  'identity.read': '查看管理员与角色',
  'identity.manage': '管理管理员与角色',
  'approval.request': '发起高风险审批',
  'approval.read': '查看高风险审批',
  'approval.decide': '复核高风险审批',
  'billing.read': '查看计费',
  'billing.topup': '积分充值',
  'billing.manage': '管理计费',
  'billing.refund': '积分退款',
  'audit.read': '查看审计',
  'audit.export': '导出审计',
  'audit.verify': '校验审计链',
  'audit.anchor.manage': '管理审计锚定',
  'data_governance.read': '查看数据治理',
  'data_governance.manage': '管理数据治理',
  'data_export.create': '创建数据导出',
  'customer_erasure.manage': '执行客户注销',
  'legal_hold.manage': '管理法律保全',
  'forensic_export.create': '创建取证导出',
  'customer_delivery.read': '查看客户交付资料',
  'edge_gateway.read': '查看边缘网关',
  'edge_gateway.manage': '管理边缘网关',
} satisfies Record<AdminPermission, string>;

const ROLE_LABELS: Record<string, string> = {
  super_admin: '超级管理员',
  security_admin: '安全管理员',
  commercial_admin: '商业管理员',
  operations_admin: '运维管理员',
  auditor: '审计员',
  support_operator: '支持专员',
};

export const OPERATOR_CONSOLE_IDENTITY_CSS = `.identity-overview { display: grid; grid-template-columns: minmax(0, 1fr) minmax(300px, .8fr); gap: 18px; }
.identity-role-list { display: grid; gap: 10px; }
.identity-role { padding: 13px 14px; border: 1px solid #dbe4e0; border-radius: 6px; background: #f8faf9; }
.identity-role-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.identity-role-heading strong { font-size: 14px; }
.identity-role-heading small { color: #71807a; }
.identity-permissions { margin: 9px 0 0; color: #5d6c66; font-size: 12px; line-height: 1.6; }
.identity-table { min-width: 920px; }
.identity-actions { display: flex; align-items: center; gap: 7px; }
.identity-actions button { white-space: nowrap; }
.identity-role-tags { display: flex; flex-wrap: wrap; gap: 5px; }
.identity-role-tags span { padding: 3px 7px; color: #335346; background: #edf4f1; border-radius: 4px; font-size: 12px; }
.role-picker { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin-top: 8px; }
.role-picker label { display: flex; align-items: flex-start; gap: 8px; padding: 10px; border: 1px solid #dbe4e0; border-radius: 6px; }
.role-picker input { margin-top: 3px; }
.role-picker span { min-width: 0; }
.role-picker strong, .role-picker small { display: block; }
.role-picker small { margin-top: 3px; color: #71807a; line-height: 1.45; }
.enrollment-grid { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 8px 14px; margin: 16px 0; }
.enrollment-grid dt { color: #71807a; }
.enrollment-grid dd { min-width: 0; margin: 0; overflow-wrap: anywhere; }
.enrollment-secret { padding: 10px 12px; background: #f4f7f6; border: 1px solid #dbe4e0; border-radius: 5px; font: 12px/1.6 ui-monospace, "Cascadia Code", Consolas, monospace; }
.activation-import { display: flex; align-items: center; gap: 9px; margin-bottom: 14px; }
.activation-import input { min-width: 0; }
.recovery-code-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin: 14px 0; }
.recovery-code-list code { padding: 8px 10px; text-align: center; background: #f4f7f6; border: 1px solid #dbe4e0; border-radius: 5px; }
.login-secondary-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px; }
@media (max-width: 900px) { .identity-overview { grid-template-columns: 1fr; } }
@media (max-width: 680px) {
  .role-picker, .recovery-code-list { grid-template-columns: 1fr; }
  .enrollment-grid { grid-template-columns: 1fr; }
}`;

export const OPERATOR_CONSOLE_IDENTITY_JS = `let latestAdminAccounts = [];
let latestAdminRoles = [];
let selectedAdminAccount = null;
let currentEnrollment = null;
let currentRecoveryCodes = [];
const adminPermissionLabels = ${JSON.stringify(PERMISSION_LABELS)};
const adminRoleLabels = ${JSON.stringify(ROLE_LABELS)};
const adminStatusLabels = { pending: '待激活', active: '正常', disabled: '已停用' };

function roleLabel(roleId) { return adminRoleLabels[roleId] || roleId; }
function identityStatusTone(status) {
  if (status === 'active') return 'good';
  if (status === 'pending') return 'warning';
  return 'danger';
}
function roleTags(roleIds) {
  const wrap = document.createElement('div');
  wrap.className = 'identity-role-tags';
  roleIds.forEach((roleId) => {
    const tag = document.createElement('span');
    tag.textContent = roleLabel(roleId);
    wrap.append(tag);
  });
  return wrap;
}
function renderAdminRoles(roles) {
  const list = byId('admin-role-list');
  list.replaceChildren();
  roles.forEach((role) => {
    const item = document.createElement('article');
    item.className = 'identity-role';
    const heading = document.createElement('div');
    heading.className = 'identity-role-heading';
    const name = document.createElement('strong');
    name.textContent = roleLabel(role.id);
    const count = document.createElement('small');
    count.textContent = role.permissions.length + ' 项权限';
    heading.append(name, count);
    const permissions = document.createElement('p');
    permissions.className = 'identity-permissions';
    permissions.textContent = role.permissions.map((permission) => adminPermissionLabels[permission] || permission).join('、');
    item.append(heading, permissions);
    list.append(item);
  });
}
function adminAccountActions(account) {
  const actions = document.createElement('div');
  actions.className = 'identity-actions';
  if (!hasPermission('identity.manage')) {
    actions.textContent = '仅查看';
    return actions;
  }
  const roles = document.createElement('button');
  roles.type = 'button';
  roles.className = 'table-action';
  roles.textContent = '角色';
  roles.addEventListener('click', () => openAdminRoleEditor(account));
  actions.append(roles);
  if (account.status !== 'pending') {
    const status = document.createElement('button');
    status.type = 'button';
    status.className = account.status === 'active' ? 'danger-button' : 'table-action';
    status.textContent = account.status === 'active' ? '停用' : '恢复';
    status.disabled = account.id === state.principal.accountId && account.status === 'active';
    status.title = status.disabled ? '不能停用当前登录账号' : '';
    status.addEventListener('click', () => changeAdminStatus(account, account.status === 'active' ? 'disabled' : 'active', status));
    actions.append(status);
  }
  return actions;
}
function renderAdminAccounts(accounts) {
  setText('admin-account-count', accounts.length);
  setText('admin-pending-count', accounts.filter((account) => account.status === 'pending').length + ' 个待激活');
  const body = byId('admin-accounts-body');
  body.replaceChildren();
  accounts.forEach((account) => {
    const row = document.createElement('tr');
    const identity = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = account.displayName;
    const username = document.createElement('small');
    username.textContent = account.username + (account.id === state.principal.accountId ? ' · 当前账号' : '');
    identity.append(name, document.createElement('br'), username);
    addCells(row, [
      identity,
      roleTags(account.roles),
      badge(account.mfaEnabled ? '已启用' : '未激活', account.mfaEnabled ? 'good' : 'warning'),
      badge(adminStatusLabels[account.status] || account.status, identityStatusTone(account.status)),
      localTime(account.updatedAt),
      adminAccountActions(account),
    ]);
    body.append(row);
  });
  if (!accounts.length) emptyRow(body, 6, '暂无管理员账号');
}
async function refreshAdminIdentity() {
  const section = byId('admin-identity-center');
  if (!state.principal || !hasPermission('identity.read')) {
    section.classList.add('hidden');
    return;
  }
  section.classList.remove('hidden');
  byId('create-admin-button').classList.toggle('hidden', !hasPermission('identity.manage'));
  try {
    const [roleResult, accountResult] = await Promise.all([
      request('/v1/admin/roles'),
      request('/v1/admin/accounts'),
    ]);
    latestAdminRoles = roleResult.roles;
    latestAdminAccounts = accountResult.accounts;
    renderAdminRoles(latestAdminRoles);
    renderAdminAccounts(latestAdminAccounts);
  } catch (error) {
    emptyRow(byId('admin-accounts-body'), 6, error.message);
  }
}
function renderRolePicker(container, selected) {
  container.replaceChildren();
  latestAdminRoles.forEach((role) => {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.name = 'admin-role';
    input.value = role.id;
    input.checked = selected.includes(role.id);
    const copy = document.createElement('span');
    const name = document.createElement('strong');
    name.textContent = roleLabel(role.id);
    const summary = document.createElement('small');
    summary.textContent = role.permissions.length + ' 项权限';
    copy.append(name, summary);
    label.append(input, copy);
    container.append(label);
  });
}
function selectedRoles(container) {
  return [...container.querySelectorAll('input[name="admin-role"]:checked')].map((input) => input.value);
}
function openAdminRoleEditor(account) {
  selectedAdminAccount = account;
  setText('admin-role-title', '调整 ' + account.displayName + ' 的角色');
  renderRolePicker(byId('admin-role-picker'), account.roles);
  byId('admin-role-form').querySelector('.form-error').textContent = '';
  byId('admin-role-dialog').showModal();
}
async function changeAdminStatus(account, status, button) {
  const action = status === 'disabled' ? '停用' : '恢复';
  if (!window.confirm('确认' + action + '管理员“' + account.displayName + '”？')) return;
  button.disabled = true;
  try {
    await request('/v1/admin/accounts/' + encodeURIComponent(account.id) + '/status', {
      method: 'PUT', body: JSON.stringify({ status }),
    });
    toast('管理员状态已更新');
    await refreshAdminIdentity();
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; }
}
function enrollmentPackage(enrollment) {
  return {
    version: 1,
    accountId: enrollment.account.id,
    username: enrollment.account.username,
    displayName: enrollment.account.displayName,
    enrollmentToken: enrollment.enrollmentToken,
    mfaSecret: enrollment.mfaSecret,
    otpauthUri: enrollment.otpauthUri,
  };
}
function downloadText(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type: type || 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
function showEnrollment(enrollment) {
  currentEnrollment = enrollmentPackage(enrollment);
  setText('enrollment-account', enrollment.account.displayName + '（' + enrollment.account.username + '）');
  setText('enrollment-id', enrollment.account.id);
  setText('enrollment-secret', enrollment.mfaSecret);
  setText('enrollment-uri', enrollment.otpauthUri);
  byId('enrollment-dialog').showModal();
}
function populateActivation(value) {
  if (!value || value.version !== 1 || !value.accountId || !value.enrollmentToken || !value.mfaSecret) {
    throw new Error('激活包格式不正确');
  }
  byId('activation-account-id').value = value.accountId;
  byId('activation-token').value = value.enrollmentToken;
  byId('activation-secret').value = value.mfaSecret;
  setText('activation-secret-display', value.mfaSecret);
  setText('activation-account-name', value.displayName || value.username || value.accountId);
}
function acceptAdminSession(result) {
  state.token = result.token;
  state.principal = result.principal;
  state.expiresAt = result.expiresAt;
  sessionStorage.setItem(sessionKey, result.token);
  sessionStorage.setItem(sessionKey + '.expiresAt', result.expiresAt);
}
function showRecoveryCodes(codes) {
  currentRecoveryCodes = [...codes];
  const list = byId('recovery-code-list');
  list.replaceChildren();
  codes.forEach((code) => {
    const item = document.createElement('code');
    item.textContent = code;
    list.append(item);
  });
  byId('recovery-codes-dialog').showModal();
}
async function refreshBootstrapAvailability() {
  try {
    const response = await fetch('/v1/admin-auth/bootstrap/status');
    const result = await response.json();
    byId('bootstrap-admin-button').classList.toggle('hidden', !response.ok || !result.required);
  } catch {
    byId('bootstrap-admin-button').classList.add('hidden');
  }
}

byId('create-admin-button').addEventListener('click', () => {
  byId('create-admin-form').reset();
  renderRolePicker(byId('create-admin-role-picker'), []);
  byId('create-admin-form').querySelector('.form-error').textContent = '';
  byId('create-admin-dialog').showModal();
});
byId('create-admin-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const error = form.querySelector('.form-error');
  const password = byId('create-admin-password').value;
  if (password !== byId('create-admin-password-confirm').value) return void (error.textContent = '两次密码输入不一致');
  const roleIds = selectedRoles(byId('create-admin-role-picker'));
  if (!roleIds.length) return void (error.textContent = '至少选择一个角色');
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  error.textContent = '';
  try {
    const result = await request('/v1/admin/accounts', {
      method: 'POST',
      body: JSON.stringify({
        username: byId('create-admin-username').value,
        displayName: byId('create-admin-name').value,
        password,
        roleIds,
      }),
    });
    closeDialog('create-admin-dialog');
    showEnrollment(result.enrollment);
    await refreshAdminIdentity();
  } catch (caught) { error.textContent = caught.message; }
  finally { button.disabled = false; }
});
byId('admin-role-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!selectedAdminAccount) return;
  const form = event.currentTarget;
  const error = form.querySelector('.form-error');
  const roleIds = selectedRoles(byId('admin-role-picker'));
  if (!roleIds.length) return void (error.textContent = '至少选择一个角色');
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  error.textContent = '';
  try {
    await request('/v1/admin/accounts/' + encodeURIComponent(selectedAdminAccount.id) + '/roles', {
      method: 'PUT', body: JSON.stringify({ roleIds }),
    });
    closeDialog('admin-role-dialog');
    if (selectedAdminAccount.id === state.principal.accountId) {
      showLogin('当前账号角色已变更，请重新登录。');
      return;
    }
    toast('管理员角色已更新');
    await refreshAdminIdentity();
  } catch (caught) { error.textContent = caught.message; }
  finally { button.disabled = false; }
});
byId('admin-role-dialog').addEventListener('close', () => { selectedAdminAccount = null; });
byId('download-enrollment').addEventListener('click', () => {
  if (!currentEnrollment) return;
  downloadText('otto-control-admin-enrollment-' + currentEnrollment.accountId + '.json', JSON.stringify(currentEnrollment, null, 2), 'application/json');
});
byId('copy-enrollment-secret').addEventListener('click', async () => {
  if (!currentEnrollment) return;
  try { await navigator.clipboard.writeText(currentEnrollment.mfaSecret); toast('MFA 密钥已复制'); }
  catch { toast('浏览器未允许复制，请手动选择密钥'); }
});
byId('enrollment-dialog').addEventListener('close', () => { currentEnrollment = null; });
byId('activate-enrollment-button').addEventListener('click', () => {
  byId('activation-form').reset();
  setText('activation-account-name', '尚未导入');
  setText('activation-secret-display', '-');
  byId('activation-form').querySelector('.form-error').textContent = '';
  byId('activation-dialog').showModal();
});
byId('activation-package-file').addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  try { populateActivation(JSON.parse(await file.text())); }
  catch (error) { byId('activation-form').querySelector('.form-error').textContent = error.message; }
});
byId('activation-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const error = form.querySelector('.form-error');
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  error.textContent = '';
  try {
    const response = await fetch('/v1/admin-auth/enroll/confirm', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        accountId: byId('activation-account-id').value,
        enrollmentToken: byId('activation-token').value,
        totpCode: byId('activation-code').value,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ? result.error.message : '激活失败');
    acceptAdminSession(result);
    closeDialog('activation-dialog');
    showRecoveryCodes(result.recoveryCodes);
  } catch (caught) { error.textContent = caught.message; }
  finally { button.disabled = false; }
});
byId('bootstrap-admin-button').addEventListener('click', () => {
  byId('bootstrap-form').reset();
  byId('bootstrap-form').querySelector('.form-error').textContent = '';
  byId('bootstrap-dialog').showModal();
});
byId('bootstrap-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const error = form.querySelector('.form-error');
  const password = byId('bootstrap-password').value;
  if (password !== byId('bootstrap-password-confirm').value) return void (error.textContent = '两次密码输入不一致');
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  error.textContent = '';
  try {
    const response = await fetch('/v1/admin-auth/bootstrap', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + byId('bootstrap-token').value },
      body: JSON.stringify({ username: byId('bootstrap-username').value, displayName: byId('bootstrap-name').value, password }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ? result.error.message : '初始化失败');
    closeDialog('bootstrap-dialog');
    byId('bootstrap-admin-button').classList.add('hidden');
    showEnrollment(result.enrollment);
  } catch (caught) { error.textContent = caught.message; }
  finally { button.disabled = false; }
});
byId('download-recovery-codes').addEventListener('click', () => {
  if (!currentRecoveryCodes.length) return;
  downloadText('otto-control-recovery-codes.txt', currentRecoveryCodes.join('\\n') + '\\n');
});
byId('recovery-codes-dialog').addEventListener('close', async () => {
  currentRecoveryCodes = [];
  if (state.token && state.principal) {
    showDashboard();
    await refreshDashboard();
  }
});
void refreshBootstrapAvailability();`;

import type { AdminApprovalOperation, AdminPermission } from '../../contracts/admin-identity.js';

export const OPERATOR_CONSOLE_APPROVAL_ACTIONS = Object.freeze({
  'license.revoke': { label: '吊销 License', permission: 'license.revoke' },
  'license.transfer_machine': { label: '迁移授权机器', permission: 'license.transfer' },
  'license.rebind_deployment': { label: '重绑授权部署', permission: 'license.transfer' },
  'signing_key.activate': { label: '启用签名密钥', permission: 'signing_key.manage' },
  'signing_key.retire': { label: '停用签名密钥', permission: 'signing_key.manage' },
  'signing_key.revoke': { label: '紧急吊销密钥', permission: 'signing_key.manage' },
  'update_release.activate': { label: '激活更新版本', permission: 'update_release.publish' },
  'update_release.rollback': { label: '回滚更新版本', permission: 'update_release.publish' },
  'release_artifact.revoke': { label: '吊销发行物', permission: 'update_release.publish' },
  'billing.rate.set': { label: '调整计费费率', permission: 'billing.manage' },
  'billing.topup': { label: '企业积分充值', permission: 'billing.topup' },
  'billing.refund': { label: '客户积分退款', permission: 'billing.refund' },
  'billing.execution_receipt_key.register': {
    label: '登记执行收据公钥',
    permission: 'billing.manage',
  },
  'billing.execution_receipt_key.revoke': {
    label: '吊销执行收据公钥',
    permission: 'billing.manage',
  },
  'customer_erasure.execute': {
    label: '执行客户数据注销',
    permission: 'customer_erasure.manage',
  },
  'legal_hold.create': { label: '创建法律保全', permission: 'legal_hold.manage' },
  'legal_hold.release': { label: '解除法律保全', permission: 'legal_hold.manage' },
  'forensic_export.create': { label: '创建审计取证导出', permission: 'forensic_export.create' },
} satisfies Record<AdminApprovalOperation, {
  label: string;
  permission: AdminPermission;
}>);

export const OPERATOR_CONSOLE_APPROVAL_CSS = `.approval-table { min-width: 840px; }
.approval-actions { display: flex; align-items: center; gap: 8px; }
.approval-actions small { color: #71807a; }
.approval-payload { max-height: 220px; margin: 0; padding: 14px; overflow: auto; color: #1e352c; background: #f4f7f6; border: 1px solid #dbe4e0; border-radius: 6px; font: 12px/1.65 ui-monospace, "Cascadia Code", Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
.action-dialog textarea { width: 100%; padding: 12px 13px; resize: vertical; color: #14231d; background: #fff; border: 1px solid #bfcac5; border-radius: 6px; font: inherit; line-height: 1.5; }
.danger-zone { display: flex; align-items: center; justify-content: space-between; gap: 24px; }
.danger-zone p { margin: 5px 0 0; color: #6f554f; line-height: 1.6; }
.danger-button { width: auto; padding: 10px 14px; color: #9f241b; background: #fff; border: 1px solid #e2aaa4; border-radius: 6px; font-weight: 800; }
.danger-button:hover:not(:disabled) { background: #fff0ee; }
.danger-button:disabled { color: #9b9795; border-color: #ddd; cursor: not-allowed; }
@media (max-width: 680px) {
  .danger-zone { align-items: stretch; flex-direction: column; }
  .danger-button { width: 100%; }
}`;

export const OPERATOR_CONSOLE_APPROVAL_JS = `let currentApproval = null;
let latestApprovals = [];
const approvalOperationMetadata = ${JSON.stringify(OPERATOR_CONSOLE_APPROVAL_ACTIONS)};
const approvalOperationLabels = Object.fromEntries(Object.entries(approvalOperationMetadata)
  .map(([operation, metadata]) => [operation, metadata.label]));
const approvalStatusLabels = { pending: '待复核', approved: '已批准', rejected: '已拒绝', executed: '已执行', expired: '已过期' };
const approvalExecutionPermissions = Object.fromEntries(Object.entries(approvalOperationMetadata)
  .map(([operation, metadata]) => [operation, metadata.permission]));
function approvalTone(status) {
  if (status === 'approved') return 'good';
  if (status === 'pending') return 'warning';
  if (status === 'rejected' || status === 'expired') return 'danger';
  return 'neutral';
}
function approvalAction(approval) {
  const wrap = document.createElement('div');
  wrap.className = 'approval-actions';
  const ownRequest = approval.requesterAccountId === state.principal.accountId;
  if (approval.status === 'pending' && hasPermission('approval.decide') && !ownRequest) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'table-action';
    button.textContent = '复核';
    button.addEventListener('click', () => openApprovalDecision(approval));
    wrap.append(button);
    return wrap;
  }
  if (approval.status === 'approved' && ownRequest) {
    const permission = approvalExecutionPermissions[approval.operation];
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'danger-button';
    button.textContent = '执行';
    button.disabled = !permission || !hasPermission(permission);
    button.addEventListener('click', () => executeApprovedApproval(approval, button));
    wrap.append(button);
    return wrap;
  }
  const message = document.createElement('small');
  message.textContent = approval.status === 'pending' && ownRequest
    ? '等待其他管理员复核'
    : approval.status === 'approved' ? '等待申请人执行' : '无需操作';
  wrap.append(message);
  return wrap;
}
function renderApprovals(data) {
  latestApprovals = data.approvals;
  const pending = data.approvals.filter((approval) => approval.status === 'pending').length;
  setStatus(byId('approval-pending-count'), pending + ' 项待处理', pending ? 'warning' : 'good');
  const body = byId('approvals-body');
  body.replaceChildren();
  data.approvals.slice(0, 20).forEach((approval) => {
    const row = document.createElement('tr');
    addCells(row, [
      approvalOperationLabels[approval.operation] || approval.operation,
      approval.targetType + ' / ' + approval.targetId,
      approval.requesterAccountId === state.principal.accountId ? '我' : approval.requesterAccountId,
      badge(approvalStatusLabels[approval.status] || approval.status, approvalTone(approval.status)),
      localTime(approval.expiresAt),
      approvalAction(approval),
    ]);
    body.append(row);
  });
  if (!data.approvals.length) emptyRow(body, 6, '暂无高风险操作审批');
}
async function refreshApprovals() {
  const center = byId('approval-center');
  if (!state.principal || !hasPermission('approval.read')) {
    center.classList.add('hidden');
    return;
  }
  center.classList.remove('hidden');
  try { renderApprovals(await request('/v1/admin/approvals?limit=50')); }
  catch (error) {
    const body = byId('approvals-body');
    emptyRow(body, 6, error.message);
  }
}
function openApprovalDecision(approval) {
  currentApproval = approval;
  setText('approval-decision-title', approvalOperationLabels[approval.operation] || approval.operation);
  setText('approval-operation', approval.operation);
  setText('approval-target', approval.targetType + ' / ' + approval.targetId);
  setText('approval-requester', approval.requesterAccountId);
  setText('approval-expiry', localTime(approval.expiresAt));
  byId('approval-request-payload').textContent = JSON.stringify(approval.request || {}, null, 2);
  byId('approval-reason').value = '';
  byId('approval-decision-form').querySelector('.form-error').textContent = '';
  byId('approval-decision-dialog').showModal();
}
async function decideCurrentApproval(decision) {
  if (!currentApproval) return;
  const reason = byId('approval-reason').value.trim();
  const error = byId('approval-decision-form').querySelector('.form-error');
  if (decision === 'reject' && !reason) {
    error.textContent = '拒绝时请填写原因。';
    return;
  }
  const buttons = [byId('approve-approval'), byId('reject-approval')];
  buttons.forEach((button) => { button.disabled = true; });
  error.textContent = '';
  try {
    await request('/v1/admin/approvals/' + encodeURIComponent(currentApproval.id) + '/decide', {
      method: 'POST', body: JSON.stringify({ decision, reason }),
    });
    closeDialog('approval-decision-dialog');
    toast(decision === 'approve' ? '审批已批准，等待申请人执行' : '审批已拒绝');
    await refreshApprovals();
  } catch (caught) { error.textContent = caught.message; }
  finally { buttons.forEach((button) => { button.disabled = false; }); }
}
function approvalExecutionRequest(approval) {
  const id = encodeURIComponent(approval.targetId);
  const request = approval.request || {};
  const receiptKeySeparator = approval.targetId.indexOf(':');
  const receiptKeyTarget = receiptKeySeparator > 0 && receiptKeySeparator < approval.targetId.length - 1
    ? {
        deploymentId: encodeURIComponent(approval.targetId.slice(0, receiptKeySeparator)),
        keyId: encodeURIComponent(approval.targetId.slice(receiptKeySeparator + 1)),
      }
    : null;
  const definitions = {
    'license.revoke': { path: '/v1/admin/licenses/' + id + '/revoke', method: 'POST' },
    'license.transfer_machine': { path: '/v1/admin/licenses/' + id + '/transfer-machine', method: 'POST', body: request },
    'license.rebind_deployment': { path: '/v1/admin/licenses/' + id + '/rebind-deployment', method: 'POST', body: request },
    'signing_key.activate': { path: '/v1/admin/signing-keys/' + id + '/activate', method: 'POST' },
    'signing_key.retire': { path: '/v1/admin/signing-keys/' + id + '/retire', method: 'POST' },
    'signing_key.revoke': { path: '/v1/admin/signing-keys/' + id + '/revoke', method: 'POST', body: request },
    'update_release.activate': { path: '/v1/admin/update-releases/' + id + '/activate', method: 'POST' },
    'update_release.rollback': { path: '/v1/admin/update-releases/' + id + '/rollback', method: 'POST' },
    'release_artifact.revoke': { path: '/v1/admin/release-artifacts/' + id + '/revoke', method: 'POST', body: request },
    'billing.rate.set': { path: '/v1/admin/billing/customers/' + id + '/rates/' + encodeURIComponent(request.module), method: 'PUT', body: request },
    'billing.topup': { path: '/v1/admin/billing/customers/' + id + '/topups', method: 'POST', body: request },
    'billing.refund': { path: '/v1/admin/billing/customers/' + id + '/refunds', method: 'POST', body: request },
    'billing.execution_receipt_key.register': { path: '/v1/admin/deployments/' + id + '/execution-receipt-keys', method: 'POST', body: request },
    'billing.execution_receipt_key.revoke': receiptKeyTarget ? { path: '/v1/admin/deployments/' + receiptKeyTarget.deploymentId + '/execution-receipt-keys/' + receiptKeyTarget.keyId + '/revoke', method: 'POST' } : null,
    'customer_erasure.execute': { path: '/v1/admin/data-governance/erasure-requests/' + id + '/execute', method: 'POST', body: request },
    'legal_hold.create': { path: '/v1/admin/data-governance/legal-holds', method: 'POST', body: request },
    'legal_hold.release': { path: '/v1/admin/data-governance/legal-holds/' + id + '/release', method: 'POST', body: request },
    'forensic_export.create': { path: '/v1/admin/data-governance/forensic-exports', method: 'POST', body: request },
  };
  return definitions[approval.operation];
}
async function executeApprovedApproval(approval, button) {
  const definition = approvalExecutionRequest(approval);
  if (!definition) return toast('审批目标格式无效，已阻止执行');
  button.disabled = true;
  try {
    const options = { method: definition.method, headers: { 'x-otto-approval-id': approval.id } };
    if (definition.body !== undefined) options.body = JSON.stringify(definition.body);
    const result = await request(definition.path, options);
    if (result && result.signature && result.license) presentLicenseEnvelope(result, '授权迁移成功');
    toast('高风险操作已执行，审批凭证已核销');
    await refreshDashboard();
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; }
}
byId('approval-decision-dialog').addEventListener('close', () => { currentApproval = null; });
byId('approve-approval').addEventListener('click', () => decideCurrentApproval('approve'));
byId('reject-approval').addEventListener('click', () => decideCurrentApproval('reject'));
byId('request-license-revoke').addEventListener('click', async (event) => {
  if (!activeLicenseDetail) return;
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await request('/v1/admin/approvals', {
      method: 'POST',
      body: JSON.stringify({ operation: 'license.revoke', targetType: 'license', targetId: activeLicenseDetail.id, request: {} }),
    });
    closeDialog('license-lifecycle-dialog');
    toast('吊销申请已提交：' + result.approval.id);
    await refreshApprovals();
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; }
});`;

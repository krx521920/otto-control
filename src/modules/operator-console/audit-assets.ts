export const OPERATOR_CONSOLE_AUDIT_CSS = `.audit-filters { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)) auto; gap: 10px; align-items: end; }
.audit-filters label { margin: 0; }
.audit-filters input { min-height: 42px; }
.audit-actions { display: flex; flex-wrap: wrap; gap: 8px; }
.audit-integrity { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px; margin: 16px 0; overflow: hidden; background: #dbe4e0; border: 1px solid #dbe4e0; border-radius: 6px; }
.audit-integrity > div { min-width: 0; padding: 12px; background: #f8faf9; }
.audit-integrity span, .audit-integrity strong { display: block; }
.audit-integrity span { color: #74817b; font-size: 12px; }
.audit-integrity strong { margin-top: 5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.audit-table { min-width: 920px; }
.audit-detail { max-width: 340px; overflow: hidden; color: #65736d; font: 12px/1.5 ui-monospace, "Cascadia Code", Consolas, monospace; text-overflow: ellipsis; white-space: nowrap; }
.audit-pagination { display: flex; justify-content: center; margin-top: 14px; }
.audit-anchor-panel { margin: 16px 0; padding: 14px; border: 1px solid #dbe4e0; border-radius: 6px; background: #f8faf9; }
.audit-anchor-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.audit-anchor-heading strong, .audit-anchor-heading span { display: block; }
.audit-anchor-heading span { margin-top: 4px; color: #74817b; font-size: 12px; }
.audit-anchor-list { display: grid; gap: 8px; margin-top: 12px; }
.audit-anchor-item { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 12px; align-items: center; padding: 10px 12px; border-top: 1px solid #e5ebe8; }
.audit-anchor-item code { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.audit-anchor-item small { color: #74817b; }
@media (max-width: 980px) { .audit-filters { grid-template-columns: repeat(2, minmax(0, 1fr)); } .audit-actions { grid-column: 1 / -1; } }
@media (max-width: 620px) { .audit-filters, .audit-integrity { grid-template-columns: 1fr; } .audit-anchor-heading { align-items: stretch; flex-direction: column; } .audit-anchor-item { grid-template-columns: 1fr; } }`;

export const OPERATOR_CONSOLE_AUDIT_JS = `let auditCursor = null;
function auditParameters(includeCursor) {
  const parameters = new URLSearchParams({ limit: '20' });
  [['actorId', 'audit-actor'], ['action', 'audit-action'], ['targetType', 'audit-target-type'], ['targetId', 'audit-target-id']].forEach(([name, id]) => {
    const value = byId(id).value.trim();
    if (value) parameters.set(name, value);
  });
  if (includeCursor && auditCursor) parameters.set('beforeId', String(auditCursor));
  return parameters;
}
function appendAuditEvents(events, reset) {
  const body = byId('audit-body');
  if (reset) body.replaceChildren();
  events.forEach((event) => {
    const row = document.createElement('tr');
    [localTime(event.createdAt), event.actorId, event.action, event.targetType + ' · ' + event.targetId].forEach((value) => {
      const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
    });
    const detail = document.createElement('td');
    detail.className = 'audit-detail';
    detail.textContent = JSON.stringify(event.detail);
    detail.title = detail.textContent;
    row.append(detail);
    const chain = document.createElement('td');
    chain.textContent = event.chainSequence == null ? '迁移前' : '#' + event.chainSequence;
    row.append(chain);
    body.append(row);
  });
  if (!body.children.length) {
    const row = document.createElement('tr'); row.className = 'empty-row';
    const cell = document.createElement('td'); cell.colSpan = 6; cell.textContent = '暂无匹配的审计记录。';
    row.append(cell); body.append(row);
  }
}
async function refreshAudit(reset = true) {
  const section = byId('audit-center');
  if (!state.principal || !hasPermission('audit.read')) { section.classList.add('hidden'); return; }
  section.classList.remove('hidden');
  if (reset) auditCursor = null;
  try {
    const data = await request('/v1/admin/audit/events?' + auditParameters(!reset));
    appendAuditEvents(data.events, reset);
    auditCursor = data.nextBeforeId;
    byId('audit-load-more').classList.toggle('hidden', !auditCursor);
    if (reset) await refreshAuditAnchors();
  } catch (error) { toast(error.message); }
}
function auditAnchorStatus(status) {
  return ({ pending: '等待投递', delivering: '正在投递', retrying: '等待重试', delivered: '已外部存证', failed: '最终失败' })[status] || status;
}
async function refreshAuditAnchors() {
  const data = await request('/v1/admin/audit/anchors?limit=10');
  setText('audit-anchor-destination', data.enabled ? data.destinationOrigin : '未配置外部锚定地址');
  const action = byId('poll-audit-anchors');
  action.classList.toggle('hidden', !hasPermission('audit.anchor.manage'));
  action.disabled = !data.enabled;
  const list = byId('audit-anchor-list'); list.replaceChildren();
  data.anchors.forEach((anchor) => {
    const item = document.createElement('div'); item.className = 'audit-anchor-item';
    const identity = document.createElement('div');
    const hash = document.createElement('code'); hash.textContent = anchor.payload.evidence.receipt.headHash;
    const metadata = document.createElement('small');
    metadata.textContent = localTime(anchor.createdAt) + ' · 链序号 #' + anchor.payload.evidence.receipt.lastSequence;
    identity.append(hash, metadata);
    const status = document.createElement('span'); status.className = 'status-pill ' + (anchor.status === 'delivered' ? 'good' : anchor.status === 'failed' ? 'danger' : 'neutral');
    status.textContent = auditAnchorStatus(anchor.status);
    item.append(identity, status);
    if (anchor.status === 'failed' && hasPermission('audit.anchor.manage')) {
      const retry = document.createElement('button'); retry.className = 'secondary compact'; retry.type = 'button'; retry.textContent = '重试';
      retry.addEventListener('click', async () => {
        retry.disabled = true;
        try { await request('/v1/admin/audit/anchors/' + encodeURIComponent(anchor.id) + '/retry', { method: 'POST' }); await refreshAuditAnchors(); }
        catch (error) { toast(error.message); } finally { retry.disabled = false; }
      });
      item.append(retry);
    } else {
      const reference = document.createElement('small'); reference.textContent = anchor.remoteReference || ('尝试 ' + anchor.attempts + ' 次'); item.append(reference);
    }
    list.append(item);
  });
  if (!data.anchors.length) { const empty = document.createElement('p'); empty.className = 'muted'; empty.textContent = '尚无外部锚定记录。'; list.append(empty); }
  await refreshAuditWitness();
}
async function refreshAuditWitness() {
  const data = await request('/v1/admin/audit-witness/receipts?limit=10');
  setText('audit-witness-sources', data.enabled ? ('可信来源：' + data.sources.map((source) => source.id).join('、')) : '尚未配置可信来源');
  const list = byId('audit-witness-list'); list.replaceChildren();
  data.receipts.forEach((receipt) => {
    const item = document.createElement('div'); item.className = 'audit-anchor-item';
    const identity = document.createElement('div');
    const hash = document.createElement('code'); hash.textContent = receipt.headHash;
    const metadata = document.createElement('small'); metadata.textContent = receipt.sourceId + ' · ' + localTime(receipt.receivedAt);
    identity.append(hash, metadata);
    const sequence = document.createElement('span'); sequence.className = 'status-pill good'; sequence.textContent = '链序号 #' + receipt.chainSequence;
    const key = document.createElement('small'); key.textContent = '密钥 ' + receipt.signingKeyId;
    item.append(identity, sequence, key); list.append(item);
  });
  if (!data.receipts.length) { const empty = document.createElement('p'); empty.className = 'muted'; empty.textContent = '尚未收到独立见证回执。'; list.append(empty); }
}
async function pollAuditAnchors() {
  const button = byId('poll-audit-anchors'); button.disabled = true;
  try {
    const result = await request('/v1/admin/audit/anchors/poll', { method: 'POST' });
    toast(result.chainValid === false ? '审计链异常，已拒绝对外锚定' : result.delivered ? '审计证据已外部锚定' : '锚定任务已检查');
    await refreshAudit(true);
  } catch (error) { toast(error.message); } finally { button.disabled = false; }
}
async function verifyAuditChain() {
  const button = byId('verify-audit'); button.disabled = true;
  try {
    const result = await request('/v1/admin/audit/verify', { method: 'POST' });
    const receipt = result.receipt;
    setStatus(byId('audit-integrity-state'), receipt.valid ? '完整' : '异常', receipt.valid ? 'good' : 'danger');
    setText('audit-checked-count', receipt.checkedEvents);
    setText('audit-chain-head', receipt.headHash.slice(0, 16) + '…');
    setText('audit-signing-key', result.signingKeyId);
    setText('audit-legacy-count', receipt.legacyEventCount);
    toast(receipt.valid ? '审计链校验通过' : '审计链在 #' + receipt.brokenAtSequence + ' 处异常');
  } catch (error) { toast(error.message); } finally { button.disabled = false; }
}
async function exportAuditCsv() {
  const button = byId('export-audit'); button.disabled = true;
  try {
    const response = await fetch('/v1/admin/audit/export.csv?' + auditParameters(false), {
      headers: { authorization: 'Bearer ' + state.token }, credentials: 'same-origin',
    });
    if (!response.ok) throw new Error('审计记录导出失败');
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'otto-control-audit-' + new Date().toISOString().slice(0, 10) + '.csv';
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 0);
    toast('审计记录已导出');
  } catch (error) { toast(error.message); } finally { button.disabled = false; }
}
byId('audit-filter-form').addEventListener('submit', (event) => { event.preventDefault(); void refreshAudit(true); });
byId('audit-load-more').addEventListener('click', () => refreshAudit(false));
byId('verify-audit').addEventListener('click', verifyAuditChain);
byId('export-audit').addEventListener('click', exportAuditCsv);
byId('poll-audit-anchors').addEventListener('click', pollAuditAnchors);`;

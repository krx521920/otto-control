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
@media (max-width: 980px) { .audit-filters { grid-template-columns: repeat(2, minmax(0, 1fr)); } .audit-actions { grid-column: 1 / -1; } }
@media (max-width: 620px) { .audit-filters, .audit-integrity { grid-template-columns: 1fr; } }`;

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
  } catch (error) { toast(error.message); }
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
byId('export-audit').addEventListener('click', exportAuditCsv);`;

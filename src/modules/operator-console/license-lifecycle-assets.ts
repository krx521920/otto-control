export const OPERATOR_CONSOLE_LICENSE_CSS = `.table-action { min-width: 58px; padding: 7px 10px; color: #075d4b; background: #edf7f3; border: 1px solid #b9d9cd; border-radius: 5px; font-weight: 800; }
.table-action:hover:not(:disabled) { background: #dff0e9; }
.table-action:disabled { color: #8b9692; background: #f1f3f2; border-color: #e0e5e3; cursor: not-allowed; }
.lifecycle-dialog { max-height: min(880px, calc(100vh - 32px)); overflow-y: auto; }
.license-summary { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 24px; margin-top: 0 !important; margin-bottom: 8px; }
.license-summary div { min-width: 0; padding: 11px 0; border-bottom: 1px solid #e5ebe8; }
.license-summary dt { margin-bottom: 5px; color: #71807a; font-size: 12px; font-weight: 800; text-transform: uppercase; }
.license-summary dd { margin: 0; overflow-wrap: anywhere; color: #172a22; font-weight: 700; }
.license-summary.compact { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.lifecycle-section { margin: 0 24px; padding: 18px 0; border-top: 1px solid #dbe4e0; }
.lifecycle-section h3 { margin: 0 0 13px; font-size: 16px; }
.subheading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.module-tags { display: flex; flex-wrap: wrap; gap: 8px; }
.module-tag { padding: 6px 9px; color: #245447; background: #edf7f3; border: 1px solid #cfe4dc; border-radius: 5px; font-size: 12px; font-weight: 800; }
.lifecycle-history { display: grid; gap: 0; }
.history-row { display: grid; grid-template-columns: 110px 90px minmax(0, 1fr) 170px; gap: 14px; align-items: center; padding: 11px 0; border-top: 1px solid #e8edeb; }
.history-row:first-child { border-top: 0; }
.history-row strong { color: #183b30; }
.history-row span, .history-row time { color: #64736d; font-size: 13px; overflow-wrap: anywhere; }
.manage-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 24px; padding-bottom: 24px; }
.lifecycle-form { min-width: 0; }
.lifecycle-form + .lifecycle-form { padding-left: 24px; border-left: 1px solid #dbe4e0; }
.lifecycle-form label { margin-bottom: 12px; }
@media (max-width: 760px) {
  .license-summary, .license-summary.compact, .manage-grid { grid-template-columns: 1fr; }
  .history-row { grid-template-columns: 72px minmax(0, 1fr); }
  .history-row time { grid-column: 2; }
  .lifecycle-form + .lifecycle-form { margin-top: 20px; padding-top: 20px; padding-left: 0; border-top: 1px solid #dbe4e0; border-left: 0; }
  .lifecycle-section { margin-left: 18px; margin-right: 18px; }
}`;

export const OPERATOR_CONSOLE_LICENSE_JS = `let activeLicenseDetail = null;
const licenseModuleLabels = {
  enterprise_tree: '企业组织', park_service: '产业园服务', feishu_auto_reply: '飞书自动回复',
  direct_messages: '企业私聊', atoa: 'A2A 协作', knowledge: '企业知识', skill_market: 'Skill 市场',
};
const lifecycleLabels = {
  renewed: '续期', expanded: '扩容', downgraded: '缩容', terms_changed: '条款调整',
  machine_transferred: '迁移机器', deployment_rebound: '重绑部署',
};
const seatLabels = {
  unreported: '尚未上报', within_limit: '正常', over_limit_monitor: '超额监测',
  overage_grace: '超额宽限', blocked: '已阻断',
};
function dateValue(value) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString().slice(0, 10) : '';
}
function replaceMessage(container, message) {
  const text = document.createElement('p');
  text.className = 'inline-message';
  text.textContent = message;
  container.replaceChildren(text);
}
function renderLicenseModules(modules) {
  const container = byId('lifecycle-modules');
  container.replaceChildren();
  modules.forEach((module) => {
    const tag = document.createElement('span');
    tag.className = 'module-tag';
    tag.textContent = licenseModuleLabels[module] || module;
    container.append(tag);
  });
}
function renderSeatUsage(usage, readable) {
  if (!readable) {
    setStatus(byId('lifecycle-seat-status'), '无读取权限', 'neutral');
    setText('lifecycle-active-seats', '-');
    setText('lifecycle-seat-limit', '-');
    setText('lifecycle-seat-grace', '-');
    setText('lifecycle-seat-reported', '-');
    return;
  }
  if (!usage) {
    setStatus(byId('lifecycle-seat-status'), '尚未上报', 'neutral');
    setText('lifecycle-active-seats', 0);
    setText('lifecycle-seat-limit', activeLicenseDetail.seatLimit);
    setText('lifecycle-seat-grace', '-');
    setText('lifecycle-seat-reported', '-');
    return;
  }
  const tone = usage.status === 'within_limit' ? 'good' : usage.status === 'blocked' ? 'danger' : 'warning';
  setStatus(byId('lifecycle-seat-status'), seatLabels[usage.status] || usage.status, tone);
  setText('lifecycle-active-seats', usage.activeSeats);
  setText('lifecycle-seat-limit', usage.seatLimit);
  setText('lifecycle-seat-grace', localTime(usage.graceExpiresAtMs));
  setText('lifecycle-seat-reported', localTime(usage.lastReportedAtMs));
}
function renderLicenseHistory(events, readable) {
  const container = byId('lifecycle-history');
  if (!readable) return replaceMessage(container, '当前账号没有生命周期历史读取权限。');
  if (!events.length) return replaceMessage(container, '这是初始授权，尚无后续变更。');
  container.replaceChildren();
  events.forEach((event) => {
    const row = document.createElement('div');
    row.className = 'history-row';
    const revision = document.createElement('strong');
    revision.textContent = 'v' + event.revision;
    const change = document.createElement('span');
    change.textContent = lifecycleLabels[event.changeType] || event.changeType;
    const actor = document.createElement('span');
    actor.textContent = '操作人：' + event.actorId;
    const created = document.createElement('time');
    created.textContent = localTime(event.createdAt);
    row.append(revision, change, actor, created);
    container.append(row);
  });
}
function configureLifecycleForms(detail) {
  const canManage = hasPermission('license.manage') && detail.state !== 'revoked';
  byId('license-manage-actions').classList.toggle('hidden', !canManage);
  const canRequestRevocation = hasPermission('license.revoke') && hasPermission('approval.request') && detail.state !== 'revoked';
  byId('license-danger-actions').classList.toggle('hidden', !canRequestRevocation);
  if (!canManage) return;
  const dayMs = 24 * 60 * 60 * 1000;
  const expiresAtMs = Date.parse(detail.expiresAt);
  const minimumMs = Math.max(Date.now() + dayMs, expiresAtMs + dayMs);
  const maximumMs = Date.now() + (5 * 366 - 1) * dayMs;
  const renewal = byId('license-renew-expiry');
  renewal.min = dateValue(minimumMs);
  renewal.max = dateValue(maximumMs);
  const renewalAvailable = minimumMs <= maximumMs;
  renewal.value = renewalAvailable ? dateValue(Math.min(Math.max(Date.now() + 365 * dayMs, minimumMs), maximumMs)) : '';
  renewal.disabled = !renewalAvailable;
  byId('license-renew-form').querySelector('button[type="submit"]').disabled = !renewalAvailable;
  byId('license-renew-form').querySelector('.form-error').textContent = renewalAvailable ? '' : '当前授权已经达到最长可续期限，请稍后再续期。';
  byId('license-renew-grace').value = String(detail.gracePeriodDays);
  byId('license-resize-seats').value = String(detail.seatLimit);
  byId('license-resize-grace').value = String(detail.gracePeriodDays);
  const enforcement = byId('license-resize-enforcement');
  enforcement.value = detail.offline ? 'monitor' : detail.seatEnforcement;
  enforcement.disabled = detail.offline;
}
function renderLicenseLifecycle(summary, usage, events, usageReadable) {
  activeLicenseDetail = summary;
  setText('lifecycle-title', summary.customerName + ' License');
  setText('lifecycle-id', summary.id);
  setText('lifecycle-revision', 'v' + summary.revision);
  setText('lifecycle-customer', summary.customerName);
  setText('lifecycle-deployment', summary.deploymentId);
  setText('lifecycle-expiry', localTime(summary.expiresAt));
  setText('lifecycle-mode', summary.offline ? '离线 / ' + licenseLabels[summary.state] : '在线 / ' + licenseLabels[summary.state]);
  renderLicenseModules(summary.modules);
  renderSeatUsage(usage, usageReadable);
  renderLicenseHistory(events, usageReadable);
  configureLifecycleForms(summary);
  byId('lifecycle-loading').classList.add('hidden');
  byId('lifecycle-content').classList.remove('hidden');
}
async function openLicenseLifecycle(licenseId) {
  activeLicenseDetail = null;
  byId('lifecycle-content').classList.add('hidden');
  byId('lifecycle-loading').classList.remove('hidden');
  byId('lifecycle-loading').textContent = '正在读取授权状态...';
  byId('license-lifecycle-dialog').showModal();
  const canReadUsage = hasPermission('license.usage.read');
  try {
    const [summary, lifecycle, seats] = await Promise.all([
      request('/v1/admin/licenses/' + encodeURIComponent(licenseId) + '/summary'),
      canReadUsage ? request('/v1/admin/licenses/' + encodeURIComponent(licenseId) + '/lifecycle?limit=50') : Promise.resolve({ events: [] }),
      canReadUsage ? request('/v1/admin/licenses/' + encodeURIComponent(licenseId) + '/seats') : Promise.resolve({ usage: null }),
    ]);
    renderLicenseLifecycle(summary.license, seats.usage, lifecycle.events, canReadUsage);
  } catch (error) {
    byId('lifecycle-loading').textContent = error.message;
  }
}
byId('license-lifecycle-dialog').addEventListener('close', () => { activeLicenseDetail = null; });
byId('license-renew-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  await submitAction(form, async () => {
    if (!activeLicenseDetail) throw new Error('请重新打开 License 详情');
    const expiresAt = byId('license-renew-expiry').value;
    const result = await request('/v1/admin/licenses/' + encodeURIComponent(activeLicenseDetail.id) + '/renew', {
      method: 'POST',
      body: JSON.stringify({ expiresAt: new Date(expiresAt + 'T23:59:59.999Z').toISOString(), gracePeriodDays: Number(byId('license-renew-grace').value) }),
    });
    closeDialog('license-lifecycle-dialog');
    presentLicenseEnvelope(result, 'License 续期成功');
    await refreshDashboard();
  });
});
byId('license-resize-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  await submitAction(form, async () => {
    if (!activeLicenseDetail) throw new Error('请重新打开 License 详情');
    const result = await request('/v1/admin/licenses/' + encodeURIComponent(activeLicenseDetail.id) + '/resize', {
      method: 'POST',
      body: JSON.stringify({
        seatLimit: Number(byId('license-resize-seats').value),
        seatEnforcement: byId('license-resize-enforcement').value,
        gracePeriodDays: Number(byId('license-resize-grace').value),
      }),
    });
    closeDialog('license-lifecycle-dialog');
    presentLicenseEnvelope(result, 'License 席位调整成功');
    await refreshDashboard();
  });
});`;

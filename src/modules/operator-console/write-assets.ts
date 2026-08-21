export const OPERATOR_CONSOLE_WRITE_CSS = `.write-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; }
.primary.compact { width: auto; }
.action-dialog { width: min(560px, calc(100vw - 28px)); padding: 0; color: #14231d; background: #fff; border: 1px solid #cbd6d1; border-radius: 8px; box-shadow: 0 24px 70px rgba(20,35,29,.22); }
.action-dialog.wide { width: min(820px, calc(100vw - 28px)); }
.action-dialog::backdrop { background: rgba(20,35,29,.42); }
.action-dialog form, .action-dialog > div, .action-dialog > p { margin-left: 24px; margin-right: 24px; }
.action-dialog form { margin-top: 0; margin-bottom: 0; padding-bottom: 22px; }
.dialog-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin: 0 0 20px !important; padding: 22px 24px 16px; border-bottom: 1px solid #e4eae7; }
.dialog-heading h2 { margin: 4px 0 0; font-size: 21px; }
.icon-close { width: 36px; height: 36px; padding: 0; color: #6f7c77; background: transparent; border: 0; border-radius: 50%; font-size: 28px; line-height: 1; }
.icon-close:hover { color: #172a22; background: #edf2f0; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 16px; }
.action-dialog select { width: 100%; min-height: 48px; padding: 11px 13px; color: #14231d; background: #fff; border: 1px solid #bfcac5; border-radius: 6px; }
.action-dialog fieldset { margin: 0 0 18px; padding: 14px; border: 1px solid #dbe4e0; border-radius: 6px; }
.action-dialog legend { padding: 0 6px; color: #43524c; font-size: 13px; font-weight: 800; }
.module-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px 14px; }
.module-grid label, .toggle-row label { display: flex; align-items: center; gap: 8px; margin: 0; color: #354a41; font-weight: 600; }
.module-grid input, .toggle-row input { width: 17px; min-height: 17px; margin: 0; box-shadow: none; accent-color: #087a61; }
.toggle-row { display: flex; flex-wrap: wrap; gap: 18px; margin-bottom: 16px; }
.form-error { min-height: 20px; margin: 0 0 8px; color: #b42318; font-size: 13px; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 8px; padding-top: 16px; border-top: 1px solid #e4eae7; }
.issued-summary { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 11px 14px; padding: 2px 0 18px; }
.issued-summary span { color: #71807a; }
.issued-summary strong { overflow-wrap: anywhere; }
.sensitive-note { padding: 12px 14px; color: #7c4f08; background: #fff4db; border: 1px solid #f0d49b; border-radius: 6px; font-size: 13px; line-height: 1.6; }
.delivery-summary { margin: 0 24px 18px; }
.delivery-summary div { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 16px; padding: 11px 0; border-bottom: 1px solid #e4eae7; }
.delivery-summary dt { color: #71807a; }
.delivery-summary dd { margin: 0; text-align: right; overflow-wrap: anywhere; }
@media (max-width: 680px) {
  .write-actions { width: 100%; justify-content: stretch; }
  .write-actions button { flex: 1; }
  .form-grid, .module-grid { grid-template-columns: 1fr; }
  .dialog-heading { padding: 18px; }
  .action-dialog form, .action-dialog > div, .action-dialog > p { margin-left: 18px; margin-right: 18px; }
}`;

export const OPERATOR_CONSOLE_WRITE_JS = `let latestOverview = null;
let lastLicenseEnvelope = null;
let commercialPlanCatalog = null;
let activeDeliveryCustomer = null;
function renderCommercialPlanCatalog(result) {
  commercialPlanCatalog = result.catalog;
  syncPlanControls(false);
}
async function openCustomerDelivery(customer) {
  activeDeliveryCustomer = customer;
  setText('delivery-title', customer.name + ' · 授权与上报范围');
  byId('delivery-dialog').showModal();
  try {
    const result = await request('/v1/admin/customers/' + encodeURIComponent(customer.id) + '/delivery-package.json');
    const bundle = result.bundle;
    const licenses = bundle.authorization.licenses;
    const modules = [...new Set(licenses.flatMap((license) => license.modules))];
    setText('delivery-plans', licenses.length ? licenses.map((license) => license.plan + (license.planCompliant ? '' : '（需复核）')).join(' / ') : '暂无授权');
    setText('delivery-modules', modules.length ? modules.join('、') : '暂无');
    setText('delivery-telemetry', bundle.reportingBoundary.enabledByLicense ? '已由至少一个 License 允许，仅上传下列运行元数据' : '当前 License 均未允许');
    setText('delivery-region', bundle.customer.dataRegion);
    setText('delivery-contact', bundle.privacyOperations.contact);
    setText('delivery-prohibited', bundle.reportingBoundary.prohibitedByDefault.join('、'));
  } catch (error) { toast(error.message); closeDialog('delivery-dialog'); }
}
function presentLicenseEnvelope(result, title) {
  lastLicenseEnvelope = result;
  setText('issued-result-title', title || '授权文件已生成');
  setText('issued-license-id', result.license.id);
  setText('issued-customer', result.license.customerName);
  setText('issued-expiry', localTime(result.license.expiresAtMs));
  byId('license-result-dialog').showModal();
}
function hasPermission(permission) {
  return Boolean(state.principal && state.principal.permissions.includes(permission));
}
function configureWriteActions() {
  const actions = [
    ['create-customer-button', 'customer.create'],
    ['create-deployment-button', 'deployment.create'],
    ['issue-license-button', 'license.issue'],
  ];
  actions.forEach(([id, permission]) => byId(id).classList.toggle('hidden', !hasPermission(permission)));
  byId('create-deployment-enrollment-button').classList.toggle(
    'hidden',
    !hasPermission('deployment.create') || !hasPermission('license.issue'),
  );
}
function replaceOptions(id, records, label) {
  const list = byId(id);
  list.replaceChildren();
  records.forEach((record) => {
    const option = document.createElement('option');
    option.value = record.id;
    option.label = label(record);
    list.append(option);
  });
}
function populateWriteOptions(overview) {
  latestOverview = overview;
  replaceOptions('customer-options', overview.recent.customers, (record) => record.name);
  replaceOptions('deployment-options', overview.recent.deployments, (record) => record.name + ' · ' + record.customerName);
}
function newDeploymentId() {
  return 'dep_' + crypto.randomUUID().replaceAll('-', '').slice(0, 24);
}
function tomorrowDate() {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() + 1);
  return date.toISOString().slice(0, 10);
}
function syncOfflineLicenseControls() {
  const offline = byId('license-offline').checked;
  const enforcement = byId('license-seat-enforcement');
  const billingEnforcement = byId('license-billing-enforcement');
  const telemetry = byId('license-telemetry');
  if (offline) {
    enforcement.value = 'monitor';
    billingEnforcement.value = 'disabled';
    telemetry.checked = false;
  }
  enforcement.disabled = offline;
  billingEnforcement.disabled = offline;
  telemetry.disabled = offline;
}
function syncPlanControls(resetModules) {
  if (!commercialPlanCatalog) return syncOfflineLicenseControls();
  const plan = commercialPlanCatalog.plans.find((item) => item.id === byId('license-plan').value);
  if (!plan) return;
  document.querySelectorAll('input[name="license-module"]').forEach((input) => {
    input.disabled = !plan.allowedModules.includes(input.value);
    if (resetModules) input.checked = plan.defaultModules.includes(input.value);
    if (plan.requiredModules.includes(input.value)) input.checked = true;
  });
  const offline = byId('license-offline');
  offline.disabled = !plan.offlineAllowed;
  if (!plan.offlineAllowed) offline.checked = false;
  if (resetModules) {
    byId('license-seat-enforcement').value = plan.defaultSeatEnforcement;
    byId('license-billing-enforcement').value = plan.defaultBillingEnforcement;
    byId('license-telemetry').checked = plan.defaultTelemetryAllowed;
  }
  syncOfflineLicenseControls();
}
function openDialog(id) {
  const dialog = byId(id);
  if (id === 'deployment-dialog') {
    byId('deployment-id').value = newDeploymentId();
    if (latestOverview && latestOverview.recent.customers.length === 1) byId('deployment-customer').value = latestOverview.recent.customers[0].id;
  }
  if (id === 'license-dialog') {
    byId('license-expiry').min = tomorrowDate();
    if (!byId('license-expiry').value) {
      const date = new Date();
      date.setUTCFullYear(date.getUTCFullYear() + 1);
      byId('license-expiry').value = date.toISOString().slice(0, 10);
    }
    if (latestOverview && latestOverview.recent.deployments.length === 1) byId('license-deployment').value = latestOverview.recent.deployments[0].id;
    syncPlanControls(false);
  }
  dialog.showModal();
}
function closeDialog(id) {
  const dialog = byId(id);
  if (dialog.open) dialog.close();
  if (id === 'license-result-dialog') lastLicenseEnvelope = null;
  if (id === 'delivery-dialog') activeDeliveryCustomer = null;
}
async function submitAction(form, action) {
  const button = form.querySelector('button[type="submit"]');
  const error = form.querySelector('.form-error');
  button.disabled = true;
  error.textContent = '';
  try { await action(); }
  catch (caught) { error.textContent = caught.message; }
  finally { button.disabled = false; }
}
document.querySelectorAll('[data-close]').forEach((button) => button.addEventListener('click', () => closeDialog(button.dataset.close)));
byId('create-customer-button').addEventListener('click', () => openDialog('customer-dialog'));
byId('create-deployment-button').addEventListener('click', () => openDialog('deployment-dialog'));
byId('issue-license-button').addEventListener('click', () => openDialog('license-dialog'));
byId('customer-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  await submitAction(form, async () => {
    const result = await request('/v1/admin/customers', { method: 'POST', body: JSON.stringify({ name: byId('customer-name').value.trim() }) });
    closeDialog('customer-dialog');
    form.reset();
    toast('客户“' + result.customer.name + '”已创建');
    await refreshDashboard();
  });
});
byId('deployment-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  await submitAction(form, async () => {
    const result = await request('/v1/admin/deployments', { method: 'POST', body: JSON.stringify({
      deploymentId: byId('deployment-id').value,
      customerId: byId('deployment-customer').value.trim(),
      organizationId: byId('deployment-organization').value.trim(),
      machineFingerprint: byId('deployment-fingerprint').value.trim().toLowerCase(),
      name: byId('deployment-name').value.trim(),
    }) });
    closeDialog('deployment-dialog');
    form.reset();
    toast('部署“' + result.deployment.name + '”已登记');
    await refreshDashboard();
  });
});
byId('license-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  await submitAction(form, async () => {
    const modules = [...document.querySelectorAll('input[name="license-module"]:checked')].map((input) => input.value);
    if (!modules.length) throw new Error('请至少选择一个授权模块');
    const expiry = byId('license-expiry').value;
    const result = await request('/v1/admin/licenses', { method: 'POST', body: JSON.stringify({
      deploymentId: byId('license-deployment').value.trim(),
      plan: byId('license-plan').value,
      expiresAt: new Date(expiry + 'T23:59:59.999Z').toISOString(),
      seatLimit: Number(byId('license-seats').value),
      gracePeriodDays: Number(byId('license-grace').value),
      seatEnforcement: byId('license-seat-enforcement').value,
      billingEnforcement: byId('license-billing-enforcement').value,
      modules,
      offline: byId('license-offline').checked,
      telemetryAllowed: byId('license-telemetry').checked,
    }) });
    closeDialog('license-dialog');
    presentLicenseEnvelope(result, '授权签发成功');
    await refreshDashboard();
  });
});
byId('license-offline').addEventListener('change', syncOfflineLicenseControls);
byId('license-plan').addEventListener('change', () => syncPlanControls(true));
byId('license-result-dialog').addEventListener('close', () => { lastLicenseEnvelope = null; });
byId('download-license').addEventListener('click', () => {
  if (!lastLicenseEnvelope) return;
  const blob = new Blob([JSON.stringify(lastLicenseEnvelope, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'otto-license-' + lastLicenseEnvelope.license.id + '.json';
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  toast('授权文件已下载');
});
byId('download-delivery-package').addEventListener('click', () => {
  if (!activeDeliveryCustomer) return;
  void downloadWithAuth('/v1/admin/customers/' + encodeURIComponent(activeDeliveryCustomer.id) + '/delivery-package.json', 'otto-delivery-' + activeDeliveryCustomer.id + '.json');
});
byId('download-roi-report').addEventListener('click', () => {
  if (!activeDeliveryCustomer) return;
  void downloadWithAuth('/v1/admin/customers/' + encodeURIComponent(activeDeliveryCustomer.id) + '/roi-report.csv', 'otto-roi-' + activeDeliveryCustomer.id + '.csv');
});`;

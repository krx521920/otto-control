export const OPERATOR_CONSOLE_DEPLOYMENT_ENROLLMENT_CSS = `.deployment-enrollment-summary {
  grid-template-columns: 140px minmax(0, 1fr);
}
.deployment-enrollment-summary .enrollment-secret {
  display: block;
  padding: 10px 12px;
  color: #12342a;
  background: #edf8f4;
  border: 1px solid #b9d9ce;
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  line-height: 1.55;
  overflow-wrap: anywhere;
  user-select: all;
}
@media (max-width: 680px) {
  .deployment-enrollment-summary { grid-template-columns: 1fr; }
}`;

export const OPERATOR_CONSOLE_DEPLOYMENT_ENROLLMENT_JS = `let activeDeploymentEnrollment = null;

function deploymentEnrollmentExpiryDate() {
  const date = new Date();
  date.setUTCFullYear(date.getUTCFullYear() + 1);
  return date.toISOString().slice(0, 10);
}
function optionalTrimmedValue(id) {
  const value = byId(id).value.trim();
  return value || undefined;
}
function clearDeploymentEnrollmentResult() {
  activeDeploymentEnrollment = null;
  setText('deployment-enrollment-result-id', '-');
  setText('deployment-enrollment-result-tenant', '-');
  setText('deployment-enrollment-result-expiry', '-');
  setText('deployment-enrollment-result-control-url', '-');
  setText('deployment-enrollment-result-secret', '-');
}
function openDeploymentEnrollmentDialog() {
  const expiry = byId('enroll-deployment-expiry');
  expiry.min = tomorrowDate();
  if (!expiry.value) expiry.value = deploymentEnrollmentExpiryDate();
  if (latestOverview && latestOverview.recent.customers.length === 1) {
    byId('enroll-deployment-customer').value = latestOverview.recent.customers[0].id;
  }
  byId('deployment-enrollment-dialog').showModal();
}
function presentDeploymentEnrollment(result) {
  activeDeploymentEnrollment = {
    id: result.enrollment.id,
    secret: result.bootstrapSecret,
  };
  setText('deployment-enrollment-result-id', result.enrollment.id);
  setText(
    'deployment-enrollment-result-tenant',
    result.enrollment.customerId + ' / ' + result.enrollment.organizationId,
  );
  setText('deployment-enrollment-result-expiry', localTime(result.enrollment.expiresAt));
  setText('deployment-enrollment-result-control-url', window.location.origin);
  setText('deployment-enrollment-result-secret', result.bootstrapSecret);
  byId('deployment-enrollment-result-dialog').showModal();
}
function downloadDeploymentEnrollmentSecret() {
  if (!activeDeploymentEnrollment) return;
  const blob = new Blob([activeDeploymentEnrollment.secret + '\\n'], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'otto-deployment-bootstrap-' + activeDeploymentEnrollment.id + '.secret';
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  toast('一次性口令文件已下载，请限制为部署服务账号可读');
}

byId('create-deployment-enrollment-button').addEventListener('click', openDeploymentEnrollmentDialog);
byId('deployment-enrollment-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  await submitAction(form, async () => {
    const expiry = byId('enroll-deployment-expiry').value;
    const result = await request('/v1/admin/deployment-enrollments', {
      method: 'POST',
      body: JSON.stringify({
        customerId: byId('enroll-deployment-customer').value.trim(),
        organizationId: byId('enroll-deployment-organization').value.trim(),
        organizationName: byId('enroll-organization-name').value.trim(),
        organizationSlug: optionalTrimmedValue('enroll-organization-slug'),
        ceoUsername: byId('enroll-ceo-username').value.trim(),
        ceoName: byId('enroll-ceo-name').value.trim(),
        ceoPhone: byId('enroll-ceo-phone').value.trim(),
        defaultDepartmentName: byId('enroll-default-department').value.trim(),
        deploymentName: byId('enroll-deployment-name').value.trim(),
        plan: byId('enroll-deployment-plan').value,
        expiresAt: new Date(expiry + 'T23:59:59.999Z').toISOString(),
        seatLimit: Number(byId('enroll-deployment-seats').value),
        validForHours: Number(byId('enroll-deployment-valid-hours').value),
        telemetryAllowed: byId('enroll-telemetry').checked,
        modelGatewayUrl: optionalTrimmedValue('enroll-model-gateway-url'),
        federationGatewayUrl: optionalTrimmedValue('enroll-federation-gateway-url'),
        updateDistributionId: optionalTrimmedValue('enroll-update-distribution-id'),
      }),
    });
    closeDialog('deployment-enrollment-dialog');
    form.reset();
    presentDeploymentEnrollment(result);
    toast('服务器一键接入凭证已生成');
  });
});
byId('deployment-enrollment-result-dialog').addEventListener('close', clearDeploymentEnrollmentResult);
byId('copy-deployment-enrollment-secret').addEventListener('click', async () => {
  if (!activeDeploymentEnrollment) return;
  try {
    await navigator.clipboard.writeText(activeDeploymentEnrollment.secret);
    toast('一次性口令已复制');
  } catch { toast('复制失败，请使用下载口令文件'); }
});
byId('download-deployment-enrollment-secret').addEventListener(
  'click',
  downloadDeploymentEnrollmentSecret,
);`;

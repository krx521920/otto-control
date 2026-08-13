import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REQUIRED_AUDIT_SCOPE = [
  'authentication_and_policy',
  'provider_secret_handling',
  'network_boundary',
  'billing_integrity',
  'availability_and_abuse_resistance',
];
const DPA_STATUSES = new Set(['pending', 'approved', 'rejected', 'expired']);
const AUDIT_STATUSES = new Set(['pending', 'passed', 'failed', 'expired']);
const ACCEPTANCE_STATUSES = new Set(['pending', 'passed', 'failed', 'expired']);
const REQUIRED_ACCEPTANCE = {
  runtimeFailures: (report) => report.drill === 'edge_runtime_failures'
    && report.result === 'passed',
  keyRevocation: (report) => report.drill === 'edge_signing_key_revocation'
    && report.result === 'passed',
  billingReconciliation: (report) => report.schemaVersion === 1
    && report.result === 'passed' && Array.isArray(report.issues) && report.issues.length === 0,
  soak24h: (report) => report.kind === 'otto_edge_gateway_acceptance'
    && report.profile === 'soak-24h' && report.result === 'passed'
    && report.durationSeconds >= 24 * 60 * 60,
  costLoad: (report) => report.kind === 'otto_edge_gateway_acceptance'
    && report.profile === 'cost-load' && report.result === 'passed',
  esaInfrastructure: (report) => report.kind === 'otto_aliyun_esa_infrastructure_acceptance'
    && report.result === 'passed' && report.publicRouteEnabled === true
    && report.publicRouteBypass === false && report.certificateStatus === 'issued'
    && report.wafEnabled === true && report.tls10 === false && report.tls11 === false
    && report.tls12 === true && report.tls13 === true
    && report.secretMaterialInTerraform === false
    && typeof report.terraformPlanSha256 === 'string'
    && SHA256.test(report.terraformPlanSha256),
  esaRollout: (report) => report.drill === 'esa_canary_rollout'
    && report.result === 'promoted' && report.startedPercent <= 10
    && report.completedPercent === 100 && report.rollbackDrill === 'passed'
    && report.billingReady === true,
  esaKeyringRevocation: (report) => report.drill === 'esa_keyring_emergency_revocation'
    && report.environment === 'preproduction' && report.result === 'passed'
    && report.publicKeyringVerified === true && Array.isArray(report.nodeEvidence)
    && report.nodeEvidence.length >= 2
    && report.nodeEvidence.every((node) => node.oldTokenStatus === 401
      && node.replacementTokenStatus >= 200 && node.replacementTokenStatus < 300),
  multiNodeBilling: (report) => report.kind === 'otto_edge_multi_node_billing_acceptance'
    && report.result === 'passed' && report.nodes >= 2 && report.activeNodes >= 2
    && report.pending === 0 && report.retrying === 0 && report.deadLetter === 0
    && report.sequenceGaps === 0 && report.reconciliationResult === 'passed',
};
const SHA256 = /^[a-f0-9]{64}$/u;
const PLACEHOLDERS = /(?:TODO|TBD|UNSET|CONFIGURE|EXAMPLE|REPLACE)/iu;

function object(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function array(value, name) {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  return value;
}

function text(value, name, maximum = 500) {
  if (typeof value !== 'string' || !value.trim() || value.length > maximum) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function nullableText(value, name, maximum = 500) {
  return value === null ? null : text(value, name, maximum);
}

function integer(value, name, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function nullableInteger(value, name, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  return value === null ? null : integer(value, name, minimum, maximum);
}

function instant(value, name) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function nullableInstant(value, name) {
  return value === null ? null : instant(value, name);
}

function evidence(value, name) {
  const body = object(value, name);
  const path = nullableText(body.path, `${name}.path`, 500);
  const sha256 = body.sha256;
  if (sha256 !== null && (typeof sha256 !== 'string' || !SHA256.test(sha256))) {
    throw new Error(`${name}.sha256 is invalid`);
  }
  if ((path === null) !== (sha256 === null)) {
    throw new Error(`${name} path and sha256 must be supplied together`);
  }
  return { path, sha256 };
}

function assertEvidence(root, record, name) {
  if (!record.path || !record.sha256) throw new Error(`${name} evidence is missing`);
  if (isAbsolute(record.path)) throw new Error(`${name} evidence path must be repository-relative`);
  const candidate = resolve(root, record.path);
  const rootReal = realpathSync(root);
  if (!existsSync(candidate)) {
    throw new Error(`${name} evidence path escapes the repository or does not exist`);
  }
  const candidateReal = realpathSync(candidate);
  const relativePath = relative(rootReal, candidateReal);
  if (relativePath.startsWith('..') || isAbsolute(relativePath)) {
    throw new Error(`${name} evidence path escapes the repository or does not exist`);
  }
  const actual = createHash('sha256').update(readFileSync(candidateReal)).digest('hex');
  if (actual !== record.sha256) throw new Error(`${name} evidence checksum does not match`);
  return candidateReal;
}

function acceptance(value, name) {
  const body = object(value, name);
  if (typeof body.status !== 'string' || !ACCEPTANCE_STATUSES.has(body.status)) {
    throw new Error(`${name}.status is invalid`);
  }
  return {
    status: body.status,
    releaseCandidate: nullableText(body.releaseCandidate, `${name}.releaseCandidate`, 200),
    evidence: evidence(body.evidence, `${name}.evidence`),
    performedAt: nullableInstant(body.performedAt, `${name}.performedAt`),
    expiresAt: nullableInstant(body.expiresAt, `${name}.expiresAt`),
  };
}

function approvedWindow(reviewedAt, expiresAt, now, name) {
  if (!reviewedAt || !expiresAt) throw new Error(`${name} approval window is missing`);
  if (Date.parse(reviewedAt) > now) throw new Error(`${name} approval is dated in the future`);
  if (Date.parse(expiresAt) <= now || Date.parse(expiresAt) <= Date.parse(reviewedAt)) {
    throw new Error(`${name} approval is expired`);
  }
}

function normalizeStatus(raw) {
  const body = object(raw, 'release assurance status');
  if (body.schemaVersion !== 1) throw new Error('release assurance schemaVersion must be 1');
  if (body.product !== 'otto-edge-gateway') throw new Error('release assurance product is invalid');
  const releaseCandidate = text(body.releaseCandidate, 'releaseCandidate', 200);
  if (body.overallStatus !== 'blocked' && body.overallStatus !== 'ready') {
    throw new Error('overallStatus is invalid');
  }
  const auditBody = object(body.externalSecurityAudit, 'externalSecurityAudit');
  if (typeof auditBody.status !== 'string' || !AUDIT_STATUSES.has(auditBody.status)) {
    throw new Error('externalSecurityAudit.status is invalid');
  }
  const findingBody = object(auditBody.openFindings, 'externalSecurityAudit.openFindings');
  const audit = {
    status: auditBody.status,
    auditor: nullableText(auditBody.auditor, 'externalSecurityAudit.auditor', 200),
    scope: array(auditBody.scope, 'externalSecurityAudit.scope').map((entry, index) => (
      text(entry, `externalSecurityAudit.scope[${index}]`, 100)
    )),
    report: evidence(auditBody.report, 'externalSecurityAudit.report'),
    openFindings: {
      critical: nullableInteger(findingBody.critical, 'openFindings.critical'),
      high: nullableInteger(findingBody.high, 'openFindings.high'),
      medium: nullableInteger(findingBody.medium, 'openFindings.medium'),
      low: nullableInteger(findingBody.low, 'openFindings.low'),
    },
    reviewedAt: nullableInstant(auditBody.reviewedAt, 'externalSecurityAudit.reviewedAt'),
    expiresAt: nullableInstant(auditBody.expiresAt, 'externalSecurityAudit.expiresAt'),
  };
  const reviews = array(body.providerDpaReviews, 'providerDpaReviews').map((value, index) => {
    const review = object(value, `providerDpaReviews[${index}]`);
    if (typeof review.status !== 'string' || !DPA_STATUSES.has(review.status)) {
      throw new Error(`providerDpaReviews[${index}].status is invalid`);
    }
    const incidentNoticeHours = nullableInteger(
      review.securityIncidentNoticeHours,
      `providerDpaReviews[${index}].securityIncidentNoticeHours`,
      1,
      720,
    );
    const deletionCommitmentDays = nullableInteger(
      review.deletionCommitmentDays,
      `providerDpaReviews[${index}].deletionCommitmentDays`,
      0,
      3650,
    );
    return {
      providerId: text(review.providerId, `providerDpaReviews[${index}].providerId`, 100),
      status: review.status,
      legalReviewer: nullableText(
        review.legalReviewer,
        `providerDpaReviews[${index}].legalReviewer`,
        200,
      ),
      agreementReference: nullableText(
        review.agreementReference,
        `providerDpaReviews[${index}].agreementReference`,
        300,
      ),
      dataResidency: nullableText(review.dataResidency, `providerDpaReviews[${index}].dataResidency`),
      crossBorderTransferBasis: nullableText(
        review.crossBorderTransferBasis,
        `providerDpaReviews[${index}].crossBorderTransferBasis`,
      ),
      modelTrainingUse: review.modelTrainingUse,
      subprocessorsReviewed: review.subprocessorsReviewed,
      securityIncidentNoticeHours: incidentNoticeHours,
      deletionCommitmentDays,
      evidence: evidence(review.evidence, `providerDpaReviews[${index}].evidence`),
      reviewedAt: nullableInstant(review.reviewedAt, `providerDpaReviews[${index}].reviewedAt`),
      expiresAt: nullableInstant(review.expiresAt, `providerDpaReviews[${index}].expiresAt`),
    };
  });
  const providerIds = new Set();
  for (const review of reviews) {
    if (providerIds.has(review.providerId)) throw new Error(`duplicate DPA provider: ${review.providerId}`);
    providerIds.add(review.providerId);
  }
  const acceptanceBody = object(body.technicalAcceptance, 'technicalAcceptance');
  const technicalAcceptance = Object.fromEntries(Object.keys(REQUIRED_ACCEPTANCE).map((key) => [
    key,
    acceptance(acceptanceBody[key], `technicalAcceptance.${key}`),
  ]));
  return {
    schemaVersion: 1,
    product: body.product,
    releaseCandidate,
    overallStatus: body.overallStatus,
    externalSecurityAudit: audit,
    technicalAcceptance,
    providerDpaReviews: reviews,
  };
}

export function checkEdgeReleaseAssurance(raw, options) {
  const status = normalizeStatus(raw);
  const root = resolve(options.root);
  const now = options.now?.() ?? Date.now();
  const blockers = [];
  if (status.overallStatus !== 'ready') blockers.push('overallStatus is not ready');
  if (PLACEHOLDERS.test(status.releaseCandidate)) blockers.push('releaseCandidate is a placeholder');

  const audit = status.externalSecurityAudit;
  if (audit.status !== 'passed') blockers.push('external security audit has not passed');
  if (!audit.auditor || PLACEHOLDERS.test(audit.auditor)) blockers.push('external auditor is missing');
  for (const required of REQUIRED_AUDIT_SCOPE) {
    if (!audit.scope.includes(required)) blockers.push(`external audit scope is missing ${required}`);
  }
  if (audit.openFindings.critical !== 0 || audit.openFindings.high !== 0) {
    blockers.push('external audit has unresolved critical or high findings');
  }
  if (audit.status === 'passed') {
    try {
      assertEvidence(root, audit.report, 'external security audit');
      approvedWindow(audit.reviewedAt, audit.expiresAt, now, 'external security audit');
    } catch (error) {
      blockers.push(error instanceof Error ? error.message : String(error));
    }
  }

  for (const [key, validate] of Object.entries(REQUIRED_ACCEPTANCE)) {
    const record = status.technicalAcceptance[key];
    const name = `technical acceptance ${key}`;
    if (record.status !== 'passed') {
      blockers.push(`${name} has not passed`);
      continue;
    }
    if (record.releaseCandidate !== status.releaseCandidate) {
      blockers.push(`${name} is not bound to the release candidate`);
    }
    try {
      const path = assertEvidence(root, record.evidence, name);
      approvedWindow(record.performedAt, record.expiresAt, now, name);
      const report = JSON.parse(readFileSync(path, 'utf8'));
      if (!validate(report)) blockers.push(`${name} report does not prove the required result`);
    } catch (error) {
      blockers.push(error instanceof Error ? error.message : String(error));
    }
  }

  if (status.providerDpaReviews.length === 0) blockers.push('no model provider DPA was reviewed');
  for (const review of status.providerDpaReviews) {
    const name = `DPA ${review.providerId}`;
    if (review.status !== 'approved') blockers.push(`${name} is not approved`);
    if (PLACEHOLDERS.test(review.providerId)) blockers.push(`${name} uses a placeholder provider`);
    if (!review.legalReviewer || PLACEHOLDERS.test(review.legalReviewer)) {
      blockers.push(`${name} legal reviewer is missing`);
    }
    if (!review.agreementReference || !review.dataResidency
      || !review.crossBorderTransferBasis) blockers.push(`${name} contractual fields are incomplete`);
    if (review.modelTrainingUse !== 'prohibited') {
      blockers.push(`${name} does not prohibit provider model training use`);
    }
    if (review.subprocessorsReviewed !== true) blockers.push(`${name} subprocessors were not reviewed`);
    if (review.securityIncidentNoticeHours === null
      || review.securityIncidentNoticeHours > 72) blockers.push(`${name} incident notice exceeds 72 hours`);
    if (review.deletionCommitmentDays === null
      || review.deletionCommitmentDays > 90) blockers.push(`${name} deletion commitment exceeds 90 days`);
    if (review.status === 'approved') {
      try {
        assertEvidence(root, review.evidence, name);
        approvedWindow(review.reviewedAt, review.expiresAt, now, name);
      } catch (error) {
        blockers.push(error instanceof Error ? error.message : String(error));
      }
    }
  }
  return {
    schemaVersion: 1,
    product: status.product,
    releaseCandidate: status.releaseCandidate,
    checkedAt: new Date(now).toISOString(),
    result: blockers.length === 0 ? 'passed' : 'blocked',
    blockers,
  };
}

function argumentsMap(argv) {
  const values = new Map();
  const flags = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const entry = argv[index];
    if (entry === '--allow-pending') {
      flags.add('allow-pending');
      continue;
    }
    if (!entry?.startsWith('--')) throw new Error(`unexpected argument: ${entry}`);
    const [name, inline] = entry.slice(2).split('=', 2);
    const value = inline ?? argv[index + 1];
    if (!name || !value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
    values.set(name, value);
    if (inline === undefined) index += 1;
  }
  return { values, flags };
}

function runCli(argv) {
  const { values, flags } = argumentsMap(argv);
  const statusFile = resolve(values.get('status') ?? 'security/edge-release-assurance-status.json');
  const root = resolve(values.get('root') ?? process.cwd());
  const raw = JSON.parse(readFileSync(statusFile, 'utf8'));
  const report = checkEdgeReleaseAssurance(raw, { root });
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  const output = values.get('output')?.trim();
  if (output) writeFileSync(resolve(output), serialized, { encoding: 'utf8', flag: 'wx' });
  else process.stdout.write(serialized);
  if (report.result !== 'passed' && !flags.has('allow-pending')) process.exitCode = 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

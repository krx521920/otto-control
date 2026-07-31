import type {
  AuditEventInput,
  ControlStore,
  CreateLicenseRecordInput,
  CreateUpdateReleaseRecordInput,
  CustomerRecord,
  DeploymentUpdateAssignmentRecord,
  DeploymentRecord,
  LicenseRecord,
  SigningKeyProvider,
  SigningKeyRecord,
  SigningKeyTransition,
  UpdateDistributionRecord,
  UpdateReleaseRecord,
  UpdateReleaseTransition,
} from '../../src/storage/control-store.js';
import type {
  DeploymentTelemetrySummary,
  OttoTelemetryEvent,
  OttoTelemetryReceipt,
} from '../../src/contracts/telemetry.js';

interface StoredTelemetryEvent extends OttoTelemetryEvent {
  deploymentId: string;
  licenseId: string;
  receivedAtMs: number;
}

export class MemoryControlStore implements ControlStore {
  readonly customers = new Map<string, CustomerRecord>();
  readonly deployments = new Map<string, DeploymentRecord>();
  readonly licenses = new Map<string, LicenseRecord>();
  readonly signingKeys = new Map<string, SigningKeyRecord>();
  readonly nonces = new Set<string>();
  readonly audits: AuditEventInput[] = [];
  readonly telemetryEvents = new Map<string, StoredTelemetryEvent>();
  readonly telemetryNonces = new Set<string>();
  readonly updateDistributions = new Map<string, UpdateDistributionRecord>();
  readonly updateReleases = new Map<string, UpdateReleaseRecord>();
  readonly updateAssignments = new Map<string, DeploymentUpdateAssignmentRecord>();
  readonly updatePolicyNonces = new Set<string>();

  async ping(): Promise<void> {}
  async close(): Promise<void> {}

  async createCustomer(input: { id: string; name: string }): Promise<CustomerRecord> {
    if (this.customers.has(input.id)) throw new Error('customer already exists');
    const now = new Date();
    const customer: CustomerRecord = {
      ...input,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    };
    this.customers.set(customer.id, customer);
    return customer;
  }

  async createDeployment(input: {
    id: string;
    customerId: string;
    organizationId: string;
    machineFingerprint: string;
    name: string;
  }): Promise<DeploymentRecord> {
    const customer = this.customers.get(input.customerId);
    if (!customer) throw new Error('customer does not exist');
    const now = new Date();
    const deployment: DeploymentRecord = {
      ...input,
      customerName: customer.name,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    };
    this.deployments.set(deployment.id, deployment);
    return deployment;
  }

  async getDeployment(id: string): Promise<DeploymentRecord | null> {
    return this.deployments.get(id) ?? null;
  }

  async createLicense(input: CreateLicenseRecordInput): Promise<LicenseRecord> {
    const now = new Date();
    const license = { ...input, createdAt: now, updatedAt: now };
    this.licenses.set(license.id, license);
    return license;
  }

  async getLicense(id: string): Promise<LicenseRecord | null> {
    return this.licenses.get(id) ?? null;
  }

  async revokeLicense(id: string, revokedAtMs: number): Promise<LicenseRecord | null> {
    const existing = this.licenses.get(id);
    if (!existing) return null;
    const updated = {
      ...existing,
      revokedAtMs: existing.revokedAtMs ?? revokedAtMs,
      updatedAt: new Date(revokedAtMs),
    };
    this.licenses.set(id, updated);
    return updated;
  }

  async registerSigningKey(input: {
    keyId: string;
    publicKeyPem: string;
    provider: SigningKeyProvider;
  }): Promise<SigningKeyRecord> {
    const existing = this.signingKeys.get(input.keyId);
    if (existing) {
      if (existing.publicKeyPem !== input.publicKeyPem || existing.provider !== input.provider) {
        throw new Error('signing key id is already bound to another provider or public key');
      }
      return existing;
    }
    const now = new Date();
    const key: SigningKeyRecord = {
      ...input,
      algorithm: 'ed25519',
      state: 'standby',
      createdAt: now,
      activatedAt: null,
      retiredAt: null,
      revokedAt: null,
      revocationReason: null,
      updatedAt: now,
    };
    this.signingKeys.set(key.keyId, key);
    return key;
  }

  async getSigningKey(keyId: string): Promise<SigningKeyRecord | null> {
    return this.signingKeys.get(keyId) ?? null;
  }

  async listSigningKeys(): Promise<SigningKeyRecord[]> {
    return [...this.signingKeys.values()];
  }

  async activateSigningKey(
    keyId: string,
    changedAt: Date,
  ): Promise<SigningKeyTransition | null> {
    const target = this.signingKeys.get(keyId);
    if (!target) return null;
    if (target.state === 'revoked') throw new Error('revoked signing key cannot be activated');
    const previous = [...this.signingKeys.values()].find((key) => key.state === 'active');
    if (previous && previous.keyId !== keyId) {
      this.signingKeys.set(previous.keyId, {
        ...previous,
        state: 'retired',
        retiredAt: changedAt,
        updatedAt: changedAt,
      });
    }
    const active: SigningKeyRecord = {
      ...target,
      state: 'active',
      activatedAt: target.activatedAt ?? changedAt,
      retiredAt: null,
      updatedAt: changedAt,
    };
    this.signingKeys.set(keyId, active);
    return { key: active, activeKey: active, previousActiveKey: previous ?? null };
  }

  async retireSigningKey(
    keyId: string,
    changedAt: Date,
  ): Promise<SigningKeyTransition | null> {
    const target = this.signingKeys.get(keyId);
    if (!target) return null;
    if (target.state === 'active') throw new Error('activate a replacement before retiring the active key');
    if (target.state === 'revoked') throw new Error('revoked signing key cannot be retired');
    const retired: SigningKeyRecord = {
      ...target,
      state: 'retired',
      retiredAt: target.retiredAt ?? changedAt,
      updatedAt: changedAt,
    };
    this.signingKeys.set(keyId, retired);
    return {
      key: retired,
      activeKey: [...this.signingKeys.values()].find((key) => key.state === 'active') ?? null,
      previousActiveKey: null,
    };
  }

  async revokeSigningKey(input: {
    keyId: string;
    replacementKeyId: string | null;
    reason: string;
    changedAt: Date;
  }): Promise<SigningKeyTransition | null> {
    const target = this.signingKeys.get(input.keyId);
    if (!target) return null;
    if (target.state === 'revoked') {
      return {
        key: target,
        activeKey: [...this.signingKeys.values()].find((key) => key.state === 'active') ?? null,
        previousActiveKey: null,
      };
    }
    let activeKey = [...this.signingKeys.values()].find((key) => key.state === 'active') ?? null;
    if (target.state === 'active') {
      if (!input.replacementKeyId || input.replacementKeyId === input.keyId) {
        throw new Error('revoking the active key requires a different replacement key');
      }
      const replacement = this.signingKeys.get(input.replacementKeyId);
      if (!replacement || replacement.state === 'revoked') {
        throw new Error('replacement signing key does not exist');
      }
      activeKey = {
        ...replacement,
        state: 'active',
        activatedAt: replacement.activatedAt ?? input.changedAt,
        retiredAt: null,
        updatedAt: input.changedAt,
      };
      this.signingKeys.set(activeKey.keyId, activeKey);
    }
    const revoked: SigningKeyRecord = {
      ...target,
      state: 'revoked',
      revokedAt: input.changedAt,
      retiredAt: target.retiredAt ?? input.changedAt,
      revocationReason: input.reason,
      updatedAt: input.changedAt,
    };
    this.signingKeys.set(input.keyId, revoked);
    return {
      key: revoked,
      activeKey: activeKey?.keyId === revoked.keyId ? null : activeKey,
      previousActiveKey: target.state === 'active' ? target : null,
    };
  }

  async consumeLeaseNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean> {
    const key = `${input.deploymentId}\0${input.nonce}`;
    if (this.nonces.has(key)) return false;
    this.nonces.add(key);
    return true;
  }

  async ingestTelemetryBatch(input: {
    deploymentId: string;
    licenseId: string;
    nonce: string;
    nonceExpiresAtMs: number;
    retentionBeforeMs: number;
    receivedAtMs: number;
    events: OttoTelemetryEvent[];
  }): Promise<OttoTelemetryReceipt | null> {
    const nonceKey = `${input.deploymentId}\0${input.nonce}`;
    if (this.telemetryNonces.has(nonceKey)) return null;
    this.telemetryNonces.add(nonceKey);
    for (const [key, event] of this.telemetryEvents) {
      if (event.receivedAtMs < input.retentionBeforeMs) this.telemetryEvents.delete(key);
    }
    let accepted = 0;
    let duplicates = 0;
    for (const event of input.events) {
      const key = `${input.deploymentId}\0${event.id}`;
      if (this.telemetryEvents.has(key)) {
        duplicates += 1;
      } else {
        accepted += 1;
        this.telemetryEvents.set(key, {
          ...event,
          deploymentId: input.deploymentId,
          licenseId: input.licenseId,
          receivedAtMs: input.receivedAtMs,
        });
      }
    }
    return { accepted, duplicates };
  }

  async getDeploymentTelemetrySummary(input: {
    deploymentId: string;
    sinceMs: number;
  }): Promise<DeploymentTelemetrySummary> {
    const allEvents = [...this.telemetryEvents.values()]
      .filter((event) => event.deploymentId === input.deploymentId);
    const events = allEvents.filter((event) => event.receivedAtMs >= input.sinceMs);
    const eventCounts: Record<string, number> = {};
    for (const event of events) {
      eventCounts[event.eventType] = (eventCounts[event.eventType] ?? 0) + 1;
    }
    const latestRuntimeHealth = allEvents
      .filter((event) => event.eventType === 'runtime_health')
      .sort((left, right) => right.createdAtMs - left.createdAtMs)[0];
    const lastSeen = allEvents
      .map((event) => event.receivedAtMs)
      .sort((left, right) => right - left)[0];
    return {
      deploymentId: input.deploymentId,
      since: new Date(input.sinceMs).toISOString(),
      totalEvents: events.length,
      lastSeenAt: lastSeen === undefined ? null : new Date(lastSeen).toISOString(),
      eventCounts,
      latestRuntimeHealth: latestRuntimeHealth
        ? {
            createdAt: new Date(latestRuntimeHealth.createdAtMs).toISOString(),
            receivedAt: new Date(latestRuntimeHealth.receivedAtMs).toISOString(),
            payload: latestRuntimeHealth.payload,
          }
        : null,
    };
  }

  async createUpdateDistribution(input: {
    id: string;
    name: string;
  }): Promise<UpdateDistributionRecord> {
    if (this.updateDistributions.has(input.id)) throw new Error('distribution already exists');
    const now = new Date();
    const distribution: UpdateDistributionRecord = {
      ...input,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    };
    this.updateDistributions.set(distribution.id, distribution);
    return distribution;
  }

  async getUpdateDistribution(id: string): Promise<UpdateDistributionRecord | null> {
    return this.updateDistributions.get(id) ?? null;
  }

  async assignDeploymentUpdateDistribution(input: {
    deploymentId: string;
    distributionId: string;
    updatedAt: Date;
  }): Promise<DeploymentUpdateAssignmentRecord> {
    if (!this.deployments.has(input.deploymentId)) throw new Error('deployment does not exist');
    if (!this.updateDistributions.has(input.distributionId)) {
      throw new Error('distribution does not exist');
    }
    const assignment = { ...input };
    this.updateAssignments.set(`${input.deploymentId}\0${input.distributionId}`, assignment);
    return assignment;
  }

  async hasDeploymentUpdateAssignment(
    deploymentId: string,
    distributionId: string,
  ): Promise<boolean> {
    return this.updateAssignments.has(`${deploymentId}\0${distributionId}`);
  }

  async createUpdateRelease(input: CreateUpdateReleaseRecordInput): Promise<UpdateReleaseRecord> {
    if (!this.updateDistributions.has(input.distributionId)) {
      throw new Error('distribution does not exist');
    }
    if (this.updateReleases.has(input.id)) throw new Error('release already exists');
    const duplicate = [...this.updateReleases.values()].some((release) => (
      release.distributionId === input.distributionId
      && release.version === input.version
      && release.channel === input.channel
    ));
    if (duplicate) throw new Error('release already exists');
    const now = new Date();
    const release: UpdateReleaseRecord = {
      ...input,
      state: 'draft',
      previousReleaseId: null,
      publishedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    this.updateReleases.set(release.id, release);
    return release;
  }

  async getUpdateRelease(id: string): Promise<UpdateReleaseRecord | null> {
    return this.updateReleases.get(id) ?? null;
  }

  async listUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]> {
    return [...this.updateReleases.values()]
      .filter((release) => release.distributionId === distributionId)
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime());
  }

  async activateUpdateRelease(
    id: string,
    publishedAt: Date,
  ): Promise<UpdateReleaseTransition | null> {
    const candidate = this.updateReleases.get(id);
    if (!candidate) return null;
    if (candidate.state === 'active') throw new Error('release is already active');
    if (candidate.state === 'rolled_back') throw new Error('release cannot be reactivated');
    const previous = [...this.updateReleases.values()].find((release) => (
      release.id !== id
      && release.distributionId === candidate.distributionId
      && release.channel === candidate.channel
      && release.state === 'active'
    ));
    if (previous) {
      this.updateReleases.set(previous.id, {
        ...previous,
        state: 'paused',
        updatedAt: publishedAt,
      });
    }
    const release: UpdateReleaseRecord = {
      ...candidate,
      state: 'active',
      previousReleaseId: previous?.id ?? null,
      publishedAt: candidate.publishedAt ?? publishedAt,
      updatedAt: publishedAt,
    };
    this.updateReleases.set(id, release);
    return { release, fallback: previous ?? null };
  }

  async pauseUpdateRelease(id: string, updatedAt: Date): Promise<UpdateReleaseRecord | null> {
    const existing = this.updateReleases.get(id);
    if (!existing) return null;
    if (existing.state !== 'active') return null;
    const release: UpdateReleaseRecord = { ...existing, state: 'paused', updatedAt };
    this.updateReleases.set(id, release);
    return release;
  }

  async rollbackUpdateRelease(
    id: string,
    updatedAt: Date,
  ): Promise<UpdateReleaseTransition | null> {
    const existing = this.updateReleases.get(id);
    if (!existing) return null;
    if (existing.state !== 'active' && existing.state !== 'paused') {
      throw new Error('release cannot be rolled back');
    }
    const release: UpdateReleaseRecord = { ...existing, state: 'rolled_back', updatedAt };
    this.updateReleases.set(id, release);
    const previous = existing.previousReleaseId
      ? this.updateReleases.get(existing.previousReleaseId)
      : undefined;
    const fallback = previous
      ? { ...previous, state: 'active' as const, updatedAt }
      : null;
    if (fallback) this.updateReleases.set(fallback.id, fallback);
    return { release, fallback };
  }

  async getActiveUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]> {
    const priority = { required: 0, stable: 1, canary: 2 } as const;
    return [...this.updateReleases.values()]
      .filter((release) => release.distributionId === distributionId && release.state === 'active')
      .sort((left, right) => priority[left.channel] - priority[right.channel]);
  }

  async consumeUpdatePolicyNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean> {
    const key = `${input.deploymentId}\0${input.nonce}`;
    if (this.updatePolicyNonces.has(key)) return false;
    this.updatePolicyNonces.add(key);
    return true;
  }

  async appendAuditEvent(input: AuditEventInput): Promise<void> {
    this.audits.push(input);
  }
}

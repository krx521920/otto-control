import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

function repositoryFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

describe('Edge Gateway production deployment', () => {
  it('orchestrates an independently healthy, restartable and bounded gateway', () => {
    const compose = repositoryFile('compose.production.yaml');
    const gateway = compose.slice(
      compose.indexOf('x-edge-gateway-common:'),
      compose.indexOf('\nservices:'),
    );
    expect(gateway).toContain('restart: unless-stopped');
    expect(gateway).toContain('stop_grace_period: 45s');
    expect(gateway).toContain('condition: service_healthy');
    expect(gateway).toContain("fetch('http://127.0.0.1:7791/readyz')");
    expect(gateway).toContain('read_only: true');
    expect(gateway).toContain('no-new-privileges:true');
    expect(gateway).toContain('max-size: ${OTTO_EDGE_LOG_MAX_SIZE:-20m}');
    expect(gateway).toContain('max-file: ${OTTO_EDGE_LOG_MAX_FILES:-5}');
    expect(compose).toContain('profiles: [edge]');
    expect(compose).toContain('profiles: [edge-rollout]');
    expect(compose).not.toContain('"7791:7791"');
  });

  it('uses TLS Redis and file-backed deployment/provider secrets', () => {
    const compose = repositoryFile('compose.production.yaml');
    const redis = compose.slice(
      compose.indexOf('  edge-redis:'),
      compose.indexOf('  edge-gateway:'),
    );
    expect(redis).toContain("'port 0'");
    expect(redis).toContain("'tls-port 6379'");
    expect(redis).toContain("'appendonly yes'");
    expect(redis).toContain('exec redis-server /tmp/redis.conf');
    expect(redis).not.toContain('--requirepass');
    expect(redis).toContain('edge_redis_tls_cert');
    expect(redis).toContain('edge_redis_tls_key');
    expect(redis).toContain('edge_redis_tls_ca');
    expect(compose).toContain('OTTO_EDGE_REDIS_PASSWORD_FILE: /run/secrets/edge_redis_password');
    expect(compose).toContain('OTTO_EDGE_RATE_LIMIT_KEY_FILE: /run/secrets/edge_rate_limit_key');
    expect(compose).toContain('OTTO_EDGE_LEASE_TOKEN_FILE: /run/secrets/edge_lease_token');
    expect(compose).toContain(':/run/otto-edge-provider-secrets:ro');
    expect(compose).not.toMatch(/OTTO_EDGE_REDIS_URL:.*@/u);
    const entrypoint = repositoryFile('deploy/edge-entrypoint.sh');
    expect(entrypoint).toContain('OTTO_EDGE_EXECUTION_RECEIPT_KEY_FILE');
    expect(entrypoint).toContain('/run/otto-edge-provider-secrets/*');
    expect(entrypoint).toContain('exec su-exec node "$@"');
    expect(repositoryFile('Dockerfile')).toContain(
      'deploy/edge-entrypoint.sh /usr/local/bin/otto-edge-entrypoint',
    );
  });

  it('terminates public TLS while keeping operations routes private', () => {
    const caddy = repositoryFile('deploy/Caddyfile');
    const edge = caddy.slice(caddy.indexOf('{$EDGE_DOMAIN}'));
    expect(edge).toContain('@edge_api path /v1/chat/completions /v1/responses');
    expect(edge).toContain('@edge_health path /healthz /readyz');
    expect(edge).toContain('reverse_proxy edge-gateway:7791');
    expect(edge).toContain('respond 404');
    expect(edge).not.toContain('/v1/operations/');
    expect(caddy).toContain('email {$ACME_EMAIL}');
    expect(caddy).toContain('acme_ca {$ACME_CA}');
  });

  it('provisions, validates, stages and rolls back immutable releases', () => {
    const bootstrap = repositoryFile('scripts/bootstrap-edge-production.mjs');
    expect(bootstrap).toContain("generateKeyPairSync('ed25519')");
    expect(bootstrap).toContain('Otto Edge Redis CA');
    expect(bootstrap).toContain("OTTO_EDGE_ENABLED=true");
    expect(bootstrap).toContain("flag: 'wx'");
    const preflight = repositoryFile('scripts/preflight-deployment.mjs');
    expect(preflight).toContain('validateEdgeGateway');
    expect(preflight).toContain('validateEdgeRedisIdentity');
    expect(preflight).toContain("'--profile', 'edge'");
    const upgrade = repositoryFile('deploy/upgrade-edge-gateway.sh');
    const rollback = repositoryFile('deploy/rollback-edge-gateway.sh');
    expect(upgrade).toContain('--confirm=UPGRADE_OTTO_EDGE');
    expect(upgrade).toContain('edge-gateway-canary');
    expect(upgrade).toContain('automatic rollback also failed');
    expect(upgrade).toContain('require_digest_image');
    expect(rollback).toContain('--confirm=ROLLBACK_OTTO_EDGE');
    expect(rollback).toContain('previous-image');
  });
});

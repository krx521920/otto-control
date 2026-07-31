import { describe, expect, it } from 'vitest';

import { loadControlConfig } from '../src/config.js';

describe('control configuration', () => {
  it('uses a loopback-only development default', () => {
    expect(loadControlConfig({})).toMatchObject({
      environment: 'development',
      host: '127.0.0.1',
      port: 7788,
      trustProxy: false,
    });
  });

  it('rejects invalid ports and ambiguous booleans', () => {
    expect(() => loadControlConfig({ CONTROL_PORT: '70000' })).toThrow(
      'CONTROL_PORT must be between 1 and 65535',
    );
    expect(() => loadControlConfig({ CONTROL_TRUST_PROXY: 'yes' })).toThrow(
      'CONTROL_TRUST_PROXY must be true or false',
    );
  });

  it('requires an HTTPS public URL in production', () => {
    expect(() => loadControlConfig({
      NODE_ENV: 'production',
      CONTROL_PUBLIC_BASE_URL: 'http://control.example.test',
    })).toThrow('CONTROL_PUBLIC_BASE_URL must use HTTPS in production');

    expect(loadControlConfig({
      NODE_ENV: 'production',
      CONTROL_PUBLIC_BASE_URL: 'https://control.example.test/',
    }).publicBaseUrl).toBe('https://control.example.test');
  });
});

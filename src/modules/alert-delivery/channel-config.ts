import { readFileSync, statSync } from 'node:fs';

import type { AlertSeverity } from '../../contracts/alert-delivery.js';

const MAX_CHANNEL_FILE_BYTES = 64 * 1024;
const MAX_CHANNELS = 20;
const CHANNEL_ID_PATTERN = /^[a-z][a-z0-9_-]{1,63}$/u;

export interface AlertChannelDefinition {
  id: string;
  name: string;
  url: string;
  secretFile: string;
  enabled: boolean;
  minimumSeverity: AlertSeverity;
}

export interface AlertChannelSummary {
  id: string;
  name: string;
  enabled: boolean;
  minimumSeverity: AlertSeverity;
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string, maximumLength: number): string {
  if (typeof value !== 'string' || !value.trim() || value.length > maximumLength) {
    throw new Error(`${label} must be a non-empty string up to ${maximumLength} characters`);
  }
  return value.trim();
}

function channelUrl(value: unknown, label: string): string {
  const normalized = requiredString(value, label, 2_048);
  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    throw new Error(`${label} must be an absolute HTTPS URL`);
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new Error(`${label} must use HTTPS without credentials or fragments`);
  }
  return url.toString();
}

function channelDefinition(value: unknown, index: number): AlertChannelDefinition {
  const record = objectValue(value, `alert channel ${index + 1}`);
  const id = requiredString(record.id, `alert channel ${index + 1} id`, 64);
  if (!CHANNEL_ID_PATTERN.test(id)) {
    throw new Error(`alert channel ${index + 1} id must match ${CHANNEL_ID_PATTERN}`);
  }
  const enabled = record.enabled === undefined ? true : record.enabled;
  if (typeof enabled !== 'boolean') {
    throw new Error(`alert channel ${id} enabled must be true or false`);
  }
  const minimumSeverity = record.minimumSeverity ?? 'warning';
  if (minimumSeverity !== 'warning' && minimumSeverity !== 'critical') {
    throw new Error(`alert channel ${id} minimumSeverity must be warning or critical`);
  }
  return {
    id,
    name: requiredString(record.name, `alert channel ${id} name`, 80),
    url: channelUrl(record.url, `alert channel ${id} URL`),
    secretFile: requiredString(record.secretFile, `alert channel ${id} secretFile`, 1_024),
    enabled,
    minimumSeverity,
  };
}

export function loadAlertChannelDefinitions(path: string): AlertChannelDefinition[] {
  let serialized: string;
  let metadata: ReturnType<typeof statSync>;
  try {
    metadata = statSync(path);
    serialized = readFileSync(path, 'utf8');
  } catch {
    throw new Error('alert channels file could not be read');
  }
  if (!metadata.isFile() || metadata.size < 2 || metadata.size > MAX_CHANNEL_FILE_BYTES) {
    throw new Error('alert channels file must be a regular JSON file up to 65536 bytes');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error('alert channels file must contain valid JSON');
  }
  const manifest = objectValue(parsed, 'alert channels manifest');
  if (manifest.version !== 1) throw new Error('alert channels manifest version must be 1');
  if (!Array.isArray(manifest.channels) || manifest.channels.length > MAX_CHANNELS) {
    throw new Error(`alert channels manifest must contain at most ${MAX_CHANNELS} channels`);
  }
  const channels = manifest.channels.map(channelDefinition);
  const ids = new Set<string>();
  for (const channel of channels) {
    if (ids.has(channel.id)) throw new Error(`duplicate alert channel id: ${channel.id}`);
    ids.add(channel.id);
  }
  return channels;
}

export function alertChannelSummary(channel: AlertChannelDefinition): AlertChannelSummary {
  return {
    id: channel.id,
    name: channel.name,
    enabled: channel.enabled,
    minimumSeverity: channel.minimumSeverity,
  };
}

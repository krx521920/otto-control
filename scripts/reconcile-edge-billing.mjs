import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const CURRENCY = /^[A-Z]{3}$/u;
const STATUSES = new Set(['settled', 'released', 'active', 'uncertain']);

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

function identifier(value, name) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function text(value, name, maximum = 160) {
  if (typeof value !== 'string' || !value.trim() || value.length > maximum) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function integer(value, name, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`${name} is invalid`);
  return value;
}

function instant(value, name) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function period(value, name) {
  const body = object(value, name);
  const from = instant(body.from, `${name}.from`);
  const to = instant(body.to, `${name}.to`);
  if (Date.parse(from) >= Date.parse(to)) throw new Error(`${name} is invalid`);
  return { from, to };
}

function currency(value, name) {
  if (typeof value !== 'string' || !CURRENCY.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function inPeriod(value, window, name) {
  const time = Date.parse(instant(value, name));
  if (time < Date.parse(window.from) || time >= Date.parse(window.to)) {
    throw new Error(`${name} is outside the statement period`);
  }
  return value;
}

function assertNoDuplicate(items, key, name) {
  const seen = new Set();
  for (const item of items) {
    const value = item[key];
    if (seen.has(value)) throw new Error(`${name} contains duplicate ${key}: ${value}`);
    seen.add(value);
  }
}

function ottoManifest(raw) {
  const body = object(raw, 'Otto statement');
  if (body.schemaVersion !== 1) throw new Error('Otto statement schemaVersion must be 1');
  const window = period(body.period, 'Otto statement period');
  const statementCurrency = currency(body.currency, 'Otto statement currency');
  const reservations = array(body.reservations, 'Otto reservations').map((value, index) => {
    const entry = object(value, `Otto reservation ${index}`);
    const status = entry.status;
    if (typeof status !== 'string' || !STATUSES.has(status)) {
      throw new Error(`Otto reservation ${index}.status is invalid`);
    }
    const providerBillingKey = entry.providerBillingKey === null
      ? null
      : identifier(entry.providerBillingKey, `Otto reservation ${index}.providerBillingKey`);
    const normalized = {
      requestId: identifier(entry.requestId, `Otto reservation ${index}.requestId`),
      reservationId: identifier(entry.reservationId, `Otto reservation ${index}.reservationId`),
      providerBillingKey,
      provider: identifier(entry.provider, `Otto reservation ${index}.provider`),
      model: text(entry.model, `Otto reservation ${index}.model`),
      reservedUnits: integer(entry.reservedUnits, `Otto reservation ${index}.reservedUnits`, 1),
      actualUnits: integer(entry.actualUnits, `Otto reservation ${index}.actualUnits`),
      chargedMicros: integer(entry.chargedMicros, `Otto reservation ${index}.chargedMicros`),
      status,
      occurredAt: inPeriod(entry.occurredAt, window, `Otto reservation ${index}.occurredAt`),
    };
    if (status === 'settled' && (!providerBillingKey || normalized.actualUnits < 1)) {
      throw new Error(`Otto reservation ${index} settled evidence is incomplete`);
    }
    if (status === 'released' && (providerBillingKey || normalized.actualUnits !== 0
      || normalized.chargedMicros !== 0)) {
      throw new Error(`Otto reservation ${index} released evidence is inconsistent`);
    }
    return normalized;
  });
  assertNoDuplicate(reservations, 'requestId', 'Otto statement');
  assertNoDuplicate(reservations, 'reservationId', 'Otto statement');
  const settled = reservations.filter((entry) => entry.status === 'settled');
  assertNoDuplicate(settled, 'providerBillingKey', 'Otto settled statement');
  return { schemaVersion: 1, period: window, currency: statementCurrency, reservations };
}

function providerManifest(raw) {
  const body = object(raw, 'provider statement');
  if (body.schemaVersion !== 1) throw new Error('provider statement schemaVersion must be 1');
  const window = period(body.period, 'provider statement period');
  const statementCurrency = currency(body.currency, 'provider statement currency');
  const entries = array(body.entries, 'provider entries').map((value, index) => {
    const entry = object(value, `provider entry ${index}`);
    return {
      providerBillingKey: identifier(
        entry.providerBillingKey,
        `provider entry ${index}.providerBillingKey`,
      ),
      provider: identifier(entry.provider, `provider entry ${index}.provider`),
      model: text(entry.model, `provider entry ${index}.model`),
      actualUnits: integer(entry.actualUnits, `provider entry ${index}.actualUnits`),
      chargedMicros: integer(entry.chargedMicros, `provider entry ${index}.chargedMicros`),
      occurredAt: inPeriod(entry.occurredAt, window, `provider entry ${index}.occurredAt`),
    };
  });
  assertNoDuplicate(entries, 'providerBillingKey', 'provider statement');
  return { schemaVersion: 1, period: window, currency: statementCurrency, entries };
}

function issue(type, providerBillingKey, detail) {
  return { type, providerBillingKey, detail };
}

export function reconcileEdgeBilling(ottoRaw, providerRaw, options = {}) {
  const otto = ottoManifest(ottoRaw);
  const provider = providerManifest(providerRaw);
  const amountToleranceMicros = integer(
    options.amountToleranceMicros ?? 0,
    'amountToleranceMicros',
  );
  const unitTolerance = integer(options.unitTolerance ?? 0, 'unitTolerance');
  if (otto.currency !== provider.currency) throw new Error('statement currencies do not match');
  if (otto.period.from !== provider.period.from || otto.period.to !== provider.period.to) {
    throw new Error('statement periods do not match exactly');
  }

  const issues = [];
  const providerByKey = new Map(provider.entries.map((entry) => [entry.providerBillingKey, entry]));
  const settled = otto.reservations.filter((entry) => entry.status === 'settled');
  const settledKeys = new Set(settled.map((entry) => entry.providerBillingKey));

  for (const reservation of otto.reservations) {
    if (reservation.status === 'active' || reservation.status === 'uncertain') {
      issues.push(issue(
        'unfinalized_reservation',
        reservation.providerBillingKey,
        `${reservation.requestId}:${reservation.status}`,
      ));
    }
    if (reservation.actualUnits > reservation.reservedUnits) {
      issues.push(issue(
        'reservation_overrun',
        reservation.providerBillingKey,
        `${reservation.actualUnits - reservation.reservedUnits} units above reservation`,
      ));
    }
  }

  for (const local of settled) {
    const key = local.providerBillingKey;
    const external = providerByKey.get(key);
    if (!external) {
      issues.push(issue('missing_provider_charge', key, local.requestId));
      continue;
    }
    if (local.provider !== external.provider || local.model !== external.model) {
      issues.push(issue('routing_mismatch', key, `${local.provider}/${local.model}`));
    }
    const unitDelta = local.actualUnits - external.actualUnits;
    if (Math.abs(unitDelta) > unitTolerance) {
      issues.push(issue('unit_mismatch', key, String(unitDelta)));
    }
    const amountDeltaMicros = local.chargedMicros - external.chargedMicros;
    if (Math.abs(amountDeltaMicros) > amountToleranceMicros) {
      issues.push(issue('amount_mismatch', key, String(amountDeltaMicros)));
    }
  }
  for (const external of provider.entries) {
    if (!settledKeys.has(external.providerBillingKey)) {
      issues.push(issue('missing_otto_charge', external.providerBillingKey, external.provider));
    }
  }

  const sum = (items, field) => items.reduce((total, entry) => total + entry[field], 0);
  const report = {
    schemaVersion: 1,
    result: issues.length === 0 ? 'passed' : 'failed',
    generatedAt: new Date(options.now?.() ?? Date.now()).toISOString(),
    period: otto.period,
    currency: otto.currency,
    thresholds: { amountToleranceMicros, unitTolerance },
    reservations: {
      total: otto.reservations.length,
      settled: settled.length,
      released: otto.reservations.filter((entry) => entry.status === 'released').length,
      active: otto.reservations.filter((entry) => entry.status === 'active').length,
      uncertain: otto.reservations.filter((entry) => entry.status === 'uncertain').length,
      overrun: otto.reservations.filter((entry) => entry.actualUnits > entry.reservedUnits).length,
    },
    otto: {
      billableEntries: settled.length,
      actualUnits: sum(settled, 'actualUnits'),
      chargedMicros: sum(settled, 'chargedMicros'),
    },
    provider: {
      billableEntries: provider.entries.length,
      actualUnits: sum(provider.entries, 'actualUnits'),
      chargedMicros: sum(provider.entries, 'chargedMicros'),
    },
    issues,
  };
  return report;
}

function argumentsMap(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const entry = argv[index];
    if (!entry?.startsWith('--')) throw new Error(`unexpected argument: ${entry}`);
    const [name, inlineValue] = entry.slice(2).split('=', 2);
    const value = inlineValue ?? argv[index + 1];
    if (!name || value === undefined || value.startsWith('--')) {
      throw new Error(`--${name} requires a value`);
    }
    values.set(name, value);
    if (inlineValue === undefined) index += 1;
  }
  return values;
}

function required(values, name) {
  const value = values.get(name)?.trim();
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

function optionalInteger(values, name) {
  const value = values.get(name);
  if (value === undefined) return 0;
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new Error(`--${name} is invalid`);
  return Number(value);
}

function runCli(argv) {
  const values = argumentsMap(argv);
  const otto = JSON.parse(readFileSync(resolve(required(values, 'otto')), 'utf8'));
  const provider = JSON.parse(readFileSync(resolve(required(values, 'provider')), 'utf8'));
  const report = reconcileEdgeBilling(otto, provider, {
    amountToleranceMicros: optionalInteger(values, 'amount-tolerance-micros'),
    unitTolerance: optionalInteger(values, 'unit-tolerance'),
  });
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  const output = values.get('output')?.trim();
  if (output) writeFileSync(resolve(output), serialized, { encoding: 'utf8', flag: 'wx' });
  else process.stdout.write(serialized);
  if (report.result !== 'passed') process.exitCode = 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

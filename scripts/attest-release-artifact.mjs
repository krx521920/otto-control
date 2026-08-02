import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, canonicalize(item)]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function parseArgs(argv) {
  const result = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key?.startsWith('--')) throw new Error(`unexpected argument: ${key}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${key} requires a value`);
    result.set(key.slice(2), value);
    index += 1;
  }
  return result;
}

function required(args, name) {
  const value = args.get(name)?.trim();
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function command(file, args) {
  return execFileSync(file, args, {
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function powershellAuthenticode(file) {
  if (process.platform !== 'win32') throw new Error('Authenticode attestation requires Windows');
  const script = [
    "$ErrorActionPreference='Stop'",
    `$s=Get-AuthenticodeSignature -LiteralPath '${file.replaceAll("'", "''")}'`,
    'if ($s.Status.ToString() -ne "Valid") { throw "Authenticode status: $($s.Status)" }',
    'if ($null -eq $s.SignerCertificate) { throw "Signer certificate missing" }',
    'if ($null -eq $s.TimeStamperCertificate) { throw "RFC3161/AuthentiCode timestamp missing" }',
    '[pscustomobject]@{status=$s.Status.ToString();subject=$s.SignerCertificate.Subject;certificate=[Convert]::ToBase64String($s.SignerCertificate.RawData);timestampSubject=$s.TimeStamperCertificate.Subject}|ConvertTo-Json -Compress',
  ].join(';');
  const raw = command('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);
  const result = JSON.parse(raw);
  return {
    system: 'authenticode',
    signerIdentity: String(result.subject),
    certificateSha256: sha256(Buffer.from(String(result.certificate), 'base64')),
    timestamped: true,
    notarized: false,
    verifier: 'powershell:Get-AuthenticodeSignature',
    transcript: result,
  };
}

function macDeveloperId(file) {
  if (process.platform !== 'darwin') throw new Error('Developer ID attestation requires macOS');
  command('codesign', ['--verify', '--deep', '--strict', '--verbose=2', file]);
  command('spctl', ['--assess', '--type', 'open', '--verbose=4', file]);
  const stapler = command('xcrun', ['stapler', 'validate', file]);
  let detail = '';
  try {
    detail = execFileSync('codesign', ['-dv', '--verbose=4', file], {
      encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    detail = `${error.stdout ?? ''}\n${error.stderr ?? ''}`;
    if (!detail.includes('Authority=')) throw error;
  }
  const identity = detail.match(/^Authority=(.+)$/mu)?.[1]?.trim();
  const teamId = detail.match(/^TeamIdentifier=(.+)$/mu)?.[1]?.trim();
  const timestamp = detail.match(/^Timestamp=(.+)$/mu)?.[1]?.trim();
  if (!identity || !teamId || !timestamp) throw new Error('Developer ID identity, team, or timestamp missing');
  const temporary = mkdtempSync(join(tmpdir(), 'otto-codesign-'));
  try {
    const prefix = join(temporary, 'certificate');
    command('codesign', ['-d', `--extract-certificates=${prefix}`, file]);
    const certificate = readFileSync(`${prefix}0`);
    return {
      system: 'apple_developer_id',
      signerIdentity: `${identity}; TeamIdentifier=${teamId}`,
      certificateSha256: sha256(certificate),
      timestamped: true,
      notarized: /validate|ticket|worked/iu.test(stapler),
      verifier: 'codesign+spctl+stapler',
      transcript: { identity, teamId, timestamp, stapler },
    };
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function linuxDetachedSignature(file, signatureFile, publicKeyFile) {
  if (!signatureFile || !publicKeyFile) {
    throw new Error('Linux attestation requires --linux-signature and --linux-public-key');
  }
  const publicKey = createPublicKey(readFileSync(resolve(publicKeyFile), 'utf8'));
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Linux package key must be Ed25519');
  const signatureRaw = readFileSync(resolve(signatureFile));
  const signature = /^[A-Za-z0-9_-]+\s*$/u.test(signatureRaw.toString('utf8'))
    ? Buffer.from(signatureRaw.toString('utf8').trim(), 'base64url')
    : signatureRaw;
  if (!verify(null, readFileSync(file), publicKey, signature)) {
    throw new Error('Linux package detached signature is invalid');
  }
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  return {
    system: 'linux_package',
    signerIdentity: `ed25519:${sha256(publicDer).slice(0, 16)}`,
    certificateSha256: sha256(publicDer),
    timestamped: false,
    notarized: false,
    verifier: 'node:crypto.verify',
    transcript: { signatureSha256: sha256(signature), keySha256: sha256(publicDer) },
  };
}

export function createAttestation(input) {
  const file = resolve(input.file);
  const bytes = readFileSync(file);
  const fileSha256 = sha256(bytes);
  const sizeBytes = statSync(file).size;
  let verification;
  if (input.kind === 'windows_installer') verification = powershellAuthenticode(file);
  else if (input.kind === 'macos_dmg') verification = macDeveloperId(file);
  else if (input.kind === 'linux_archive' || input.kind === 'enterprise_server') {
    verification = linuxDetachedSignature(file, input.linuxSignature, input.linuxPublicKey);
  } else {
    throw new Error('only installable release artifacts require code-signing attestation');
  }
  const verifiedAtMs = Date.now();
  const evidence = {
    version: 1,
    releaseId: input.releaseId,
    releaseVersion: input.releaseVersion,
    sourceCommit: input.sourceCommit,
    kind: input.kind,
    platform: input.platform,
    sha256: fileSha256,
    sizeBytes,
    system: verification.system,
    status: 'valid',
    signerIdentity: verification.signerIdentity,
    certificateSha256: verification.certificateSha256,
    timestamped: verification.timestamped,
    notarized: verification.notarized,
    verifier: `${verification.verifier}; ${process.platform}; ${process.version}`,
    evidenceSha256: sha256(Buffer.from(canonicalJson({
      file: basename(file),
      fileSha256,
      sizeBytes,
      verification: verification.transcript,
    }))),
    verifiedAtMs,
  };
  const privateKey = createPrivateKey(readFileSync(resolve(input.attestationPrivateKeyFile), 'utf8'));
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('attestation key must be Ed25519');
  return {
    evidence,
    attestationKeyId: input.attestationKeyId,
    signature: `ed25519:${sign(null, Buffer.from(canonicalJson(evidence)), privateKey).toString('base64url')}`,
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = createAttestation({
    file: required(args, 'file'),
    releaseId: required(args, 'release-id'),
    releaseVersion: required(args, 'release-version'),
    sourceCommit: required(args, 'source-commit'),
    kind: required(args, 'kind'),
    platform: required(args, 'platform'),
    attestationKeyId: required(args, 'attestation-key-id'),
    attestationPrivateKeyFile: required(args, 'attestation-private-key-file'),
    linuxSignature: args.get('linux-signature'),
    linuxPublicKey: args.get('linux-public-key'),
  });
  const serialized = `${JSON.stringify(result, null, 2)}\n`;
  const output = args.get('output');
  if (output) writeFileSync(resolve(output), serialized, { mode: 0o600 });
  else process.stdout.write(serialized);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

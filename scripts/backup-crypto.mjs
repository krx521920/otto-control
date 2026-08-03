import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as deriveKey,
} from 'node:crypto';
import { spawn } from 'node:child_process';
import {
  appendFileSync,
  closeSync,
  createReadStream,
  createWriteStream,
  openSync,
  readFileSync,
  readSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Writable } from 'node:stream';
import { promisify } from 'node:util';

const MAGIC = Buffer.from('OTTOCBK1', 'ascii');
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = MAGIC.length + SALT_BYTES + IV_BYTES;
const scrypt = promisify(deriveKey);

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function requiredOption(name) {
  const value = option(name);
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function keyFromFile(path, salt) {
  const secret = readFileSync(path, 'utf8').trim();
  if (Buffer.byteLength(secret, 'utf8') < 32) {
    throw new Error('backup encryption key must contain at least 32 bytes');
  }
  return Buffer.from(await scrypt(secret, salt, 32));
}

async function encrypt(input, output, keyFile) {
  if (output === '-') throw new Error('encrypted output must be a file');
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await keyFromFile(keyFile, salt);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const header = Buffer.concat([MAGIC, salt, iv]);

  try {
    writeFileSync(output, header, { flag: 'wx', mode: 0o600 });
    await pipeline(createReadStream(input), cipher, createWriteStream(output, { flags: 'a' }));
    appendFileSync(output, cipher.getAuthTag());
  } catch (error) {
    rmSync(output, { force: true });
    throw error;
  }
}

async function decryptionStreams(input, keyFile) {
  const size = statSync(input).size;
  if (size <= HEADER_BYTES + TAG_BYTES) throw new Error('encrypted backup is truncated');

  const descriptor = openSync(input, 'r');
  const header = Buffer.alloc(HEADER_BYTES);
  const tag = Buffer.alloc(TAG_BYTES);
  try {
    if (readSync(descriptor, header, 0, header.length, 0) !== header.length) {
      throw new Error('encrypted backup header is truncated');
    }
    if (readSync(descriptor, tag, 0, tag.length, size - tag.length) !== tag.length) {
      throw new Error('encrypted backup authentication tag is truncated');
    }
  } finally {
    closeSync(descriptor);
  }

  if (!header.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('encrypted backup format is invalid');
  }
  const salt = header.subarray(MAGIC.length, MAGIC.length + SALT_BYTES);
  const iv = header.subarray(MAGIC.length + SALT_BYTES);
  const key = await keyFromFile(keyFile, salt);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const source = createReadStream(input, {
    start: HEADER_BYTES,
    end: size - TAG_BYTES - 1,
  });

  return { source, decipher };
}

async function authenticateEncryptedBackup(input, keyFile) {
  const { source, decipher } = await decryptionStreams(input, keyFile);
  const discard = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  await pipeline(source, decipher, discard);
}

async function decrypt(input, output, keyFile) {
  const { source, decipher } = await decryptionStreams(input, keyFile);

  if (output === '-') {
    await pipeline(source, decipher, process.stdout);
    return;
  }
  try {
    await pipeline(source, decipher, createWriteStream(output, { flags: 'wx', mode: 0o600 }));
  } catch (error) {
    rmSync(output, { force: true });
    throw error;
  }
}

function commandArguments() {
  const separator = process.argv.indexOf('--');
  if (separator < 0 || !process.argv[separator + 1]) {
    throw new Error('decrypt-run requires -- COMMAND [ARGUMENTS...]');
  }
  return {
    command: process.argv[separator + 1],
    args: process.argv.slice(separator + 2),
  };
}

function waitForCommand(child) {
  return new Promise((resolveCommand, rejectCommand) => {
    child.once('error', rejectCommand);
    child.once('exit', (code, signal) => {
      if (code === 0) {
        resolveCommand();
        return;
      }
      rejectCommand(new Error(
        signal
          ? `decrypted stream command terminated by ${signal}`
          : `decrypted stream command exited with code ${code ?? 'unknown'}`,
      ));
    });
  });
}

async function decryptRun(input, keyFile) {
  await authenticateEncryptedBackup(input, keyFile);
  const { command, args } = commandArguments();
  const stdoutMode = option('--command-stdout') || 'inherit';
  if (stdoutMode !== 'inherit' && stdoutMode !== 'ignore') {
    throw new Error('--command-stdout must be inherit or ignore');
  }
  const child = spawn(command, args, {
    stdio: ['pipe', stdoutMode, 'inherit'],
    windowsHide: true,
  });
  const commandResult = waitForCommand(child);
  commandResult.catch(() => undefined);
  try {
    const { source, decipher } = await decryptionStreams(input, keyFile);
    await pipeline(source, decipher, child.stdin);
    await commandResult;
  } catch (error) {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    await commandResult.catch(() => undefined);
    throw error;
  }
}

async function main() {
  const action = process.argv[2];
  const input = requiredOption('--input');
  const keyFile = requiredOption('--key-file');
  if (action === 'decrypt-run') return decryptRun(input, keyFile);
  const output = requiredOption('--output');
  if (action === 'encrypt') return encrypt(input, output, keyFile);
  if (action === 'decrypt') return decrypt(input, output, keyFile);
  throw new Error('action must be encrypt, decrypt, or decrypt-run');
}

try {
  await main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

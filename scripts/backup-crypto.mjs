import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as deriveKey,
} from 'node:crypto';
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

async function decrypt(input, output, keyFile) {
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

async function main() {
  const action = process.argv[2];
  const input = requiredOption('--input');
  const output = requiredOption('--output');
  const keyFile = requiredOption('--key-file');
  if (action === 'encrypt') return encrypt(input, output, keyFile);
  if (action === 'decrypt') return decrypt(input, output, keyFile);
  throw new Error('action must be encrypt or decrypt');
}

try {
  await main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

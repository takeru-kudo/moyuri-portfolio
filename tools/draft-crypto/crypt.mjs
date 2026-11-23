// Encrypts or decrypts one file with AES-256-GCM. Node.js built-ins only.
//
// Usage: node tools/draft-crypto/crypt.mjs encrypt|decrypt --in <file> --out <file>
// Env:   DRAFT_ARTIFACT_KEY (base64 of 32 bytes)
//
// File format: MAGIC (5 bytes: "MKDC" + version 0x01) | IV (12) | ciphertext | tag (16).
// MAGIC is bound as additional authenticated data.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { open, rename, stat, unlink } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

export const MAGIC = Buffer.from([0x4d, 0x4b, 0x44, 0x43, 0x01]);
export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;
export const HEADER_LENGTH = MAGIC.length + IV_LENGTH;
export const MIN_LENGTH = HEADER_LENGTH + TAG_LENGTH;

const ALGORITHM = "aes-256-gcm";
const KEY_RE = /^[A-Za-z0-9+/]{43}=$/;

/** Error whose message is fixed text that is safe to print. */
export class CryptError extends Error {
  constructor(message) {
    super(message);
    this.name = "CryptError";
  }
}

/** Decodes DRAFT_ARTIFACT_KEY into a 32-byte key, or throws without echoing it. */
export function readKey(env) {
  const raw = (env.DRAFT_ARTIFACT_KEY ?? "").trim();
  if (!KEY_RE.test(raw)) {
    throw new CryptError("DRAFT_ARTIFACT_KEY is missing or not base64 of 32 bytes");
  }
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new CryptError("DRAFT_ARTIFACT_KEY is missing or not base64 of 32 bytes");
  }
  return key;
}

/** Parses CLI arguments into { command, input, output }, or throws CryptError. */
export function parseCli(argv) {
  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({
      args: argv,
      options: { in: { type: "string" }, out: { type: "string" } },
      strict: true,
      allowPositionals: true,
    }));
  } catch {
    throw new CryptError("usage: crypt.mjs encrypt|decrypt --in <file> --out <file>");
  }
  const [command, ...rest] = positionals;
  if ((command !== "encrypt" && command !== "decrypt") || rest.length > 0) {
    throw new CryptError("usage: crypt.mjs encrypt|decrypt --in <file> --out <file>");
  }
  if (!values.in || !values.out) {
    throw new CryptError("--in and --out are required");
  }
  if (path.resolve(values.in) === path.resolve(values.out)) {
    throw new CryptError("--in and --out must differ");
  }
  return { command, input: values.in, output: values.out };
}

function tempPathFor(output) {
  const dir = path.dirname(path.resolve(output));
  return path.join(dir, `.${path.basename(output)}.${randomBytes(8).toString("hex")}.tmp`);
}

/**
 * Runs write(tempPath) and renames the temp file to output on success.
 * The temp file is deleted on any error.
 */
async function writeAtomically(output, write) {
  const temp = tempPathFor(output);
  try {
    await write(temp);
    await rename(temp, output);
  } catch (err) {
    await unlink(temp).catch(() => {});
    throw err;
  }
}

async function assertRegularFile(input) {
  let info;
  try {
    info = await stat(input);
  } catch {
    throw new CryptError("input file cannot be read");
  }
  if (!info.isFile()) throw new CryptError("input is not a regular file");
  return info;
}

/** Encrypts input to output. */
export async function encryptFile(input, output, key) {
  await assertRegularFile(input);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
  cipher.setAAD(MAGIC);
  await writeAtomically(output, async (temp) => {
    const out = createWriteStream(temp, { flags: "wx", mode: 0o600 });
    out.write(Buffer.concat([MAGIC, iv]));
    await pipeline(createReadStream(input), cipher, out, { end: false });
    await new Promise((resolve, reject) => {
      out.on("error", reject);
      out.end(cipher.getAuthTag(), resolve);
    });
  });
}

async function readExact(fd, length, position) {
  const buf = Buffer.alloc(length);
  const { bytesRead } = await fd.read(buf, 0, length, position);
  if (bytesRead !== length) throw new CryptError("encrypted file is truncated");
  return buf;
}

/** Decrypts input to output; output appears only if authentication succeeds. */
export async function decryptFile(input, output, key) {
  const info = await assertRegularFile(input);
  if (info.size < MIN_LENGTH) throw new CryptError("encrypted file is truncated");
  const fd = await open(input, "r");
  let header;
  let tag;
  try {
    header = await readExact(fd, HEADER_LENGTH, 0);
    tag = await readExact(fd, TAG_LENGTH, info.size - TAG_LENGTH);
  } finally {
    await fd.close();
  }
  if (!header.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new CryptError("not an encrypted draft file (bad magic or version)");
  }
  const iv = header.subarray(MAGIC.length);
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
  decipher.setAAD(MAGIC);
  decipher.setAuthTag(tag);
  const end = info.size - TAG_LENGTH - 1;
  await writeAtomically(output, async (temp) => {
    const source =
      end >= HEADER_LENGTH
        ? createReadStream(input, { start: HEADER_LENGTH, end })
        : (async function* () {})();
    try {
      await pipeline(source, decipher, createWriteStream(temp, { flags: "wx", mode: 0o600 }));
    } catch (err) {
      if (err instanceof Error && /unable to authenticate|auth/i.test(err.message)) {
        throw new CryptError("authentication failed (wrong key or tampered file)");
      }
      throw err;
    }
  });
}

function describeError(err) {
  const name = typeof err?.name === "string" ? err.name : "Error";
  const code = typeof err?.code === "string" ? err.code : "";
  const safe = (v) => v.replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 40);
  return code ? `${safe(name)} (${safe(code)})` : safe(name);
}

async function main() {
  try {
    const { command, input, output } = parseCli(process.argv.slice(2));
    const key = readKey(process.env);
    if (command === "encrypt") await encryptFile(input, output, key);
    else await decryptFile(input, output, key);
    process.stdout.write(`draft-crypto: ${command} ok\n`);
    return 0;
  } catch (err) {
    const message = err instanceof CryptError ? err.message : `unexpected error (${describeError(err)})`;
    process.stderr.write(`draft-crypto: error: ${message}\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdtemp, readdir, readFile, rm, stat, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  CryptError,
  HEADER_LENGTH,
  MAGIC,
  MIN_LENGTH,
  TAG_LENGTH,
  decryptFile,
  encryptFile,
  parseCli,
  readKey,
} from "./crypt.mjs";

const SCRIPT = fileURLToPath(new URL("./crypt.mjs", import.meta.url));
const KEY = randomBytes(32);
const KEY_B64 = KEY.toString("base64");
const OTHER_KEY = randomBytes(32);
const PLAINTEXT_SENTINEL = "PLAINTEXT_SENTINEL_draft_title";

let dir;
let n = 0;
before(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "draft-crypto-test-"));
});
after(async () => {
  await rm(dir, { recursive: true, force: true });
});

function p(name) {
  n += 1;
  return path.join(dir, `${n}-${name}`);
}

async function caseDir() {
  return mkdtemp(path.join(dir, "case-"));
}

async function encryptTo(content) {
  const d = await caseDir();
  const plain = path.join(d, "plain");
  const enc = path.join(d, "enc");
  await writeFile(plain, content);
  await encryptFile(plain, enc, KEY);
  return { d, plain, enc };
}

async function onlyFiles(d) {
  return (await readdir(d)).sort();
}

describe("readKey", () => {
  it("accepts base64 of 32 bytes, with surrounding whitespace", () => {
    assert.deepEqual(readKey({ DRAFT_ARTIFACT_KEY: KEY_B64 }), KEY);
    assert.deepEqual(readKey({ DRAFT_ARTIFACT_KEY: `${KEY_B64}\n` }), KEY);
  });
  it("rejects anything else without echoing it", () => {
    const bad = [
      undefined,
      "",
      randomBytes(31).toString("base64"),
      randomBytes(33).toString("base64"),
      KEY.toString("base64url"),
      KEY.toString("hex"),
      `${KEY_B64.slice(0, 43)}!`,
    ];
    for (const value of bad) {
      try {
        readKey({ DRAFT_ARTIFACT_KEY: value });
        assert.fail("expected throw");
      } catch (err) {
        assert.ok(err instanceof CryptError);
        if (value) assert.ok(!err.message.includes(value));
      }
    }
  });
});

describe("parseCli", () => {
  it("parses commands", () => {
    assert.deepEqual(parseCli(["encrypt", "--in", "a", "--out", "b"]), {
      command: "encrypt",
      input: "a",
      output: "b",
    });
    assert.equal(parseCli(["--in=a", "--out=b", "decrypt"]).command, "decrypt");
  });
  it("rejects bad input", () => {
    assert.throws(() => parseCli(["sign", "--in", "a", "--out", "b"]), CryptError);
    assert.throws(() => parseCli(["encrypt", "--in", "a"]), CryptError);
    assert.throws(() => parseCli(["encrypt", "extra", "--in", "a", "--out", "b"]), CryptError);
    assert.throws(() => parseCli(["encrypt", "--in", "a", "--out", "./a"]), /must differ/);
    assert.throws(() => parseCli(["encrypt", "--key", "x"]), CryptError);
  });
});

describe("round trip", () => {
  for (const [label, size] of [
    ["empty", 0],
    ["small", 37],
    ["multi-chunk", 3 * 1024 * 1024 + 5],
  ]) {
    it(`restores ${label} content`, async () => {
      const content = randomBytes(size);
      const { d, enc } = await encryptTo(content);
      const info = await stat(enc);
      assert.equal(info.size, size + MIN_LENGTH);
      const out = path.join(d, "dec");
      await decryptFile(enc, out, KEY);
      assert.ok((await readFile(out)).equals(content));
      assert.deepEqual(await onlyFiles(d), ["dec", "enc", "plain"]);
    });
  }

  it("writes the header, a fresh IV per file, and no plaintext", async () => {
    const content = Buffer.from(PLAINTEXT_SENTINEL.repeat(10));
    const a = await encryptTo(content);
    const b = await encryptTo(content);
    const ea = await readFile(a.enc);
    const eb = await readFile(b.enc);
    assert.ok(ea.subarray(0, MAGIC.length).equals(MAGIC));
    assert.ok(!ea.subarray(MAGIC.length, HEADER_LENGTH).equals(eb.subarray(MAGIC.length, HEADER_LENGTH)));
    assert.ok(!ea.includes(PLAINTEXT_SENTINEL));
  });

  it("streams a large file", async () => {
    const d = await caseDir();
    const plain = path.join(d, "plain");
    const chunk = randomBytes(1024 * 1024);
    const ws = createWriteStream(plain);
    for (let i = 0; i < 64; i++) ws.write(chunk);
    await new Promise((resolve) => ws.end(resolve));
    await encryptFile(plain, path.join(d, "enc"), KEY);
    await decryptFile(path.join(d, "enc"), path.join(d, "dec"), KEY);
    assert.equal((await stat(path.join(d, "dec"))).size, 64 * 1024 * 1024);
    const dec = await readFile(path.join(d, "dec"));
    assert.ok(dec.subarray(63 * 1024 * 1024).equals(chunk));
  });
});

describe("decrypt failures leave no plaintext", () => {
  async function expectFailure(enc, d, key, re) {
    const out = path.join(d, "dec");
    await assert.rejects(decryptFile(enc, out, key), (err) => {
      assert.ok(err instanceof CryptError, String(err));
      assert.match(err.message, re);
      return true;
    });
    const files = await onlyFiles(d);
    assert.ok(!files.includes("dec"), files.join(","));
    assert.ok(!files.some((f) => f.endsWith(".tmp")), files.join(","));
  }

  it("wrong key", async () => {
    const { d, enc } = await encryptTo(Buffer.from(PLAINTEXT_SENTINEL));
    await expectFailure(enc, d, OTHER_KEY, /authentication failed/);
  });

  it("tampered ciphertext, IV, tag, or version", async () => {
    const content = randomBytes(200 * 1024);
    for (const offset of [HEADER_LENGTH + 5, MAGIC.length + 1, -1, 4]) {
      const { d, enc } = await encryptTo(content);
      const buf = await readFile(enc);
      const i = offset < 0 ? buf.length + offset : offset;
      buf[i] ^= 0x01;
      await writeFile(enc, buf);
      await expectFailure(enc, d, KEY, offset === 4 ? /bad magic/ : /authentication failed/);
    }
  });

  it("bad magic", async () => {
    const { d, enc } = await encryptTo(Buffer.from("x"));
    const buf = await readFile(enc);
    buf.write("XXXX", 0);
    await writeFile(enc, buf);
    await expectFailure(enc, d, KEY, /bad magic/);
  });

  it("truncated file", async () => {
    const content = randomBytes(1000);
    for (const size of [0, MIN_LENGTH - 1, MIN_LENGTH + 500]) {
      const { d, enc } = await encryptTo(content);
      await truncate(enc, size);
      await expectFailure(enc, d, KEY, size < MIN_LENGTH ? /truncated/ : /authentication failed/);
    }
  });

  it("appended bytes", async () => {
    const { d, enc } = await encryptTo(randomBytes(100));
    const buf = await readFile(enc);
    await writeFile(enc, Buffer.concat([buf, Buffer.alloc(TAG_LENGTH)]));
    await expectFailure(enc, d, KEY, /authentication failed/);
  });

  it("keeps an existing output file untouched on failure", async () => {
    const { d, enc } = await encryptTo(randomBytes(100));
    const out = path.join(d, "dec");
    await writeFile(out, "previous");
    await assert.rejects(decryptFile(enc, out, OTHER_KEY), CryptError);
    assert.equal(await readFile(out, "utf8"), "previous");
    assert.ok(!(await onlyFiles(d)).some((f) => f.endsWith(".tmp")));
  });
});

describe("CLI", () => {
  function cli(args, env = { DRAFT_ARTIFACT_KEY: KEY_B64 }) {
    return spawnSync(process.execPath, [SCRIPT, ...args], {
      env: { PATH: process.env.PATH, ...env },
      encoding: "utf8",
      timeout: 30_000,
    });
  }

  it("round-trips and prints no content", async () => {
    const d = await caseDir();
    const plain = path.join(d, "plain.json");
    await writeFile(plain, JSON.stringify({ title: PLAINTEXT_SENTINEL }));
    const e = cli(["encrypt", "--in", plain, "--out", path.join(d, "x.enc")]);
    assert.equal(e.status, 0, e.stderr);
    assert.equal(e.stdout, "draft-crypto: encrypt ok\n");
    const r = cli(["decrypt", "--in", path.join(d, "x.enc"), "--out", path.join(d, "back.json")]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(await readFile(path.join(d, "back.json"), "utf8"), JSON.stringify({ title: PLAINTEXT_SENTINEL }));
    for (const out of [e.stdout, e.stderr, r.stdout, r.stderr]) {
      assert.ok(!out.includes(PLAINTEXT_SENTINEL));
      assert.ok(!out.includes(KEY_B64));
    }
  });

  it("exits 1 on a bad key without printing it", async () => {
    const d = await caseDir();
    const plain = path.join(d, "plain");
    await writeFile(plain, "x");
    const badKey = randomBytes(16).toString("base64");
    const r = cli(["encrypt", "--in", plain, "--out", path.join(d, "enc")], { DRAFT_ARTIFACT_KEY: badKey });
    assert.equal(r.status, 1);
    assert.equal(r.stderr, "draft-crypto: error: DRAFT_ARTIFACT_KEY is missing or not base64 of 32 bytes\n");
    assert.ok(!r.stderr.includes(badKey));
    assert.deepEqual(await onlyFiles(d), ["plain"]);
  });

  it("exits 1 on wrong key and leaves no output", async () => {
    const { d, enc } = await encryptTo(Buffer.from(PLAINTEXT_SENTINEL));
    const r = cli(["decrypt", "--in", enc, "--out", path.join(d, "dec")], {
      DRAFT_ARTIFACT_KEY: OTHER_KEY.toString("base64"),
    });
    assert.equal(r.status, 1);
    assert.equal(r.stderr, "draft-crypto: error: authentication failed (wrong key or tampered file)\n");
    assert.deepEqual(await onlyFiles(d), ["enc", "plain"]);
  });

  it("exits 1 on a missing input file", () => {
    const r = cli(["encrypt", "--in", p("missing"), "--out", p("out")]);
    assert.equal(r.status, 1);
    assert.equal(r.stderr, "draft-crypto: error: input file cannot be read\n");
  });
});

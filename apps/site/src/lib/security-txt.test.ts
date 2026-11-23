import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const FILE = new URL("../../public/.well-known/security.txt", import.meta.url);

async function fields(): Promise<Map<string, string[]>> {
  const text = await readFile(FILE, "utf8");
  const map = new Map<string, string[]>();
  for (const line of text.split("\n")) {
    if (line === "" || line.startsWith("#")) continue;
    const match = /^([A-Za-z-]+): (.+)$/.exec(line);
    assert.ok(match, `malformed line: ${line}`);
    const [, name, value] = match;
    map.set(name!, [...(map.get(name!) ?? []), value!]);
  }
  return map;
}

describe("security.txt", () => {
  it("has the expected fields", async () => {
    const map = await fields();
    assert.deepEqual(map.get("Contact"), [
      "https://github.com/takeru-kudo/moyuri-portfolio/security/advisories/new",
    ]);
    assert.deepEqual(map.get("Preferred-Languages"), ["ja, en"]);
    assert.deepEqual(map.get("Canonical"), ["https://moyuri-kudo.com/.well-known/security.txt"]);
    assert.deepEqual([...map.keys()].sort(), ["Canonical", "Contact", "Expires", "Preferred-Languages"]);
  });

  it("has exactly one Expires in ISO 8601 UTC form", async () => {
    const expires = (await fields()).get("Expires");
    assert.equal(expires?.length, 1);
    assert.match(expires![0]!, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    assert.equal(new Date(expires![0]!).toISOString(), expires![0]);
  });

  it("contains no email address", async () => {
    assert.equal((await readFile(FILE, "utf8")).includes("@"), false);
  });
});

// End of life of the Node.js major version pinned in .mise.toml.

import { NODE_EOL_API, NODE_EOL_MIN_DAYS, NODE_VERSION_FILE } from "../config.mjs";
import { daysUntil, describeError, fail, getJson, parseIsoDay, pass } from "../lib.mjs";

/** Returns the Node.js major version from .mise.toml text, or null. */
export function nodeMajor(miseToml) {
  const match = /^node\s*=\s*"(\d+)(?:\.\d+){0,2}"\s*$/m.exec(miseToml);
  return match ? match[1] : null;
}

export async function run(ctx) {
  try {
    const major = nodeMajor(await ctx.readFile(NODE_VERSION_FILE));
    if (major === null) return [fail("node-eol", `node version not found in ${NODE_VERSION_FILE}`)];
    const { body } = await getJson(ctx, `${NODE_EOL_API}/${major}`, { headers: { accept: "application/json" } });
    const eol = parseIsoDay(body?.result?.eolFrom);
    if (eol === null) return [fail("node-eol", `no end-of-life date for Node.js ${major}`)];
    const days = daysUntil(eol, ctx.now());
    const detail = `Node.js ${major}: ${days} day(s) left`;
    return [days < NODE_EOL_MIN_DAYS ? fail("node-eol", detail) : pass("node-eol", detail)];
  } catch (err) {
    return [fail("node-eol", describeError(err))];
  }
}

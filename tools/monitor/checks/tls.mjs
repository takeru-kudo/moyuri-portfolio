// TLS certificate expiry per host.

import tls from "node:tls";
import { TLS_HOSTS, TLS_MIN_DAYS } from "../config.mjs";
import { REQUEST_TIMEOUT_MS, daysUntil, describeError, fail, pass } from "../lib.mjs";

/** Connects with certificate verification and returns the leaf certificate's expiry. */
export function connectTls(host, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port: 443, servername: host, timeout: timeoutMs }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      const validTo = new Date(cert?.valid_to ?? "");
      if (Number.isNaN(validTo.getTime())) reject(new Error("no certificate expiry"));
      else resolve({ validTo });
    });
    socket.on("timeout", () => socket.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })));
    socket.on("error", reject);
  });
}

export async function run(ctx) {
  const results = [];
  for (const host of TLS_HOSTS) {
    const name = `tls-expiry ${host}`;
    try {
      const { validTo } = await ctx.tlsConnect(host);
      const days = daysUntil(validTo, ctx.now());
      results.push(days < TLS_MIN_DAYS ? fail(name, `${days} day(s) left`) : pass(name, `${days} day(s) left`));
    } catch (err) {
      results.push(fail(name, describeError(err)));
    }
  }
  return results;
}

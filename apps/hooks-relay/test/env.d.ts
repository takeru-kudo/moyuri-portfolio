// Types for cloudflare:workers env and exports in tests.

declare namespace Cloudflare {
  interface GlobalProps {
    mainModule: typeof import("../src/index.ts");
  }
  interface Env extends import("../src/index.ts").Env {}
}

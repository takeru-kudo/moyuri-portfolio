// Types for cloudflare:workers env and exports in tests.

type CspReportEnv = import("../src/index.ts").Env;
type CspReportMigration = import("cloudflare:test").D1Migration;

declare namespace Cloudflare {
  interface GlobalProps {
    mainModule: typeof import("../src/index.ts");
  }
  interface Env extends CspReportEnv {
    TEST_MIGRATIONS: CspReportMigration[];
  }
}

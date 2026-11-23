import { fileURLToPath } from "node:url";
import { defineConfig } from "astro/config";
import { securityHeaders } from "./src/integrations/security-headers.ts";

const fixtureDir = fileURLToPath(new URL("./fixtures/content/", import.meta.url));

export default defineConfig({
  site: "https://moyuri-kudo.com",
  output: "static",
  security: {
    csp: { algorithm: "SHA-256" },
  },
  markdown: {
    syntaxHighlight: false,
  },
  integrations: [securityHeaders()],
  vite: {
    define: {
      __CONTENT_FIXTURE_DIR__: JSON.stringify(fixtureDir),
    },
  },
});

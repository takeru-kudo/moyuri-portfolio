// Expected values for the daily monitor checks.

export const ZONE = "moyuri-kudo.com";
export const PROD_URL = `https://${ZONE}/`;
export const BETA_URL = `https://beta.${ZONE}/`;
export const SECURITY_TXT_URL = `https://${ZONE}/.well-known/security.txt`;

export const GITHUB_OWNER = "takeru-kudo";
export const GITHUB_REPO = "moyuri-portfolio";
export const GITHUB_API = "https://api.github.com";

export const CLOUDFLARE_API = "https://api.cloudflare.com/client/v4";

/** Minimum HSTS max-age for the current rollout stage. */
export const HSTS_MIN_MAX_AGE = 300;

/** Thresholds in days. */
export const TLS_MIN_DAYS = 14;
export const DOMAIN_MIN_DAYS = 60;
export const SECURITY_TXT_MIN_DAYS = 30;
export const KEY_MIN_DAYS = 30;
export const PAT_MIN_DAYS = 30;
export const PAT_RECORD_TOLERANCE_DAYS = 1;
export const DEPENDABOT_MAX_OPEN_DAYS = 7;
export const NODE_EOL_MIN_DAYS = 90;

/** Exact header values expected on the production home page (names are case-insensitive). */
export const PROD_HEADERS = [
  ["reporting-endpoints", 'csp="https://csp.moyuri-kudo.com/report"'],
  ["x-content-type-options", "nosniff"],
  ["referrer-policy", "strict-origin-when-cross-origin"],
  [
    "permissions-policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  ],
  ["cross-origin-opener-policy", "same-origin"],
  ["cross-origin-resource-policy", "same-origin"],
  ["x-frame-options", "DENY"],
  ["x-robots-tag", "noindex, nofollow"],
];

export const CSP_HEADER = "content-security-policy-report-only";

/** Expected CSP directives. Directives listed in CSP_HASH_DIRECTIVES may also carry hash sources. */
export const CSP_DIRECTIVES = [
  ["default-src", ["'none'"]],
  ["script-src", ["'self'"]],
  ["style-src", ["'self'"]],
  ["style-src-attr", ["'unsafe-inline'"]],
  ["img-src", ["'self'", "data:", "https://images.microcms-assets.io"]],
  ["media-src", ["https://media.moyuri-kudo.com"]],
  ["font-src", ["'self'"]],
  ["connect-src", ["'self'"]],
  ["manifest-src", ["'self'"]],
  ["base-uri", ["'none'"]],
  ["form-action", ["'none'"]],
  ["frame-ancestors", ["'none'"]],
  ["object-src", ["'none'"]],
  ["upgrade-insecure-requests", []],
  ["report-to", ["csp"]],
  ["report-uri", ["https://csp.moyuri-kudo.com/report"]],
];
export const CSP_HASH_DIRECTIVES = ["script-src", "style-src"];

/** Hosts whose TLS certificate expiry is checked. */
export const TLS_HOSTS = [ZONE, `www.${ZONE}`, `beta.${ZONE}`, `hooks.${ZONE}`, `status.${ZONE}`];

/** CAA issuers from infra/terraform/dns.tf (local.caa_issuers), each published as issue and issuewild. */
export const CAA_ISSUERS = ["letsencrypt.org", "pki.goog; cansignhttpexchanges=yes", "ssl.com"];
/** CAA issuers Cloudflare adds to the zone on its own, allowed in addition to CAA_ISSUERS. */
export const CAA_CLOUDFLARE_ISSUERS = ["digicert.com; cansignhttpexchanges=yes", "comodoca.com"];

export const SPF = "v=spf1 -all";
export const DMARC = "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s";

/** Issuer organisations (O= in the issuer DN) allowed in Certificate Transparency logs. */
export const CT_ISSUER_ORGS = [
  "Let's Encrypt",
  "Google Trust Services",
  "Google Trust Services LLC",
  "SSL Corporation",
  "DigiCert Inc",
  "Sectigo Limited",
  "COMODO CA Limited",
];

/** Host names allowed in Certificate Transparency logs. */
export const CT_HOSTNAMES = [
  ZONE,
  `*.${ZONE}`,
  `www.${ZONE}`,
  `beta.${ZONE}`,
  `*.beta.${ZONE}`,
  `hooks.${ZONE}`,
  `*.hooks.${ZONE}`,
  `csp.${ZONE}`,
  `*.csp.${ZONE}`,
  `media.${ZONE}`,
  `status.${ZONE}`,
];

/** Workers whose workers.dev route must be disabled: [name, probed path, may be absent]. */
export const WORKERS = [
  ["site-prod", "/", false],
  ["site-beta", "/", false],
  ["hooks-relay", "/healthz", false],
  ["csp-report", "/healthz", true],
];

/** Keys that must have a date in key-expiry.json. */
export const KEYS = [
  "K1",
  "K2",
  "K3",
  "K4",
  "K5",
  "K6",
  "K7",
  "K8a",
  "K8b",
  "K9",
  "K10",
  "K11",
  "K12a",
  "K12b",
];
export const PAT_KEY = "K9";

/** csp-report D1 database. */
export const CSP_WRANGLER_CONFIG = "apps/csp-report/wrangler.jsonc";
export const CSP_DATABASE_NAME = "csp_reports";
export const CSP_DATABASE_PLACEHOLDER = "<d1-database-id>";
/** Violation rows first seen at or after ?1 (epoch milliseconds). */
export const CSP_NEW_VIOLATIONS_SQL = "SELECT COUNT(*) AS n FROM violations WHERE first_seen >= ?1";
/** Overflow count for the UTC days ?1 and later (YYYY-MM-DD). */
export const CSP_OVERFLOW_SQL = "SELECT COALESCE(SUM(count), 0) AS n FROM overflow WHERE day >= ?1";

/** Expected shape of the `main` branch ruleset. */
export const RULESET_NAME = "main";
export const RULESET = {
  target: "branch",
  enforcement: "active",
  include: ["~DEFAULT_BRANCH"],
  exclude: [],
  ruleTypes: [
    "deletion",
    "non_fast_forward",
    "pull_request",
    "required_linear_history",
    "required_signatures",
    "required_status_checks",
  ],
  pullRequest: {
    required_approving_review_count: 0,
    dismiss_stale_reviews_on_push: false,
    require_code_owner_review: false,
    require_last_push_approval: false,
    required_review_thread_resolution: true,
    allowed_merge_methods: ["squash"],
  },
  statusChecks: {
    strict_required_status_checks_policy: true,
    integration_id: 15368,
    contexts: ["dependency-review", "site", "terraform", "tools-test", "workflow-lint"],
  },
};

export const NODE_VERSION_FILE = ".mise.toml";
export const NODE_EOL_API = "https://endoflife.date/api/v1/products/nodejs/releases";

export const RDAP_URL = `https://rdap.verisign.com/com/v1/domain/${ZONE}`;
export const DOH_URL = "https://dns.google/resolve";
export const CRT_SH_URL = "https://crt.sh/";

-- CSP violation counts per (directive, blocked_origin, document_path).
-- first_seen and last_seen are epoch milliseconds.
CREATE TABLE violations (
  directive TEXT NOT NULL,
  blocked_origin TEXT NOT NULL,
  document_path TEXT NOT NULL,
  count INTEGER NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (directive, blocked_origin, document_path)
);

CREATE INDEX violations_first_seen ON violations (first_seen);
CREATE INDEX violations_last_seen ON violations (last_seen);

-- Reports not stored (daily new-row cap or per-request key limit), per UTC day (YYYY-MM-DD).
CREATE TABLE overflow (
  day TEXT PRIMARY KEY,
  count INTEGER NOT NULL
);

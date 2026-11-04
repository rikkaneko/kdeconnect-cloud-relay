CREATE TABLE accounts (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 128),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at INTEGER NOT NULL
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY NOT NULL,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  kde_device_id TEXT NOT NULL CHECK (length(CAST(kde_device_id AS BLOB)) BETWEEN 1 AND 128),
  display_name TEXT NOT NULL CHECK (length(CAST(display_name AS BLOB)) BETWEEN 1 AND 128),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
  created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX devices_active_kde_id ON devices(account_id, kde_device_id) WHERE revoked = 0;
CREATE INDEX devices_directory ON devices(account_id, id) WHERE revoked = 0;

CREATE TABLE certificates (
  fingerprint TEXT PRIMARY KEY NOT NULL CHECK (
    length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*'
  ),
  device_id TEXT NOT NULL REFERENCES devices(id),
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
  created_at INTEGER NOT NULL
);

CREATE INDEX certificates_device ON certificates(device_id);

-- Quotas live in the schema as well as transactions, so races cannot over-admit.
CREATE TRIGGER devices_account_quota BEFORE INSERT ON devices
WHEN NEW.revoked = 0 AND (SELECT count(*) FROM devices WHERE account_id = NEW.account_id AND revoked = 0) >= 10
BEGIN
  SELECT RAISE(ABORT, 'device quota');
END;

CREATE TRIGGER certificates_device_quota BEFORE INSERT ON certificates
WHEN NEW.revoked = 0 AND (SELECT count(*) FROM certificates WHERE device_id = NEW.device_id AND revoked = 0 AND expires_at > unixepoch()) >= 2
BEGIN
  SELECT RAISE(ABORT, 'certificate quota');
END;

CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL CHECK (event IN (
    'account_created', 'account_enabled', 'account_disabled', 'device_registered',
    'device_revoked', 'certificate_approved', 'certificate_revoked', 'display_updated'
  )),
  subject_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

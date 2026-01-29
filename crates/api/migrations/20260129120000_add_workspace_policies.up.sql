-- Workspace policies for organization-wide drop settings
CREATE TABLE workspace_policies (
    workspace_id UUID PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
    max_ttl_seconds INTEGER,
    min_ttl_seconds INTEGER,
    default_ttl_seconds INTEGER,
    require_once BOOLEAN,
    default_once BOOLEAN,
    allow_external BOOLEAN,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure TTL values are consistent:
-- - min <= max (if both set)
-- - min <= default <= max (if default is set)
ALTER TABLE workspace_policies ADD CONSTRAINT check_ttl_range CHECK (
    (min_ttl_seconds IS NULL OR max_ttl_seconds IS NULL OR min_ttl_seconds <= max_ttl_seconds)
    AND (default_ttl_seconds IS NULL
         OR (min_ttl_seconds IS NULL OR default_ttl_seconds >= min_ttl_seconds)
         AND (max_ttl_seconds IS NULL OR default_ttl_seconds <= max_ttl_seconds))
);

-- Ensure require_once and default_once are consistent:
-- If require_once is true, default_once must also be true (or NULL)
ALTER TABLE workspace_policies ADD CONSTRAINT check_once_consistency CHECK (
    require_once IS NULL OR require_once = false OR default_once IS NULL OR default_once = true
);

COMMENT ON TABLE workspace_policies IS 'Organization-wide policies for drop creation';
COMMENT ON COLUMN workspace_policies.max_ttl_seconds IS 'Maximum allowed TTL for drops (NULL = no limit beyond global 24h)';
COMMENT ON COLUMN workspace_policies.min_ttl_seconds IS 'Minimum required TTL for drops (NULL = no minimum)';
COMMENT ON COLUMN workspace_policies.default_ttl_seconds IS 'Default TTL applied when sender uses 30s default';
COMMENT ON COLUMN workspace_policies.require_once IS 'Force burn-after-reading for all drops (NULL/false = optional)';
COMMENT ON COLUMN workspace_policies.default_once IS 'Default burn-after-reading when sender does not specify (NULL = false)';
COMMENT ON COLUMN workspace_policies.allow_external IS 'Allow sending to recipients outside workspace domains (NULL = allowed)';

-- Workspace activity log for auditing drop events.
-- Logs sent, opened, deleted, expired, and failed events.

CREATE TABLE workspace_activity_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,  -- 'drop.sent', 'drop.opened', 'drop.deleted', 'drop.expired', 'drop.failed'
    actor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    drop_id UUID,              -- NULL for failed events (drop was never created)
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Composite index for cursor pagination (workspace scope, newest first)
CREATE INDEX idx_workspace_activity_log_cursor
    ON workspace_activity_log(workspace_id, created_at DESC, id DESC);

-- Index for user's own activity (non-admins can only see their own events)
CREATE INDEX idx_workspace_activity_log_actor
    ON workspace_activity_log(actor_id, created_at DESC);

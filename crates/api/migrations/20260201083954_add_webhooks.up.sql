-- Add webhooks table for account-level webhook configuration.
-- Users can configure a webhook URL to receive notifications when they receive drops.

CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One webhook per user for now (can be relaxed later for multiple)
CREATE UNIQUE INDEX idx_webhooks_user_id ON webhooks(user_id);

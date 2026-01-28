-- Add Stripe billing columns to workspaces table
ALTER TABLE workspaces
ADD COLUMN stripe_customer_id TEXT UNIQUE,
ADD COLUMN stripe_subscription_id TEXT UNIQUE,
ADD COLUMN subscription_status TEXT NOT NULL DEFAULT 'none';

-- Index for efficient customer lookup (e.g., webhook handling)
CREATE INDEX idx_workspaces_stripe_customer_id ON workspaces(stripe_customer_id);

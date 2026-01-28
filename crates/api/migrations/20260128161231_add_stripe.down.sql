-- Remove Stripe billing columns from workspaces table
DROP INDEX IF EXISTS idx_workspaces_stripe_customer_id;

ALTER TABLE workspaces
DROP COLUMN IF EXISTS stripe_customer_id,
DROP COLUMN IF EXISTS stripe_subscription_id,
DROP COLUMN IF EXISTS subscription_status;

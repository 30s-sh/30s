-- Workspaces table (created implicitly when first domain is verified)
CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Workspace domains with DNS-based verification
CREATE TABLE workspace_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    domain TEXT NOT NULL UNIQUE,
    verification_token TEXT NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Workspace admins (users who can manage the workspace)
CREATE TABLE workspace_admins (
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, user_id)
);

-- Indexes for efficient lookups
CREATE INDEX idx_workspace_domains_domain ON workspace_domains(domain);
CREATE INDEX idx_workspace_domains_workspace_id ON workspace_domains(workspace_id);
CREATE INDEX idx_workspace_admins_user_id ON workspace_admins(user_id);

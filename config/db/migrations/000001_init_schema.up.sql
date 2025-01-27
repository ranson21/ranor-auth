SET search_path TO auth;

-- OAuth Providers table
CREATE TABLE oauth_providers (
    id VARCHAR(50) PRIMARY KEY,  -- 'google', 'github', etc.
    name VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    secret_id VARCHAR(255) NOT NULL,  -- Reference to secret in Secret Manager
    redirect_uri VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Applications table
CREATE TABLE sso_applications (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    scopes TEXT[] NOT NULL,
    allowed_users TEXT[],
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SSO Sessions table
CREATE TABLE sso_sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    provider VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    metadata JSONB
);

-- Application Tokens table
CREATE TABLE application_tokens (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    application_id VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    FOREIGN KEY (application_id) REFERENCES sso_applications(id)
);

CREATE TABLE users (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    provider VARCHAR(50) NOT NULL,
    profile_complete BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE auth_audit_log (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    event_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_sessions_expiry ON sso_sessions(expires_at);
CREATE INDEX idx_sessions_user ON sso_sessions(user_id);
CREATE INDEX idx_tokens_user_app ON application_tokens(user_id, application_id);
CREATE INDEX idx_tokens_expiry ON application_tokens(expires_at);
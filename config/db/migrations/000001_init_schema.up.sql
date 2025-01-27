SET search_path TO auth;

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- OAuth Providers table
CREATE TABLE oauth_providers (
    id VARCHAR(50) PRIMARY KEY,  -- 'google', 'github', etc.
    name VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    secret_id VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Applications table
CREATE TABLE sso_applications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL,
    allowed_users TEXT[],
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Application Provider Configuration (many-to-many with redirect URIs)
CREATE TABLE application_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    application_id UUID NOT NULL REFERENCES sso_applications(id) ON DELETE CASCADE,
    provider_id VARCHAR(50) NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    redirect_uri VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(application_id, provider_id)
);

-- SSO Sessions table
CREATE TABLE sso_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    provider VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    metadata JSONB
);

-- Application Tokens table
CREATE TABLE application_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    application_id UUID NOT NULL,
    scopes TEXT[] NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    FOREIGN KEY (application_id) REFERENCES sso_applications(id)
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    provider VARCHAR(50) NOT NULL,
    profile_complete BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE auth_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    event_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_sessions_expiry ON sso_sessions(expires_at);
CREATE INDEX idx_sessions_user ON sso_sessions(user_id);
CREATE INDEX idx_tokens_user_app ON application_tokens(user_id, application_id);
CREATE INDEX idx_tokens_expiry ON application_tokens(expires_at);
CREATE INDEX idx_app_providers ON application_providers(application_id, provider_id);
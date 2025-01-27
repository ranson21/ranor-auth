-- Set the schema
SET search_path TO auth;

-- First, set GUC parameters from environment variables
DO $$
BEGIN
    PERFORM set_config('app.google_client_id', current_setting('env.GOOGLE_CLIENT_ID'), false);
    PERFORM set_config('app.google_secret_id', current_setting('env.GOOGLE_SECRET_ID'), false);
    PERFORM set_config('app.github_client_id', current_setting('env.GITHUB_CLIENT_ID'), false);
    PERFORM set_config('app.github_secret_id', current_setting('env.GITHUB_SECRET_ID'), false);
EXCEPTION 
    WHEN OTHERS THEN
        PERFORM set_config('app.google_client_id', 'placeholder', false);
        PERFORM set_config('app.google_secret_id', 'placeholder', false);
        PERFORM set_config('app.github_client_id', 'placeholder', false);
        PERFORM set_config('app.github_secret_id', 'placeholder', false);
END $$;

-- Insert OAuth providers
INSERT INTO oauth_providers (id, name, client_id, secret_id, scopes, enabled)
VALUES 
    ('google', 'Google', 
     current_setting('app.google_client_id'),
     current_setting('app.google_secret_id'),
     ARRAY['openid', 'email', 'profile'],
     true),
    ('github', 'GitHub',
     current_setting('app.github_client_id'),
     current_setting('app.github_secret_id'),
     ARRAY['read:user', 'user:email'],
     true);

-- Insert the Ranor application
WITH inserted_app AS (
    INSERT INTO sso_applications (name, scopes, active)
    VALUES (
        'Ranor',
        ARRAY['openid', 'email', 'profile'],
        true
    )
    RETURNING id
)
-- Insert provider configurations for the application
INSERT INTO application_providers (application_id, provider_id, redirect_uri)
SELECT 
    inserted_app.id,
    provider_id,
    'https://ranor.abbyranson.com/auth/callback/' || provider_id
FROM inserted_app
CROSS JOIN (VALUES ('google'), ('github')) AS providers(provider_id);
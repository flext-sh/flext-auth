-- Database initialization script for FLEXT Authentication API
-- This script creates the necessary tables and indexes

-- Create database if it doesn't exist (PostgreSQL doesn't support IF NOT EXISTS for CREATE DATABASE in all versions)
-- This will be handled by the Docker environment variables

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for users table
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_accessed TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for sessions table
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);

-- Create login_attempts table for security logging
CREATE TABLE IF NOT EXISTS login_attempts (
    id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason TEXT,
    attempted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for login_attempts table
CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_address ON login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_attempted_at ON login_attempts(attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_success ON login_attempts(success);

-- Create permissions table (for future RBAC)
CREATE TABLE IF NOT EXISTS permissions (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create roles table (for future RBAC)
CREATE TABLE IF NOT EXISTS roles (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create role_permissions table (for future RBAC)
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id VARCHAR(255) NOT NULL,
    permission_id VARCHAR(255) NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

-- Create user_roles table (for future RBAC)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id VARCHAR(255) NOT NULL,
    role_id VARCHAR(255) NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- Add foreign key constraints
ALTER TABLE sessions
ADD CONSTRAINT IF NOT EXISTS fk_sessions_user_id
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE role_permissions
ADD CONSTRAINT IF NOT EXISTS fk_role_permissions_role_id
FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;

ALTER TABLE role_permissions
ADD CONSTRAINT IF NOT EXISTS fk_role_permissions_permission_id
FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE;

ALTER TABLE user_roles
ADD CONSTRAINT IF NOT EXISTS fk_user_roles_user_id
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE user_roles
ADD CONSTRAINT IF NOT EXISTS fk_user_roles_role_id
FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;

-- Insert default roles
INSERT INTO roles (id, name, description) VALUES
    ('role_REDACTED_LDAP_BIND_PASSWORD', 'REDACTED_LDAP_BIND_PASSWORD', 'System REDACTED_LDAP_BIND_PASSWORDistrator with full access'),
    ('role_user', 'user', 'Regular user with basic access'),
    ('role_moderator', 'moderator', 'Moderator with elevated access')
ON CONFLICT (name) DO NOTHING;

-- Insert default permissions
INSERT INTO permissions (id, name, description, resource, action) VALUES
    ('perm_users_read', 'users:read', 'Read user information', 'users', 'read'),
    ('perm_users_write', 'users:write', 'Create and update users', 'users', 'write'),
    ('perm_users_delete', 'users:delete', 'Delete users', 'users', 'delete'),
    ('perm_sessions_read', 'sessions:read', 'Read session information', 'sessions', 'read'),
    ('perm_sessions_write', 'sessions:write', 'Create and update sessions', 'sessions', 'write'),
    ('perm_sessions_delete', 'sessions:delete', 'Delete sessions', 'sessions', 'delete'),
    ('perm_REDACTED_LDAP_BIND_PASSWORD_access', 'REDACTED_LDAP_BIND_PASSWORD:access', 'Access REDACTED_LDAP_BIND_PASSWORD functionality', 'REDACTED_LDAP_BIND_PASSWORD', 'access')
ON CONFLICT (name) DO NOTHING;

-- Grant permissions to REDACTED_LDAP_BIND_PASSWORD role
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('role_REDACTED_LDAP_BIND_PASSWORD', 'perm_users_read'),
    ('role_REDACTED_LDAP_BIND_PASSWORD', 'perm_users_write'),
    ('role_REDACTED_LDAP_BIND_PASSWORD', 'perm_users_delete'),
    ('role_REDACTED_LDAP_BIND_PASSWORD', 'perm_sessions_read'),
    ('role_REDACTED_LDAP_BIND_PASSWORD', 'perm_sessions_write'),
    ('role_REDACTED_LDAP_BIND_PASSWORD', 'perm_sessions_delete'),
    ('role_REDACTED_LDAP_BIND_PASSWORD', 'perm_REDACTED_LDAP_BIND_PASSWORD_access')
ON CONFLICT DO NOTHING;

-- Grant basic permissions to user role
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('role_user', 'perm_users_read'),
    ('role_user', 'perm_sessions_read')
ON CONFLICT DO NOTHING;

-- Grant moderator permissions
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('role_moderator', 'perm_users_read'),
    ('role_moderator', 'perm_users_write'),
    ('role_moderator', 'perm_sessions_read'),
    ('role_moderator', 'perm_sessions_write')
ON CONFLICT DO NOTHING;

-- Create a function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create a cleanup function for expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM sessions WHERE expires_at <= NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create a view for active user sessions
CREATE OR REPLACE VIEW active_user_sessions AS
SELECT
    s.id,
    s.user_id,
    u.username,
    u.email,
    s.ip_address,
    s.user_agent,
    s.created_at,
    s.last_accessed,
    s.expires_at
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.status = 'active'
  AND s.expires_at > NOW()
ORDER BY s.last_accessed DESC;

-- Grant necessary permissions to the application user
-- (These would typically be run with a more restricted user in production)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO PUBLIC;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO PUBLIC;

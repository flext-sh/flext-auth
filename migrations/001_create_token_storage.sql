-- Token Storage Table for FLX Auth
-- Stores token metadata with TTL support for blacklisting and session management

CREATE TABLE IF NOT EXISTS token_storage (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for expiration cleanup
CREATE INDEX idx_token_storage_expires_at ON token_storage(expires_at) WHERE expires_at IS NOT NULL;

-- Index for pattern matching
CREATE INDEX idx_token_storage_key_pattern ON token_storage(key);

-- Function to auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for updated_at
CREATE TRIGGER update_token_storage_updated_at BEFORE UPDATE
    ON token_storage FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE token_storage IS 'Storage for token blacklisting and session management with TTL support';
COMMENT ON COLUMN token_storage.key IS 'Unique token identifier or session key';
COMMENT ON COLUMN token_storage.value IS 'Serialized token metadata or session data';
COMMENT ON COLUMN token_storage.expires_at IS 'Optional expiration timestamp for automatic cleanup';
COMMENT ON COLUMN token_storage.created_at IS 'When the token was first stored';
COMMENT ON COLUMN token_storage.updated_at IS 'Last modification timestamp';

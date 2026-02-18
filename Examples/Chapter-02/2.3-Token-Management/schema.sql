-- ============================================
-- TOKEN MANAGEMENT DATABASE SCHEMA
-- ============================================
-- Referenced in: Vibe-Coded App Security Framework
-- Chapter 2.3.2 and 2.3.3
-- ============================================

-- ============================================
-- PASSWORD RESET TOKENS
-- ============================================
-- Used for: Password resets, magic links, email verification
-- Expiration: 15-60 minutes (configurable)
-- Single-use: Yes

CREATE TABLE password_reset_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token_hash VARCHAR(64) NOT NULL,  -- SHA-256 hash (64 hex chars)
  expires_at DATETIME NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  used_at DATETIME NULL,
  
  INDEX idx_token_hash (token_hash),
  INDEX idx_user_id (user_id),
  INDEX idx_expires_at (expires_at),
  INDEX idx_used (used),
  
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================
-- REMEMBER ME TOKENS
-- ============================================
-- Used for: Persistent "remember me" authentication
-- Expiration: 30-90 days (configurable)
-- Single-use: No (but rotated periodically)

CREATE TABLE remember_me_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  selector VARCHAR(24) NOT NULL,    -- Public identifier (12 bytes = 24 hex)
  token_hash VARCHAR(64) NOT NULL,  -- SHA-256 hash of secret token
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  UNIQUE INDEX idx_selector (selector),
  INDEX idx_user_id (user_id),
  INDEX idx_expires_at (expires_at),
  
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================
-- INVITE TOKENS
-- ============================================
-- Used for: User invitations, referral links
-- Expiration: 7-30 days (configurable)
-- Single-use: Yes

CREATE TABLE invite_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  inviter_id INT NOT NULL,
  invitee_email VARCHAR(255) NOT NULL,
  token_hash VARCHAR(64) NOT NULL,  -- SHA-256 hash
  expires_at DATETIME NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  used_at DATETIME NULL,
  used_by_user_id INT NULL,
  
  INDEX idx_token_hash (token_hash),
  INDEX idx_inviter_id (inviter_id),
  INDEX idx_invitee_email (invitee_email),
  INDEX idx_expires_at (expires_at),
  INDEX idx_used (used),
  
  FOREIGN KEY (inviter_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (used_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- ============================================
-- API KEYS (OPTIONAL)
-- ============================================
-- Used for: Third-party API access
-- Expiration: Never (or very long)
-- Single-use: No
-- Revocable: Yes

CREATE TABLE api_keys (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  key_prefix VARCHAR(16) NOT NULL,  -- First 16 chars (for display)
  key_hash VARCHAR(64) NOT NULL,    -- SHA-256 hash of full key
  name VARCHAR(255) NOT NULL,       -- User-friendly name
  scopes JSON,                      -- Permissions (e.g., ["read", "write"])
  last_used DATETIME NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  revoked BOOLEAN DEFAULT FALSE,
  revoked_at DATETIME NULL,
  
  UNIQUE INDEX idx_key_prefix (key_prefix),
  INDEX idx_key_hash (key_hash),
  INDEX idx_user_id (user_id),
  INDEX idx_revoked (revoked),
  
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================
-- CLEANUP PROCEDURES
-- ============================================
-- Run these periodically (daily cron job)

-- Clean up expired password reset tokens
DELETE FROM password_reset_tokens 
WHERE expires_at < NOW() 
   OR (used = TRUE AND used_at < DATE_SUB(NOW(), INTERVAL 30 DAY));

-- Clean up expired remember me tokens
DELETE FROM remember_me_tokens 
WHERE expires_at < NOW();

-- Clean up expired invite tokens
DELETE FROM invite_tokens 
WHERE expires_at < NOW() 
   OR (used = TRUE AND used_at < DATE_SUB(NOW(), INTERVAL 30 DAY));

-- ============================================
-- POSTGRESQL VERSION
-- ============================================
-- If using PostgreSQL instead of MySQL, use these:

/*
CREATE TABLE password_reset_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  token_hash VARCHAR(64) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  used_at TIMESTAMP NULL,
  
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_expires_at ON password_reset_tokens(expires_at);
CREATE INDEX idx_used ON password_reset_tokens(used);

-- Similar for other tables...
*/

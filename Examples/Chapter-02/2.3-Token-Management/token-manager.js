/**
 * Secure Token Management for Password Resets, Magic Links, and Invites
 * 
 * Referenced in: Vibe-Coded App Security Framework
 * Chapter 2.3.2: Custom Token Management
 * 
 * Security Features:
 * - Cryptographically secure token generation
 * - Tokens stored as hashes (never plain text)
 * - Single-use enforcement
 * - Expiration handling
 * - Token revocation
 */

const crypto = require('crypto');

class TokenManager {
  /**
   * Generate cryptographically secure random token
   * @param {number} bytes - Number of random bytes (default: 32 = 64 hex chars)
   * @returns {string} Hex-encoded token
   */
  static generateToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
  }

  /**
   * Hash a token using SHA-256
   * @param {string} token - Plain token
   * @returns {string} Hashed token (hex)
   */
  static hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Create a password reset token
   * @param {number} userId - User ID
   * @param {object} db - Database connection
   * @param {number} expiryMinutes - Token expiry time (default: 60)
   * @returns {string} Plain token (send to user, never store)
   */
  static async createPasswordResetToken(userId, db, expiryMinutes = 60) {
    const token = this.generateToken(32);
    const hashedToken = this.hashToken(token);
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);

    await db.query(
      `INSERT INTO password_reset_tokens 
       (user_id, token_hash, expires_at, used, created_at) 
       VALUES (?, ?, ?, ?, ?)`,
      [userId, hashedToken, expiresAt, false, new Date()]
    );

    return token;
  }

  /**
   * Verify a password reset token
   * @param {string} token - Plain token from user
   * @param {object} db - Database connection
   * @returns {object} { valid: boolean, userId?: number, error?: string }
   */
  static async verifyPasswordResetToken(token, db) {
    const hashedToken = this.hashToken(token);

    const result = await db.query(
      `SELECT user_id, expires_at, used 
       FROM password_reset_tokens 
       WHERE token_hash = ?`,
      [hashedToken]
    );

    if (result.length === 0) {
      return { valid: false, error: 'Invalid token' };
    }

    const tokenData = result[0];

    if (tokenData.used) {
      return { valid: false, error: 'Token already used' };
    }

    if (new Date() > new Date(tokenData.expires_at)) {
      return { valid: false, error: 'Token expired' };
    }

    return { valid: true, userId: tokenData.user_id };
  }

  /**
   * Mark token as used (single-use enforcement)
   * @param {string} token - Plain token
   * @param {object} db - Database connection
   */
  static async markTokenUsed(token, db) {
    const hashedToken = this.hashToken(token);

    await db.query(
      `UPDATE password_reset_tokens 
       SET used = ?, used_at = ? 
       WHERE token_hash = ?`,
      [true, new Date(), hashedToken]
    );
  }

  /**
   * Revoke all tokens for a user (e.g., after password change)
   * @param {number} userId - User ID
   * @param {object} db - Database connection
   */
  static async revokeUserTokens(userId, db) {
    await db.query(
      `UPDATE password_reset_tokens 
       SET used = ?, used_at = ? 
       WHERE user_id = ? AND used = ?`,
      [true, new Date(), userId, false]
    );
  }

  /**
   * Clean up expired tokens (run periodically via cron)
   * @param {object} db - Database connection
   * @param {number} daysOld - Delete tokens older than this (default: 30)
   */
  static async cleanupExpiredTokens(db, daysOld = 30) {
    const cutoffDate = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);

    await db.query(
      `DELETE FROM password_reset_tokens 
       WHERE expires_at < ? OR (used = ? AND used_at < ?)`,
      [new Date(), true, cutoffDate]
    );
  }

  /**
   * Create a magic link token (short-lived, single-use)
   * @param {number} userId - User ID
   * @param {object} db - Database connection
   * @param {number} expiryMinutes - Token expiry time (default: 15)
   * @returns {string} Plain token
   */
  static async createMagicLinkToken(userId, db, expiryMinutes = 15) {
    // Magic links use same table as password reset but shorter expiry
    return this.createPasswordResetToken(userId, db, expiryMinutes);
  }

  /**
   * Create an invite token
   * @param {number} inviterId - User ID of person sending invite
   * @param {string} inviteeEmail - Email of person being invited
   * @param {object} db - Database connection
   * @param {number} expiryDays - Token expiry time (default: 7)
   * @returns {string} Plain token
   */
  static async createInviteToken(inviterId, inviteeEmail, db, expiryDays = 7) {
    const token = this.generateToken(32);
    const hashedToken = this.hashToken(token);
    const expiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);

    await db.query(
      `INSERT INTO invite_tokens 
       (inviter_id, invitee_email, token_hash, expires_at, used, created_at) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [inviterId, inviteeEmail, hashedToken, expiresAt, false, new Date()]
    );

    return token;
  }

  /**
   * Verify an invite token
   * @param {string} token - Plain token
   * @param {object} db - Database connection
   * @returns {object} { valid: boolean, inviterId?: number, inviteeEmail?: string, error?: string }
   */
  static async verifyInviteToken(token, db) {
    const hashedToken = this.hashToken(token);

    const result = await db.query(
      `SELECT inviter_id, invitee_email, expires_at, used 
       FROM invite_tokens 
       WHERE token_hash = ?`,
      [hashedToken]
    );

    if (result.length === 0) {
      return { valid: false, error: 'Invalid token' };
    }

    const tokenData = result[0];

    if (tokenData.used) {
      return { valid: false, error: 'Token already used' };
    }

    if (new Date() > new Date(tokenData.expires_at)) {
      return { valid: false, error: 'Token expired' };
    }

    return { 
      valid: true, 
      inviterId: tokenData.inviter_id,
      inviteeEmail: tokenData.invitee_email
    };
  }

  /**
   * Mark invite token as used
   * @param {string} token - Plain token
   * @param {object} db - Database connection
   */
  static async markInviteTokenUsed(token, db) {
    const hashedToken = this.hashToken(token);

    await db.query(
      `UPDATE invite_tokens 
       SET used = ?, used_at = ? 
       WHERE token_hash = ?`,
      [true, new Date(), hashedToken]
    );
  }
}

module.exports = TokenManager;

/**
 * Secure "Remember Me" Token Management
 * 
 * Referenced in: Vibe-Coded App Security Framework
 * Chapter 2.3.3: "Remember Me" Functionality
 * 
 * Security Features:
 * - Selector pattern (public selector + secret token)
 * - Tokens stored as hashes
 * - Token rotation
 * - Revocation support
 * - Limited scope (requires re-auth for sensitive actions)
 */

const crypto = require('crypto');

class RememberMeManager {
  /**
   * Generate cryptographically secure random string
   * @param {number} bytes - Number of random bytes
   * @returns {string} Hex-encoded string
   */
  static generateRandom(bytes) {
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
   * Create a remember-me token
   * @param {number} userId - User ID
   * @param {object} db - Database connection
   * @param {number} expiryDays - Token expiry time (default: 30)
   * @returns {string} Combined token (selector:token)
   */
  static async createRememberMeToken(userId, db, expiryDays = 30) {
    const selector = this.generateRandom(12); // 24 hex chars (public)
    const token = this.generateRandom(32);    // 64 hex chars (secret)
    const hashedToken = this.hashToken(token);
    const expiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);

    await db.query(
      `INSERT INTO remember_me_tokens 
       (user_id, selector, token_hash, expires_at, created_at, last_used) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, selector, hashedToken, expiresAt, new Date(), new Date()]
    );

    // Return combined token: selector:token
    return `${selector}:${token}`;
  }

  /**
   * Verify a remember-me token
   * @param {string} combinedToken - Combined token (selector:token)
   * @param {object} db - Database connection
   * @returns {object} { valid: boolean, userId?: number, selector?: string, error?: string }
   */
  static async verifyRememberMeToken(combinedToken, db) {
    const [selector, token] = combinedToken.split(':');

    if (!selector || !token) {
      return { valid: false, error: 'Invalid token format' };
    }

    const hashedToken = this.hashToken(token);

    const result = await db.query(
      `SELECT user_id, expires_at, last_used 
       FROM remember_me_tokens 
       WHERE selector = ? AND token_hash = ?`,
      [selector, hashedToken]
    );

    if (result.length === 0) {
      return { valid: false, error: 'Invalid token' };
    }

    const tokenData = result[0];

    if (new Date() > new Date(tokenData.expires_at)) {
      // Clean up expired token
      await db.query('DELETE FROM remember_me_tokens WHERE selector = ?', [selector]);
      return { valid: false, error: 'Token expired' };
    }

    // Update last_used timestamp
    await db.query(
      'UPDATE remember_me_tokens SET last_used = ? WHERE selector = ?',
      [new Date(), selector]
    );

    return { valid: true, userId: tokenData.user_id, selector };
  }

  /**
   * Rotate a remember-me token (create new, delete old)
   * @param {string} oldSelector - Selector from old token
   * @param {number} userId - User ID
   * @param {object} db - Database connection
   * @returns {string} New combined token (selector:token)
   */
  static async rotateRememberMeToken(oldSelector, userId, db) {
    // Delete old token
    await db.query('DELETE FROM remember_me_tokens WHERE selector = ?', [oldSelector]);

    // Create new token
    return this.createRememberMeToken(userId, db);
  }

  /**
   * Revoke a specific remember-me token
   * @param {string} selector - Token selector
   * @param {object} db - Database connection
   */
  static async revokeRememberMeToken(selector, db) {
    await db.query('DELETE FROM remember_me_tokens WHERE selector = ?', [selector]);
  }

  /**
   * Revoke all remember-me tokens for a user
   * @param {number} userId - User ID
   * @param {object} db - Database connection
   */
  static async revokeAllUserTokens(userId, db) {
    await db.query('DELETE FROM remember_me_tokens WHERE user_id = ?', [userId]);
  }

  /**
   * Get all active remember-me tokens for a user (for UI display)
   * @param {number} userId - User ID
   * @param {object} db - Database connection
   * @returns {Array} Array of token info (without secrets)
   */
  static async getUserTokens(userId, db) {
    const result = await db.query(
      `SELECT selector, created_at, last_used, expires_at 
       FROM remember_me_tokens 
       WHERE user_id = ? AND expires_at > ?
       ORDER BY last_used DESC`,
      [userId, new Date()]
    );

    return result.map(token => ({
      selector: token.selector,
      createdAt: token.created_at,
      lastUsed: token.last_used,
      expiresAt: token.expires_at
    }));
  }

  /**
   * Clean up expired tokens (run periodically via cron)
   * @param {object} db - Database connection
   */
  static async cleanupExpiredTokens(db) {
    await db.query(
      'DELETE FROM remember_me_tokens WHERE expires_at < ?',
      [new Date()]
    );
  }

  /**
   * Check if token should be rotated (older than X days)
   * @param {string} selector - Token selector
   * @param {object} db - Database connection
   * @param {number} rotationDays - Rotate if older than this (default: 7)
   * @returns {boolean} True if should rotate
   */
  static async shouldRotateToken(selector, db, rotationDays = 7) {
    const result = await db.query(
      'SELECT created_at FROM remember_me_tokens WHERE selector = ?',
      [selector]
    );

    if (result.length === 0) {
      return false;
    }

    const createdAt = new Date(result[0].created_at);
    const rotationDate = new Date(Date.now() - rotationDays * 24 * 60 * 60 * 1000);

    return createdAt < rotationDate;
  }
}

module.exports = RememberMeManager;

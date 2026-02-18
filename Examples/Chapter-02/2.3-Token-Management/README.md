# Token Management Examples

Complete implementations of secure token management for password resets, magic links, remember-me functionality, and invite codes.

Referenced in Chapter 2.3.2 and 2.3.3 of the Vibe-Coded App Security Framework.

## Files

- **`token-manager.js`** - Password reset, magic links, invite tokens
- **`remember-me-manager.js`** - Persistent "remember me" authentication
- **`schema.sql`** - Database schemas for token storage
- **`test-token-manager.js`** - Test suite for token functionality

## Security Principles

All token implementations follow these security principles:

1. **Cryptographically secure random generation** - Uses `crypto.randomBytes()`, never `Math.random()`
2. **Tokens stored as hashes** - Never store plain tokens in database
3. **Single-use enforcement** - Tokens marked as used after redemption
4. **Expiration** - All tokens have appropriate expiration times
5. **Revocation** - Ability to revoke tokens before expiration

## Quick Start

### 1. Set up database

```bash
# MySQL
mysql -u root -p < schema.sql

# PostgreSQL
psql -U postgres -d your_database < schema.sql
```

### 2. Install dependencies

```npm install crypto bcrypt mysql2
# or
npm install crypto bcrypt pg
```

### 3. Use in your application

```const TokenManager = require('./token-manager');
const RememberMeManager = require('./remember-me-manager');

// Password reset
const token = await TokenManager.createPasswordResetToken(userId, db);
await sendEmail(user.email, `Reset link: https://yourapp.com/reset?token=${token}`);

// Remember me
const rememberToken = await RememberMeManager.createRememberMeToken(userId, db);
res.cookie('rememberMe', rememberToken, { httpOnly: true, secure: true });
```

## Token Types

### Password Reset Tokens

- **Entropy**: 256 bits (32 bytes)
- **Expiration**: 15-60 minutes
- **Single-use**: Yes
- **Revocable**: Yes

### Magic Link Tokens

- **Entropy:** 256 bits (32 bytes)
- **Expiration:** 5-15 minutes
- **Single-use:** Yes
- **Revocable:** Yes

### Remember Me Tokens
- **Entropy:** 256 bits (32 bytes)
- **Expiration:** 30-90 days
- **Single-use:** No (but rotated)
- **Revocable:** Yes

### Invite Tokens
- **Entropy:** 128-256 bits
- **Expiration:** 7-30 days
- **Single-use:** Yes
- **Revocable:** Yes

### Testing

```npm test
```

## Security Checklist

- [ ] Tokens generated with crypto.randomBytes()
- [ ] Tokens stored as SHA-256 hashes
- [ ] Single-use tokens marked as used
- [ ] All tokens have expiration
- [ ] Expired tokens cleaned up periodically
- [ ] Token verification checks expiration and usage
- [ ] Revocation mechanism implemented
- [ ] Rate limiting on token generation endpoints

## Common Mistakes to Avoid

- Using Math.random() for token generation 
- Storing tokens in plain text 
- No expiration on tokens 
- No single-use enforcement 
- Accepting tokens from URL parameters for sensitive actions 
- No rate limiting on token generation

## Related

- Chapter 2.3.2: Custom Token Management
- Chapter 2.3.3: "Remember Me" Functionality
- Chapter 2.6.2: Cryptography Best Practices
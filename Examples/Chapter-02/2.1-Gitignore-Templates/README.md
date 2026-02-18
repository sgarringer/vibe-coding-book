# Security-Focused .gitignore Templates

These `.gitignore` templates include security-focused additions beyond standard templates to prevent accidental commits of sensitive data.

## Templates

- **`node.gitignore`** - Node.js/JavaScript projects
- **`python.gitignore`** - Python projects
- **`java.gitignore`** - Java/Spring projects
- **`dotnet.gitignore`** - .NET/C# projects
- **`ruby.gitignore`** - Ruby/Rails projects
- **`php.gitignore`** - PHP projects
- **`go.gitignore`** - Go projects
- **`universal-security.gitignore`** - Security additions for any project

## Usage

### Option 1: Copy Template

```bash
# Copy the template for your language
cp node.gitignore /path/to/your/project/.gitignore
```

### Option 2: Append Security Rules

```# Add security rules to existing .gitignore
cat universal-security.gitignore >> /path/to/your/project/.gitignore
```

### Option 3: Use GitHub's Template + Security Additions

```# Start with GitHub's template
curl https://raw.githubusercontent.com/github/gitignore/main/Node.gitignore > .gitignore

# Add security-specific rules
cat universal-security.gitignore >> .gitignore
```

### Verification

After adding .gitignore, verify no secrets are tracked:

```# Check for common secret patterns
git grep -i "api[_-]key"
git grep -i "password"
git grep -i "secret"
git grep -E "sk_live_|pk_live_"  # Stripe keys
git grep -E "AKIA[0-9A-Z]{16}"   # AWS keys

# Check for environment files
git ls-files | grep -E "\.env$|\.env\."

# If found, remove from history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch .env" \
  --prune-empty --tag-name-filter cat -- --all
```

## Security Checklist

- [ ] .env files ignored
- [ ] API keys and secrets ignored
- [ ] Database credentials ignored
- [ ] SSL certificates and private keys ignored
- [ ] Cloud provider credentials ignored
- [ ] IDE configuration with secrets ignored
- [ ] Build artifacts with embedded secrets ignored
- [ ] Backup files ignored
- [ ] Log files with potential secrets ignored

## Related

- Chapter 2.1.1: The .gitignore File
- Chapter 2.1.2: Pre-Commit Hooks for Secret Scanning
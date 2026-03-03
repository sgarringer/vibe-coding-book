# Lockfile Conflict Resolution Guide
**Book Reference:** Chapter 3, Section 3.3.8 - Example 3.21

## The Golden Rule

> **Never manually resolve conflicts in a lockfile. Always regenerate it.**

Lockfiles contain cryptographic hashes, dependency trees, and integrity
checksums that are impossible to merge correctly by hand. A manually
resolved lockfile may:

- Install different package versions than intended
- Break integrity hash verification
- Introduce subtle dependency mismatches
- Cause `npm ci` to fail in CI/CD

---

## Why Lockfile Conflicts Happen

Lockfile conflicts occur when two branches both modify dependencies:

```
main branch:    adds lodash@4.17.21
feature branch: adds axios@1.6.0
```

When you merge, both `package.json` and `package-lock.json` have
conflicting changes. Git cannot automatically resolve the lockfile
because it contains a full dependency tree, not just the packages
you added directly.

---

## Resolution by Package Manager

### npm (package-lock.json)

Example 3.21 from the book:

```bash
# 1. Accept either version of package.json (yours or theirs)
#    Manually merge only package.json - it is human-readable
git checkout --theirs package.json    # Take their package.json
# OR
git checkout --ours package.json      # Keep your package.json
# OR manually edit package.json to include both sets of changes

# 2. Delete the conflicted lockfile
rm package-lock.json

# 3. Regenerate from package.json
npm install

# 4. Verify the lockfile is correct
npm ci

# 5. Commit the clean lockfile
git add package.json package-lock.json
git commit -m "fix: regenerate lockfile after merge"
```

### Yarn (yarn.lock)

```bash
# 1. Resolve package.json manually (keep both sets of dependencies)
# Edit package.json to include all required packages from both branches

# 2. Delete the conflicted lockfile
rm yarn.lock

# 3. Regenerate
yarn install

# 4. Verify
yarn install --frozen-lockfile

# 5. Commit
git add package.json yarn.lock
git commit -m "fix: regenerate yarn.lock after merge"
```

### pnpm (pnpm-lock.yaml)

```bash
# 1. Resolve pnpm-lock.yaml conflict by deleting it
rm pnpm-lock.yaml

# 2. Regenerate
pnpm install

# 3. Verify
pnpm install --frozen-lockfile

# 4. Commit
git add package.json pnpm-lock.yaml
git commit -m "fix: regenerate pnpm-lock.yaml after merge"
```

### Python pip (requirements.txt with hashes)

```bash
# 1. Resolve requirements.in (the source file) manually
# Keep all packages from both branches in requirements.in

# 2. Regenerate requirements.txt with hashes (Example 3.19)
pip-compile \
    --generate-hashes \
    --output-file requirements.txt \
    requirements.in

# 3. Verify installation
pip install --require-hashes -r requirements.txt

# 4. Commit
git add requirements.in requirements.txt
git commit -m "fix: regenerate requirements.txt after merge"
```

### Python Poetry (poetry.lock)

```bash
# 1. Resolve pyproject.toml manually
# Keep all dependencies from both branches

# 2. Delete the conflicted lockfile
rm poetry.lock

# 3. Regenerate
poetry lock

# 4. Verify
poetry install --no-update
poetry check --lock

# 5. Commit
git add pyproject.toml poetry.lock
git commit -m "fix: regenerate poetry.lock after merge"
```

### Go (go.sum)

```bash
# 1. Resolve go.mod manually
# Keep all require directives from both branches

# 2. Regenerate go.sum
go mod tidy

# 3. Verify
go mod verify

# 4. Commit
git add go.mod go.sum
git commit -m "fix: regenerate go.sum after merge"
```

### Ruby (Gemfile.lock)

```bash
# 1. Resolve Gemfile manually
# Keep all gem declarations from both branches

# 2. Delete the conflicted lockfile
rm Gemfile.lock

# 3. Regenerate
bundle install

# 4. Verify
bundle install --frozen

# 5. Commit
git add Gemfile Gemfile.lock
git commit -m "fix: regenerate Gemfile.lock after merge"
```

---

## Preventing Conflicts

The best conflict is one that never happens.

### Strategy 1: Merge main into your branch frequently

```bash
# Keep your branch up to date to minimise divergence
git fetch origin
git merge origin/main
# Resolve package.json conflicts, then regenerate lockfile
```

### Strategy 2: Separate dependency PRs

Make dependency updates in their own PRs that merge quickly,
rather than bundling them with feature work.

```bash
# Good: separate PR just for dependency updates
git checkout -b deps/update-axios
npm install axios@latest
git add package.json package-lock.json
git commit -m "chore: update axios to 1.6.0"
```

### Strategy 3: Use Dependabot

Let Dependabot manage dependency updates automatically.
Its PRs are small, focused, and merge quickly before conflicts develop.
See `../dependabot.yml` for configuration.

### Strategy 4: .gitattributes merge strategy

Tell Git to always use the union merge strategy for lockfiles,
which reduces (but does not eliminate) conflicts:

```
# .gitattributes
package-lock.json merge=union
yarn.lock         merge=union
```

> **Warning:** The union strategy still produces invalid lockfiles
> in many cases. Always regenerate after any merge conflict.

---

## CI/CD Conflict Detection

The `github-actions-lockfiles.yml` workflow automatically detects
out-of-sync lockfiles on every PR. If `npm ci` fails with:

```
npm ci can only install packages when your package.json
and package-lock.json are in sync
```

This means the lockfile needs to be regenerated. Follow the steps
above for your package manager.

---

## Quick Reference

| Package Manager | Delete | Regenerate | Verify |
|----------------|--------|------------|--------|
| npm | `rm package-lock.json` | `npm install` | `npm ci` |
| yarn | `rm yarn.lock` | `yarn install` | `yarn install --frozen-lockfile` |
| pnpm | `rm pnpm-lock.yaml` | `pnpm install` | `pnpm install --frozen-lockfile` |
| pip | regenerate only | `pip-compile --generate-hashes` | `pip install --require-hashes -r requirements.txt` |
| poetry | `rm poetry.lock` | `poetry lock` | `poetry check --lock` |
| go | never delete go.sum | `go mod tidy` | `go mod verify` |
| bundler | `rm Gemfile.lock` | `bundle install` | `bundle install --frozen` |

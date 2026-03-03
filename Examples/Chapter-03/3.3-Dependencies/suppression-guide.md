# Dependency Scan Suppression Guide

**Book Reference:** Chapter 3, Section 3.3.2.4

## Overview

Dependency scanners sometimes flag vulnerabilities that don't apply to your
specific usage. This guide explains how to suppress false positives correctly
across all supported tools, and how to maintain suppressions responsibly.

> **Important:** Every suppression must be documented with a reason.
> Undocumented suppressions will be rejected in code review.
> Review all suppressions quarterly.

---

## When to Suppress vs. When to Fix

Before suppressing, ask these questions:

| Question                                           | If Yes                        | If No                          |
| -------------------------------------------------- | ----------------------------- | ------------------------------ |
| Is there a fixed version available?                | **Upgrade the package** | Consider suppression           |
| Does the vulnerability affect your usage?          | **Fix it**              | Suppression may be appropriate |
| Is the vulnerable code path reachable?             | **Fix it**              | Suppression may be appropriate |
| Is there a WAF or other mitigating control?        | Document and suppress         | Fix it                         |
| Is this a transitive dependency you can't control? | Suppress with ticket          | Upgrade direct dep             |

---

## Trivy Suppressions (.trivyignore)

The `.trivyignore` file lives in your repository root.
Each line is a CVE ID to suppress, with a mandatory comment.

### Format

```
# .trivyignore
# Format: <CVE-ID>  # <reason> | expires: <YYYY-MM-DD> | ticket: <TICKET-ID>

# Example suppressions:
CVE-2023-12345  # Not exploitable - vulnerable function not called in our codebase
                # expires: 2024-03-01 | ticket: SEC-123

CVE-2023-67890  # Mitigated by WAF rule WAF-456 blocking the attack vector
                # expires: 2024-06-01 | ticket: SEC-124

CVE-2022-99999  # No fix available - transitive dep of lodash, tracking in SEC-125
                # expires: 2024-01-15 | ticket: SEC-125
```

### Required Fields

Every suppression entry must include:

1. **Reason** - Why is this not exploitable or mitigated?
2. **Expiry date** - When should this suppression be reviewed?
3. **Ticket** - Link to the tracking issue in your issue tracker

### Suppression Categories

```
# Category 1: Not exploitable in our usage
# Use when: The vulnerable code path is never called
CVE-2023-XXXXX  # Not exploitable: we use xml.parse() not xml.parseString()
                # which is the only affected function. expires: 2024-06-01

# Category 2: Mitigated by compensating control
# Use when: A WAF, network policy, or other control prevents exploitation
CVE-2023-XXXXX  # Mitigated: WAF rule blocks the HTTP request pattern
                # required for exploitation. expires: 2024-03-01

# Category 3: No fix available
# Use when: The vendor has not released a patch yet
# IMPORTANT: Set a short expiry and check regularly
CVE-2023-XXXXX  # No fix available as of 2024-01-01. Tracking upstream.
                # expires: 2024-02-01 | ticket: SEC-999

# Category 4: Accepted risk
# Use when: Risk has been formally accepted by security team
# REQUIRES: Written approval from security lead
CVE-2023-XXXXX  # Accepted risk: CVSS 4.2, requires physical access.
                # Approved by: security-lead@company.com on 2024-01-01
                # expires: 2024-07-01 | ticket: SEC-998
```

---

## Snyk Suppressions (.snyk)

Snyk uses a `.snyk` policy file in your repository root.

```yaml
# .snyk
# Snyk (https://snyk.io) policy file

version: v1.25.0

ignore:
  SNYK-JS-LODASH-567746:
    - '*':
        reason: >
          Not exploitable in our usage. We only call _.get() and _.set()
          which are not affected by the prototype pollution vulnerability.
          Mitigated by input validation in our API layer.
        expires: '2024-06-01T00:00:00.000Z'
        created: '2024-01-01T00:00:00.000Z'

  SNYK-PYTHON-REQUESTS-123456:
    - '*':
        reason: >
          No fix available. Tracking upstream issue. Internal network only,
          not exposed to untrusted input.
        expires: '2024-03-01T00:00:00.000Z'
        created: '2024-01-01T00:00:00.000Z'
```

---

## npm audit Suppressions

npm does not have a native suppression file. Use one of these approaches:

### Option 1: .nsprc (legacy, npm v6)

```json
{
  "exceptions": [
    "https://nodesecurity.io/advisories/123"
  ]
}
```

### Option 2: audit-ci configuration (recommended)

Install `audit-ci` and use its allowlist:

```json
{
  "allowlist": [
    "GHSA-xxxx-xxxx-xxxx",
    "1234567"
  ],
  "critical": true,
  "high": true,
  "moderate": false,
  "low": false
}
```

### Option 3: Wrapper script exclusions

Use the `npm-audit-wrapper.sh` from this repository with a suppressions file:

```bash
# .npm-audit-suppress
# Format: <advisory-id>  # <reason>
1234567  # Not exploitable - dev dependency only, not in production bundle
GHSA-xxxx-xxxx-xxxx  # Mitigated by WAF
```

---

## OWASP Dependency-Check Suppressions

```xml
<!-- dependency-check-suppressions.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">

    <!--
        CVE-2023-12345
        Reason: Not exploitable - we use version 2.x API only, vulnerability
                affects version 1.x API which we do not call.
        Expires: 2024-06-01
        Ticket: SEC-123
    -->
    <suppress until="2024-06-01Z">
        <notes>
            Not exploitable in our usage. We use version 2.x API only.
            Approved by security team. Ticket: SEC-123
        </notes>
        <cve>CVE-2023-12345</cve>
    </suppress>

</suppressions>
```

---

## Quarterly Review Process

All suppressions must be reviewed every quarter. Use this checklist:

### Review Checklist

```markdown
## Quarterly Suppression Review - Q[N] [YEAR]

Reviewer: [Name]
Date: [Date]
Repository: [Repo name]

### Suppressions Reviewed

| CVE/Advisory | Tool | Reason | Expiry | Action |
|-------------|------|--------|--------|--------|
| CVE-2023-XXXXX | Trivy | Not exploitable | 2024-06-01 | Keep - still valid |
| CVE-2023-YYYYY | Trivy | No fix available | 2024-02-01 | Fix available now - REMOVE |
| CVE-2023-ZZZZZ | Snyk  | Accepted risk   | 2024-01-01 | EXPIRED - re-evaluate |

### Actions Taken

- [ ] Removed expired suppressions
- [ ] Fixed vulnerabilities where fixes are now available
- [ ] Re-approved suppressions that are still valid
- [ ] Updated expiry dates for ongoing suppressions
- [ ] Filed tickets for suppressions needing follow-up
```

### Automated Expiry Checking

Add this to your CI pipeline to catch expired suppressions:

```bash
#!/usr/bin/env bash
# check-suppression-expiry.sh
# Fails if any suppression in .trivyignore has passed its expiry date

TODAY=$(date +%Y-%m-%d)
EXPIRED=0

while IFS= read -r line; do
  # Look for expiry dates in comments
  if echo "$line" | grep -qE "expires:\s*[0-9]{4}-[0-9]{2}-[0-9]{2}"; then
    EXPIRY=$(echo "$line" | \
      grep -oE "expires:\s*[0-9]{4}-[0-9]{2}-[0-9]{2}" | \
      grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}")

    if [[ "$EXPIRY" < "$TODAY" ]]; then
      CVE=$(echo "$line" | grep -oE "CVE-[0-9-]+")
      echo "EXPIRED suppression: $CVE (expired: $EXPIRY)"
      EXPIRED=$((EXPIRED + 1))
    fi
  fi
done < .trivyignore

if [ "$EXPIRED" -gt 0 ]; then
  echo "$EXPIRED suppression(s) have expired and must be reviewed"
  exit 1
fi

echo "All suppressions are within their expiry dates"
```

---

## Anti-Patterns to Avoid

```
# BAD: No reason documented
CVE-2023-12345

# BAD: Vague reason
CVE-2023-12345  # false positive

# BAD: No expiry date
CVE-2023-12345  # Not exploitable in our usage

# BAD: Suppressing entire packages instead of specific CVEs
# (Trivy does not support this, but some tools do - avoid it)

# GOOD: Full documentation
CVE-2023-12345  # Not exploitable: vulnerable function xml.parseString() is
                # never called in our codebase. We only use xml.parse().
                # Verified by code search on 2024-01-15.
                # expires: 2024-07-01 | ticket: SEC-123
```

---

## Suppression Approval Workflow

For suppressions in production-facing code, require security team approval:

1. Developer identifies false positive
2. Developer opens ticket in issue tracker with justification
3. Security team reviews and approves/rejects
4. Developer adds suppression with ticket reference
5. Suppression included in PR - security team reviews in code review
6. Quarterly review process catches expired suppressions

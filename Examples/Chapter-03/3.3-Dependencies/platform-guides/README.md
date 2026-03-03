# Platform-Specific Dependency Scanning Guides
**Book Reference:** Chapter 3, Section 3.3.3.3

## Overview

This directory contains dependency scanning configurations for platforms
beyond GitHub Actions. Each guide covers the recommended free tool for
that platform and includes threshold enforcement matching Table 3.4.

| Platform | Recommended Tool | Cost | File |
|----------|-----------------|------|------|
| GitHub | Dependabot | Free | `../dependabot.yml` |
| GitLab | Built-in scanner | Free (scan) / Ultimate (dashboard) | `../gitlab-dependency-scanning.yml` |
| Azure DevOps | Mend Bolt or Trivy | Free | `azure-devops.yml` |
| Bitbucket | Snyk or Trivy | Free tier | `bitbucket-pipelines.yml` |
| Jenkins | OWASP Dependency-Check | Free | `jenkins-owasp.groovy` |

---

## Quick Start by Platform

### GitHub (2 minutes)

1. Copy `../dependabot.yml` to `.github/dependabot.yml`
2. Go to Settings > Security > Dependabot
3. Enable Dependabot alerts and security updates

### GitLab (1 minute)

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - template: Security/Dependency-Scanning.gitlab-ci.yml
```

### Azure DevOps (5 minutes)

1. Install Mend Bolt from the marketplace
2. Copy `azure-devops.yml` to your repository
3. Add the pipeline in Azure DevOps

### Bitbucket (5 minutes)

1. Add `SNYK_TOKEN` to repository variables (optional - Trivy needs no token)
2. Copy `bitbucket-pipelines.yml` to your repository root

### Jenkins (15 minutes)

1. Install OWASP Dependency-Check plugin
2. Configure the plugin installation directory
3. Copy `jenkins-owasp.groovy` as your Jenkinsfile

---

## Threshold Reference (Table 3.4)

All platform guides enforce these thresholds by default:

| Severity | Threshold | Action |
|----------|-----------|--------|
| Critical | 0 | Always fail |
| High | 5 | Fail if exceeded |
| Medium | 20 | Warn only |
| Low | ignored | No action |

To customise thresholds, create `.security/thresholds.yml` in your
repository root. See `../../security-gate/thresholds.yml` for the
full configuration reference.

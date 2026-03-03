#!/usr/bin/env bash
# =============================================================================
# Typosquatting Check Script
# Book Reference: Chapter 3, Section 3.3.5.1 and 3.3.5.2
# =============================================================================
#
# PURPOSE:
#   Manual and automated typosquatting detection for npm and Python packages.
#   Implements the Table 3.6 red flag checks and Example 3.14 npm info checks.
#
#   Use this script:
#     - Before installing a new package suggested by an AI coding tool
#     - As a pre-commit hook to catch typos before they reach CI
#     - In CI pipelines as a lightweight alternative to the full workflow
#
# USAGE:
#   # Check a single npm package (Example 3.14)
#   ./typosquatting-check.sh --npm reqeusts
#
#   # Check all packages in package.json
#   ./typosquatting-check.sh --npm-all
#
#   # Check a single Python package
#   ./typosquatting-check.sh --python reqeusts
#
#   # Check all packages in requirements.txt
#   ./typosquatting-check.sh --python-all
#
#   # Check both npm and Python
#   ./typosquatting-check.sh --all
#
#   # Install as pre-commit hook
#   ./typosquatting-check.sh --install-hook
#
# EXIT CODES:
#   0 = No suspicious packages found
#   1 = Suspicious packages found - review before installing
#   2 = Script error (missing dependencies, etc.)
# =============================================================================

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

# Table 3.6 thresholds
MIN_WEEKLY_DOWNLOADS=1000       # Flag if fewer than this per week
MIN_AGE_DAYS=30                 # Flag if package is newer than this
REQUIRE_REPOSITORY=true         # Flag if no repository URL

# Known popular npm packages to check for typos of
# Extend this list for your specific tech stack
POPULAR_NPM_PACKAGES=(
    "react" "react-dom" "vue" "angular" "express" "lodash" "axios"
    "moment" "webpack" "babel" "typescript" "eslint" "prettier"
    "jest" "mocha" "chai" "sinon" "nodemon" "dotenv" "cors"
    "body-parser" "mongoose" "sequelize" "knex" "redis" "socket.io"
    "passport" "jsonwebtoken" "bcrypt" "multer" "sharp" "uuid"
    "chalk" "commander" "inquirer" "yargs" "glob" "rimraf"
    "cross-env" "concurrently" "husky" "lint-staged" "semantic-release"
)

# Known popular Python packages to check for typos of
POPULAR_PYTHON_PACKAGES=(
    "requests" "numpy" "pandas" "flask" "django" "sqlalchemy"
    "celery" "redis" "pymongo" "psycopg2" "pillow" "cryptography"
    "paramiko" "pyyaml" "click" "pytest" "boto3" "urllib3"
    "setuptools" "pip" "wheel" "six" "certifi" "charset-normalizer"
    "idna" "packaging" "attrs" "pydantic" "fastapi" "uvicorn"
    "aiohttp" "httpx" "tenacity" "loguru" "rich" "typer"
)

# =============================================================================
# Color output
# =============================================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}ℹ  $*${NC}"; }
success() { echo -e "${GREEN}OK $*${NC}"; }
warning() { echo -e "${YELLOW}WARN $*${NC}"; }
error()   { echo -e "${RED}SUSPICIOUS $*${NC}"; }
bold()    { echo -e "${BOLD}$*${NC}"; }

# =============================================================================
# Argument parsing
# =============================================================================
MODE=""
PACKAGE_NAME=""

parse_args() {
    if [ $# -eq 0 ]; then
        usage
        exit 2
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --npm)
                MODE="npm-single"
                PACKAGE_NAME="$2"
                shift 2
                ;;
            --npm-all)
                MODE="npm-all"
                shift
                ;;
            --python)
                MODE="python-single"
                PACKAGE_NAME="$2"
                shift 2
                ;;
            --python-all)
                MODE="python-all"
                shift
                ;;
            --all)
                MODE="all"
                shift
                ;;
            --install-hook)
                MODE="install-hook"
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "Unknown argument: $1"
                usage
                exit 2
                ;;
        esac
    done
}

usage() {
    cat << EOF
Usage: $(basename "$0") [MODE] [PACKAGE]

Typosquatting detection for npm and Python packages.
Implements Table 3.6 red flag checks from Chapter 3.

MODES:
    --npm <package>     Check a single npm package (Example 3.14)
    --npm-all           Check all packages in package.json
    --python <package>  Check a single Python package
    --python-all        Check all packages in requirements.txt
    --all               Check all npm and Python packages
    --install-hook      Install as a git pre-commit hook

EXAMPLES:
    $(basename "$0") --npm reqeusts
    $(basename "$0") --python reqeusts
    $(basename "$0") --npm-all
    $(basename "$0") --all

EXIT CODES:
    0   No suspicious packages found
    1   Suspicious packages found
    2   Script error
EOF
}

# =============================================================================
# Utility: Calculate string edit distance (Levenshtein)
# Used to detect packages that are 1-2 characters different from popular ones
# =============================================================================
edit_distance() {
    local s="$1"
    local t="$2"
    local m=${#s}
    local n=${#t}

    # Simple length-based heuristic for shell
    # Full Levenshtein is complex in bash - use Python if available
    if command -v python3 &>/dev/null; then
        python3 - "$s" "$t" << 'PYEOF'
import sys

def levenshtein(s, t):
    m, n = len(s), len(t)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s[i-1] == t[j-1]:
                dp[i][j] = dp[i-1][j-1]
            else:
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[m][n]

s, t = sys.argv[1], sys.argv[2]
print(levenshtein(s, t))
PYEOF
    else
        # Fallback: simple length difference
        local diff=$(( ${#s} - ${#t} ))
        echo "${diff#-}"
    fi
}

# =============================================================================
# Check a single npm package against Table 3.6 red flags
# Implements Example 3.14: npm info <package>
# =============================================================================
check_npm_package() {
    local pkg="$1"
    local is_suspicious=false
    local flags=()

    echo ""
    bold "Checking npm package: $pkg"
    echo "----------------------------------------"

    # Example 3.14: npm info reqeusts
    info "Running: npm info $pkg"
    local pkg_info
    pkg_info=$(npm info "$pkg" --json 2>/dev/null || echo "{}")

    if [ "$pkg_info" == "{}" ] || [ -z "$pkg_info" ]; then
        warning "Package '$pkg' not found in npm registry"
        warning "This could mean:"
        warning "  - The package name is misspelled"
        warning "  - The package does not exist"
        warning "  - The package was removed (possibly malicious)"
        return 1
    fi

    # Extract metadata
    local version
    local description
    local repo_url
    local author
    local publish_date
    version=$(echo "$pkg_info" | jq -r '.version // "unknown"' 2>/dev/null)
    description=$(echo "$pkg_info" | jq -r '.description // ""' 2>/dev/null)
    repo_url=$(echo "$pkg_info" | jq -r '.repository.url // ""' 2>/dev/null)
    author=$(echo "$pkg_info" | jq -r '.author.name // .author // "unknown"' 2>/dev/null)
    publish_date=$(echo "$pkg_info" | jq -r '.time.created // ""' 2>/dev/null)

    # Get weekly downloads
    local weekly_downloads
    weekly_downloads=$(curl -s "https://api.npmjs.org/downloads/point/last-week/$pkg" | \
        jq '.downloads // 0' 2>/dev/null || echo "0")

    # Calculate age
    local age_days=9999
    if [ -n "$publish_date" ] && [ "$publish_date" != "null" ]; then
        local publish_ts
        publish_ts=$(date -d "$publish_date" +%s 2>/dev/null || echo "0")
        local now_ts
        now_ts=$(date +%s)
        age_days=$(( (now_ts - publish_ts) / 86400 ))
    fi

    # Print package info (Example 3.14 output)
    echo ""
    echo "  Package     : $pkg"
    echo "  Version     : $version"
    echo "  Author      : $author"
    echo "  Description : ${description:0:80}"
    echo "  Repository  : ${repo_url:-MISSING}"
    echo "  Downloads   : $weekly_downloads/week"
    echo "  Age         : ${age_days} days"
    echo ""

    # Table 3.6 Red Flag checks
    bold "Table 3.6 Red Flag Analysis:"

    # Check: Downloads
    if [ "$weekly_downloads" -lt "$MIN_WEEKLY_DOWNLOADS" ] 2>/dev/null; then
        error "Low downloads: $weekly_downloads/week (threshold: $MIN_WEEKLY_DOWNLOADS)"
        flags+=("low-downloads")
        is_suspicious=true
    else
        success "Downloads: $weekly_downloads/week"
    fi

    # Check: Age
    if [ "$age_days" -lt "$MIN_AGE_DAYS" ] 2>/dev/null; then
        error "New package: ${age_days} days old (threshold: $MIN_AGE_DAYS days)"
        flags+=("new-package")
        is_suspicious=true
    else
        success "Age: ${age_days} days old"
    fi

    # Check: Repository
    if [ -z "$repo_url" ] || [ "$repo_url" == "null" ]; then
        error "No repository URL"
        flags+=("no-repository")
        is_suspicious=true
    else
        success "Repository: $repo_url"
    fi

    # Check: Description
    if [ -z "$description" ] || [ "$description" == "null" ]; then
        warning "No description"
        flags+=("no-description")
    else
        success "Description present"
    fi

    # Check: Version (very early = suspicious)
    if echo "$version" | grep -qE "^0\.0\.[0-9]+$"; then
        error "Very early version: $version"
        flags+=("very-early-version")
        is_suspicious=true
    else
        success "Version: $version"
    fi

    # Check: Typosquatting similarity to popular packages
    echo ""
    bold "Typosquatting Similarity Check:"
    for popular in "${POPULAR_NPM_PACKAGES[@]}"; do
        if [ "$pkg" != "$popular" ]; then
            local dist
            dist=$(edit_distance "$pkg" "$popular")
            if [ "$dist" -le 2 ] 2>/dev/null; then
                error "Similar to popular package '$popular' (edit distance: $dist)"
                flags+=("similar-to-$popular")
                is_suspicious=true
            fi
        fi
    done

    if [ ${#flags[@]} -eq 0 ] || ! $is_suspicious; then
        success "No typosquatting similarity detected"
    fi

    # Final verdict
    echo ""
    bold "Verdict:"
    if $is_suspicious; then
        echo -e "${RED}SUSPICIOUS: $pkg has ${#flags[@]} red flag(s): ${flags[*]}${NC}"
        echo ""
        echo "  Before installing, verify:"
        echo "  1. Is this the correct package name?"
        echo "  2. Check https://www.npmjs.com/package/$pkg"
        echo "  3. Compare with the package you intended to install"
        echo "  4. Check the GitHub repository for legitimacy"
        return 1
    else
        echo -e "${GREEN}CLEAN: $pkg passed all Table 3.6 checks${NC}"
        return 0
    fi
}

# =============================================================================
# Check a single Python package
# =============================================================================
check_python_package() {
    local pkg="$1"
    local is_suspicious=false
    local flags=()

    echo ""
    bold "Checking Python package: $pkg"
    echo "----------------------------------------"

    # Fetch from PyPI
    local pkg_info
    pkg_info=$(curl -s "https://pypi.org/pypi/$pkg/json" 2>/dev/null || echo "{}")

    if ! echo "$pkg_info" | jq -e '.info' &>/dev/null; then
        warning "Package '$pkg' not found on PyPI"
        warning "This could mean the package name is misspelled"
        return 1
    fi

    local version
    local description
    local home_page
    local author
    local requires_python
    version=$(echo "$pkg_info" | jq -r '.info.version // "unknown"' 2>/dev/null)
    description=$(echo "$pkg_info" | jq -r '.info.summary // ""' 2>/dev/null)
    home_page=$(echo "$pkg_info" | jq -r '.info.home_page // ""' 2>/dev/null)
    author=$(echo "$pkg_info" | jq -r '.info.author // "unknown"' 2>/dev/null)
    requires_python=$(echo "$pkg_info" | jq -r '.info.requires_python // ""' 2>/dev/null)

    echo ""
    echo "  Package     : $pkg"
    echo "  Version     : $version"
    echo "  Author      : $author"
    echo "  Description : ${description:0:80}"
    echo "  Homepage    : ${home_page:-MISSING}"
    echo ""

    bold "Table 3.6 Red Flag Analysis:"

    # Check: Homepage/repository
    if [ -z "$home_page" ] || [ "$home_page" == "null" ] || [ "$home_page" == "UNKNOWN" ]; then
        error "No homepage or repository URL"
        flags+=("no-homepage")
        is_suspicious=true
    else
        success "Homepage: $home_page"
    fi

    # Check: Description
    if [ -z "$description" ] || [ "$description" == "null" ]; then
        error "No description"
        flags+=("no-description")
        is_suspicious=true
    else
        success "Description present"
    fi

    # Check: Version
    if echo "$version" | grep -qE "^0\.0\.[0-9]+$"; then
        error "Very early version: $version"
        flags+=("very-early-version")
        is_suspicious=true
    else
        success "Version: $version"
    fi

    # Check: Typosquatting similarity
    echo ""
    bold "Typosquatting Similarity Check:"
    local found_similar=false
    for popular in "${POPULAR_PYTHON_PACKAGES[@]}"; do
        if [ "$pkg" != "$popular" ]; then
            local dist
            dist=$(edit_distance "$pkg" "$popular")
            if [ "$dist" -le 2 ] 2>/dev/null; then
                error "Similar to popular package '$popular' (edit distance: $dist)"
                flags+=("similar-to-$popular")
                is_suspicious=true
                found_similar=true
            fi
        fi
    done

    if ! $found_similar; then
        success "No typosquatting similarity detected"
    fi

    echo ""
    bold "Verdict:"
    if $is_suspicious; then
        echo -e "${RED}SUSPICIOUS: $pkg has ${#flags[@]} red flag(s): ${flags[*]}${NC}"
        echo ""
        echo "  Before installing, verify:"
        echo "  1. Is this the correct package name?"
        echo "  2. Check https://pypi.org/project/$pkg"
        echo "  3. Compare with the package you intended to install"
        return 1
    else
        echo -e "${GREEN}CLEAN: $pkg passed all Table 3.6 checks${NC}"
        return 0
    fi
}

# =============================================================================
# Check all packages in package.json
# =============================================================================
check_npm_all() {
    if [ ! -f package.json ]; then
        echo "No package.json found in current directory"
        exit 2
    fi

    local all_deps
    all_deps=$(jq -r '
        (.dependencies // {}) +
        (.devDependencies // {}) |
        keys[]
    ' package.json 2>/dev/null)

    local total=0
    local suspicious=0

    bold "Checking all npm packages in package.json..."
    echo ""

    for pkg in $all_deps; do
        # Skip scoped packages
        if echo "$pkg" | grep -q "^@"; then
            info "Skipping scoped package: $pkg"
            continue
        fi

        total=$((total + 1))
        if ! check_npm_package "$pkg"; then
            suspicious=$((suspicious + 1))
        fi
    done

    echo ""
    bold "============================================"
    bold "npm Scan Complete"
    bold "============================================"
    echo "  Total checked : $total"
    echo "  Suspicious    : $suspicious"
    bold "============================================"

    [ "$suspicious" -gt 0 ] && return 1 || return 0
}

# =============================================================================
# Check all packages in requirements.txt
# =============================================================================
check_python_all() {
    local req_files
    req_files=$(find . -name "requirements*.txt" -not -path "./.git/*" | head -5)

    if [ -z "$req_files" ]; then
        echo "No requirements.txt files found"
        exit 2
    fi

    local total=0
    local suspicious=0

    for req_file in $req_files; do
        bold "Checking packages in $req_file..."

        local packages
        packages=$(grep -v "^#" "$req_file" | \
            grep -v "^-" | \
            grep -v "^$" | \
            sed 's/[>=<!].*//' | \
            sed 's/\[.*//' | \
            xargs)

        for pkg in $packages; do
            total=$((total + 1))
            if ! check_python_package "$pkg"; then
                suspicious=$((suspicious + 1))
            fi
        done
    done

    echo ""
    bold "============================================"
    bold "Python Scan Complete"
    bold "============================================"
    echo "  Total checked : $total"
    echo "  Suspicious    : $suspicious"
    bold "============================================"

    [ "$suspicious" -gt 0 ] && return 1 || return 0
}

# =============================================================================
# Install as git pre-commit hook
# Runs automatically before every commit that modifies package manifests
# =============================================================================
install_hook() {
    local hook_dir=".git/hooks"
    local hook_file="$hook_dir/pre-commit"
    local script_path
    script_path=$(realpath "$0")

    if [ ! -d "$hook_dir" ]; then
        echo "Not a git repository - cannot install hook"
        exit 2
    fi

    cat > "$hook_file" << HOOK
#!/usr/bin/env bash
# Typosquatting pre-commit hook
# Installed by typosquatting-check.sh
# Book Reference: Chapter 3, Section 3.3.5

CHANGED=\$(git diff --cached --name-only)

NPM_CHANGED=false
PYTHON_CHANGED=false

echo "\$CHANGED" | grep -qE "(package\.json)" && NPM_CHANGED=true
echo "\$CHANGED" | grep -qE "(requirements.*\.txt)" && PYTHON_CHANGED=true

if [ "\$NPM_CHANGED" == "true" ]; then
    echo "package.json changed - running typosquatting check..."
    "$script_path" --npm-all || {
        echo ""
        echo "Suspicious npm packages detected."
        echo "Review the findings above before committing."
        echo "To bypass: git commit --no-verify (use with caution)"
        exit 1
    }
fi

if [ "\$PYTHON_CHANGED" == "true" ]; then
    echo "requirements.txt changed - running typosquatting check..."
    "$script_path" --python-all || {
        echo ""
        echo "Suspicious Python packages detected."
        echo "Review the findings above before committing."
        echo "To bypass: git commit --no-verify (use with caution)"
        exit 1
    }
fi

exit 0
HOOK

    chmod +x "$hook_file"
    echo "Pre-commit hook installed at $hook_file"
    echo "The hook will run typosquatting checks when package manifests change"
}

# =============================================================================
# Main
# =============================================================================
main() {
    parse_args "$@"

    bold "Typosquatting Detection Script"
    bold "Book Reference: Chapter 3, Section 3.3.5"
    echo ""

    local exit_code=0

    case "$MODE" in
        npm-single)
            check_npm_package "$PACKAGE_NAME" || exit_code=1
            ;;
        npm-all)
            check_npm_all || exit_code=1
            ;;
        python-single)
            check_python_package "$PACKAGE_NAME" || exit_code=1
            ;;
        python-all)
            check_python_all || exit_code=1
            ;;
        all)
            check_npm_all    || exit_code=1
            check_python_all || exit_code=1
            ;;
        install-hook)
            install_hook
            ;;
        *)
            usage
            exit 2
            ;;
    esac

    exit $exit_code
}

main "$@"

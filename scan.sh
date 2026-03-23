#!/usr/bin/env bash
set -euo pipefail

# ClawGuard CI Gate — Scan AI prompt files for security vulnerabilities
# Requires: curl, jq (both available on all GitHub-hosted runners)

API_URL="${CLAWGUARD_API_URL:-https://prompttools.co/api/v1/scan}"
API_KEY="${CLAWGUARD_API_KEY:-}"
FILE_PATTERNS="${CLAWGUARD_FILE_PATTERNS:-*.prompt,*.md,*.txt}"
FAIL_ON_CRITICAL="${CLAWGUARD_FAIL_ON_CRITICAL:-false}"
SCAN_ALL="${CLAWGUARD_SCAN_ALL:-false}"

TOTAL_FINDINGS=0
TOTAL_FILES=0
MAX_RISK_SCORE=0
OVERALL_RISK_LEVEL="CLEAN"
HAS_CRITICAL=false

RESULTS_FILE=$(mktemp)
COMMENT_FILE=$(mktemp)
trap 'rm -f "$RESULTS_FILE" "$COMMENT_FILE"' EXIT

# ── Dependency check ─────────────────────────────────────────────────────────

for cmd in curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "::error::Required tool '$cmd' not found. All GitHub-hosted runners include it."
    exit 1
  fi
done

# ── Collect files to scan ────────────────────────────────────────────────────

get_changed_files() {
  if [[ -z "${GITHUB_EVENT_NAME:-}" ]]; then
    # Local testing: scan working directory
    echo "::notice::No GITHUB_EVENT_NAME — running in local mode"
    collect_local_files
    return
  fi

  if [[ "$SCAN_ALL" == "true" ]]; then
    collect_all_files
    return
  fi

  case "${GITHUB_EVENT_NAME}" in
    pull_request|pull_request_target)
      local base_sha
      base_sha=$(jq -r '.pull_request.base.sha' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
      if [[ -z "$base_sha" || "$base_sha" == "null" ]]; then
        echo "::warning::Could not determine PR base SHA, scanning all matching files"
        collect_all_files
        return
      fi
      git fetch --depth=1 origin "$base_sha" 2>/dev/null || true
      git diff --name-only --diff-filter=ACMR "$base_sha"...HEAD 2>/dev/null || \
        git diff --name-only --diff-filter=ACMR HEAD~1 2>/dev/null || \
        collect_all_files
      ;;
    push)
      local before_sha
      before_sha=$(jq -r '.before' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
      if [[ -n "$before_sha" && "$before_sha" != "null" && "$before_sha" != "0000000000000000000000000000000000000000" ]]; then
        git diff --name-only --diff-filter=ACMR "$before_sha"...HEAD 2>/dev/null || \
          git diff --name-only --diff-filter=ACMR HEAD~1 2>/dev/null || true
      else
        git diff --name-only --diff-filter=ACMR HEAD~1 2>/dev/null || true
      fi
      ;;
    *)
      echo "::notice::Event '${GITHUB_EVENT_NAME}' — scanning all matching files"
      collect_all_files
      ;;
  esac
}

collect_all_files() {
  # Find all files matching patterns in the repo
  IFS=',' read -ra patterns <<< "$FILE_PATTERNS"
  for pattern in "${patterns[@]}"; do
    pattern=$(echo "$pattern" | xargs) # trim whitespace
    find . -type f -name "$pattern" -not -path './.git/*' 2>/dev/null || true
  done | sort -u
}

collect_local_files() {
  collect_all_files
}

file_matches_pattern() {
  local file="$1"
  local basename
  basename=$(basename "$file")

  IFS=',' read -ra patterns <<< "$FILE_PATTERNS"
  for pattern in "${patterns[@]}"; do
    pattern=$(echo "$pattern" | xargs) # trim whitespace
    # Use bash pattern matching (fnmatch-style)
    # shellcheck disable=SC2254
    case "$basename" in
      $pattern) return 0 ;;
    esac
  done
  return 1
}

# ── API call ─────────────────────────────────────────────────────────────────

scan_file() {
  local file="$1"
  local content
  local response
  local http_code

  if [[ ! -f "$file" ]]; then
    return
  fi

  # Skip empty files
  if [[ ! -s "$file" ]]; then
    return
  fi

  # Skip binary files (check for null bytes — works on all runners)
  if grep -Plq '\x00' "$file" 2>/dev/null; then
    echo "  $file — skipped (binary)"
    return
  fi

  # Read file content (limit to 5000 chars to stay within API limits)
  content=$(head -c 5000 "$file")

  # Build JSON payload safely using jq
  local payload
  payload=$(jq -n --arg text "$content" --arg source "$file" \
    '{"text": $text, "source": $source}')

  # Call the API
  local tmpfile
  tmpfile=$(mktemp)

  http_code=$(curl -s -o "$tmpfile" -w '%{http_code}' \
    -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: ${API_KEY}" \
    --max-time 30 --retry 3 --retry-delay 2 --retry-max-time 60 \
    -d "$payload" 2>/dev/null) || {
    echo "::warning::API request failed for $file (network error)"
    rm -f "$tmpfile"
    return
  }

  response=$(cat "$tmpfile")
  rm -f "$tmpfile"

  # Retry on 429 (rate limit) with exponential backoff
  local retries=0
  local max_retries=3
  while [[ "$http_code" == "429" && "$retries" -lt "$max_retries" ]]; do
    retries=$((retries + 1))
    local wait_time=$((retries * 5))
    echo "::notice::Rate limited on $file — retry $retries/$max_retries in ${wait_time}s"
    sleep "$wait_time"
    tmpfile=$(mktemp)
    http_code=$(curl -s -o "$tmpfile" -w '%{http_code}' \
      -X POST "$API_URL" \
      -H "Content-Type: application/json" \
      -H "X-API-Key: ${API_KEY}" \
      --max-time 30 \
      -d "$payload" 2>/dev/null) || {
      echo "::warning::API request failed for $file on retry $retries (network error)"
      rm -f "$tmpfile"
      return
    }
    response=$(cat "$tmpfile")
    rm -f "$tmpfile"
  done

  if [[ "$http_code" != "200" ]]; then
    local error_msg
    error_msg=$(echo "$response" | jq -r '.message // .error // "Unknown error"' 2>/dev/null || echo "HTTP $http_code")
    echo "::warning::API returned $http_code for $file: $error_msg"
    return
  fi

  # Parse response
  local clean findings_count risk_score severity
  clean=$(echo "$response" | jq -r '.clean' 2>/dev/null || echo "true")
  findings_count=$(echo "$response" | jq -r '.findings_count // 0' 2>/dev/null || echo "0")
  risk_score=$(echo "$response" | jq -r '.risk_score // 0' 2>/dev/null || echo "0")
  severity=$(echo "$response" | jq -r '.severity // "CLEAN"' 2>/dev/null || echo "CLEAN")

  TOTAL_FILES=$((TOTAL_FILES + 1))
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + findings_count))

  if [[ "$risk_score" -gt "$MAX_RISK_SCORE" ]]; then
    MAX_RISK_SCORE=$risk_score
  fi

  # Track highest severity
  update_risk_level "$severity"

  if [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]]; then
    HAS_CRITICAL=true
  fi

  # Store result for the comment
  if [[ "$clean" != "true" ]]; then
    {
      echo "FILE:$file"
      echo "SCORE:$risk_score"
      echo "SEVERITY:$severity"
      echo "COUNT:$findings_count"
      echo "$response" | jq -r '.findings[]? | "  - **\(.severity)** [\(.category)] \(.pattern_name): `\(.matched_text[0:80])`"' 2>/dev/null || true
      echo "---"
    } >> "$RESULTS_FILE"

    echo "::warning file=$file::ClawGuard: $findings_count finding(s), risk=$severity (score $risk_score/10)"
  else
    echo "  $file — clean"
  fi
}

update_risk_level() {
  local new_level="$1"
  local -A level_order=([CLEAN]=0 [LOW]=1 [MEDIUM]=2 [HIGH]=3 [CRITICAL]=4)
  local current_val="${level_order[$OVERALL_RISK_LEVEL]:-0}"
  local new_val="${level_order[$new_level]:-0}"
  if [[ "$new_val" -gt "$current_val" ]]; then
    OVERALL_RISK_LEVEL="$new_level"
  fi
}

# ── Build PR comment ─────────────────────────────────────────────────────────

build_comment() {
  local icon
  case "$OVERALL_RISK_LEVEL" in
    CLEAN)    icon="white_check_mark" ;;
    LOW)      icon="large_blue_circle" ;;
    MEDIUM)   icon="warning" ;;
    HIGH)     icon="orange_circle" ;;
    CRITICAL) icon="red_circle" ;;
    *)        icon="grey_question" ;;
  esac

  {
    echo "## :shield: ClawGuard AI Security Scan"
    echo ""

    if [[ "$TOTAL_FILES" -eq 0 ]]; then
      echo ":${icon}: **No matching files found to scan.**"
      echo ""
      echo "Patterns checked: \`${FILE_PATTERNS}\`"
    elif [[ "$TOTAL_FINDINGS" -eq 0 ]]; then
      echo ":${icon}: **All clear** — ${TOTAL_FILES} file(s) scanned, no threats detected."
    else
      echo ":${icon}: **${TOTAL_FINDINGS} finding(s)** across ${TOTAL_FILES} file(s) | Risk: **${OVERALL_RISK_LEVEL}** (${MAX_RISK_SCORE}/10)"
      echo ""
      echo "<details>"
      echo "<summary>View findings</summary>"
      echo ""
      echo "| File | Risk | Findings |"
      echo "|------|------|----------|"

      # Parse results file
      local current_file="" current_severity="" current_count=""
      while IFS= read -r line; do
        case "$line" in
          FILE:*)
            current_file="${line#FILE:}"
            ;;
          SEVERITY:*)
            current_severity="${line#SEVERITY:}"
            ;;
          COUNT:*)
            current_count="${line#COUNT:}"
            echo "| \`${current_file}\` | ${current_severity} | ${current_count} |"
            ;;
        esac
      done < "$RESULTS_FILE"

      echo ""
      echo "#### Details"
      echo ""

      current_file=""
      while IFS= read -r line; do
        case "$line" in
          FILE:*)
            current_file="${line#FILE:}"
            echo "**\`${current_file}\`**"
            ;;
          "  - "*)
            echo "$line"
            ;;
          "---")
            echo ""
            ;;
          SCORE:*|SEVERITY:*|COUNT:*)
            # skip metadata lines
            ;;
        esac
      done < "$RESULTS_FILE"

      echo "</details>"
    fi

    echo ""
    echo "---"
    echo "<sub>Scanned by <a href=\"https://github.com/joergmichno/clawguard\">ClawGuard</a> | <a href=\"https://prompttools.co\">Get your free API key</a></sub>"
  } > "$COMMENT_FILE"
}

post_comment() {
  if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo "::notice::No GITHUB_TOKEN — skipping PR comment"
    return
  fi

  if [[ "${GITHUB_EVENT_NAME:-}" != "pull_request" && "${GITHUB_EVENT_NAME:-}" != "pull_request_target" ]]; then
    echo "::notice::Not a pull_request event — skipping PR comment"
    return
  fi

  local pr_number
  pr_number=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
  if [[ -z "$pr_number" ]]; then
    echo "::warning::Could not determine PR number — skipping comment"
    return
  fi

  local repo="${GITHUB_REPOSITORY}"
  local comment_body
  comment_body=$(cat "$COMMENT_FILE")

  # Check for existing ClawGuard comment to update instead of creating a new one
  local existing_comment_id
  existing_comment_id=$(curl -s \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/${repo}/issues/${pr_number}/comments" \
    --max-time 10 2>/dev/null | \
    jq -r '[.[] | select(.body | startswith("## :shield: ClawGuard"))] | last | .id // empty' 2>/dev/null || echo "")

  if [[ -n "$existing_comment_id" ]]; then
    # Update existing comment
    curl -s -X PATCH \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/${repo}/issues/comments/${existing_comment_id}" \
      -d "$(jq -n --arg body "$comment_body" '{"body": $body}')" \
      --max-time 10 > /dev/null 2>&1 || echo "::warning::Failed to update PR comment"
    echo "  Updated existing PR comment"
  else
    # Create new comment
    curl -s -X POST \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/${repo}/issues/${pr_number}/comments" \
      -d "$(jq -n --arg body "$comment_body" '{"body": $body}')" \
      --max-time 10 > /dev/null 2>&1 || echo "::warning::Failed to post PR comment"
    echo "  Posted PR comment"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

echo "ClawGuard CI Gate"
echo "================="
echo "  API:      ${API_URL}"
echo "  Patterns: ${FILE_PATTERNS}"
echo "  Mode:     $([ "$SCAN_ALL" = "true" ] && echo "all files" || echo "changed files only")"
echo ""

# Validate API key
if [[ -z "$API_KEY" ]]; then
  echo "::error::No API key provided. Set the 'api_key' input or CLAWGUARD_API_KEY secret."
  echo "::error::Get a free key at https://prompttools.co"
  exit 1
fi

# Collect files
mapfile -t all_files < <(get_changed_files)

# Filter by pattern
files_to_scan=()
for f in "${all_files[@]}"; do
  [[ -z "$f" ]] && continue
  # Normalize path (remove leading ./)
  f="${f#./}"
  if file_matches_pattern "$f"; then
    files_to_scan+=("$f")
  fi
done

echo "  Files to scan: ${#files_to_scan[@]}"
echo ""

if [[ ${#files_to_scan[@]} -eq 0 ]]; then
  echo "No matching files found."
  TOTAL_FILES=0
  build_comment
  post_comment

  # Set outputs
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "findings_count=0" >> "$GITHUB_OUTPUT"
    echo "risk_level=CLEAN" >> "$GITHUB_OUTPUT"
    echo "max_risk_score=0" >> "$GITHUB_OUTPUT"
    echo "files_scanned=0" >> "$GITHUB_OUTPUT"
  fi
  exit 0
fi

# Scan each file
for file in "${files_to_scan[@]}"; do
  echo "Scanning: $file"
  scan_file "$file"
done

echo ""
echo "Results"
echo "-------"
echo "  Files scanned:  $TOTAL_FILES"
echo "  Total findings: $TOTAL_FINDINGS"
echo "  Risk level:     $OVERALL_RISK_LEVEL"
echo "  Max risk score: $MAX_RISK_SCORE/10"

# Build and post comment
build_comment
post_comment

# Set outputs
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "findings_count=$TOTAL_FINDINGS" >> "$GITHUB_OUTPUT"
  echo "risk_level=$OVERALL_RISK_LEVEL" >> "$GITHUB_OUTPUT"
  echo "max_risk_score=$MAX_RISK_SCORE" >> "$GITHUB_OUTPUT"
  echo "files_scanned=$TOTAL_FILES" >> "$GITHUB_OUTPUT"
fi

# Fail if critical findings detected and fail_on_critical is true
if [[ "$FAIL_ON_CRITICAL" == "true" && "$HAS_CRITICAL" == "true" ]]; then
  echo ""
  echo "::error::CRITICAL/HIGH severity findings detected. Failing the check (fail_on_critical=true)."
  exit 1
fi

echo ""
echo "Done."

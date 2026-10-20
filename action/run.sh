#!/usr/bin/env bash
set -Eeuo pipefail

# disdetta composite action.
#
# The script downloads the release archive of the requested tag for the runner
# operating system and architecture, verifies it against the signed checksum
# file, and runs the scanner. The scanner exit code is passed through
# unchanged, so a workflow can gate a pull request on the findings.
#
# Exit codes of this script:
#   0, 1, 2, 3  the exit code of disdetta
#   64          invalid action input
#   70          download, checksum, signature, platform or setup failure
#
# Only the exit code of the scanner reaches the caller. A failure of the
# action itself never ends with the code of the command that failed: every
# step checks the status of the commands it runs and ends with 64 or 70, so
# a broken run never looks like a scanner finding.
#
# Every command of a function is checked where it is run. Bash applies
# neither errexit nor the ERR trap inside a function called from a
# conditional context: `if ! verify_archive_checksum` would hide the
# failure of the commands of the function, and a command substitution
# that fails quietly would let a broken archive through. Every command
# substitution and every pipeline is therefore checked explicitly, and a
# pipeline is read with pipefail, so the failure of any of its stages is
# seen.
#
# No step reads a file it did not write itself: curl starts with -q, so
# that it never reads the .curlrc of the runner, and the listings of an
# archive are written to files of the work directory instead of being
# read from a process substitution, whose failure is never seen.
#
# Every function that prints an answer checks the write of that answer:
# a printf that fails is never taken for a printed answer, so a function
# called in a conditional context cannot hide a failed output.

readonly SIGNING_IDENTITY="https://github.com/HarnageaGabriel/disdetta/.github/workflows/release.yml@refs/tags/"
readonly OIDC_ISSUER="https://token.actions.githubusercontent.com"

# work_dir holds the downloaded assets. It is a global so that the cleanup
# trap can reach it from any exit path.
work_dir=""

cleanup() {
  if [[ -n "${work_dir}" ]]; then
    rm -rf -- "${work_dir}" || true
  fi
}
trap cleanup EXIT

usage_error() {
  echo "$1" >&2
  exit 64
}

action_error() {
  echo "$1" >&2
  exit 70
}

# on_error is the single place where an unexpected failure of the action
# becomes an exit code. It runs for every command that fails outside a
# guarded context, and it ends the run with 70: the code of the failed
# command (1, 2, 50, 80...) would look like a scanner finding.
on_error() {
  local status=$1
  local command=$2
  if [[ -n "${DISDETTA_GITHUB_TOKEN:-}" ]]; then
    command=${command//"${DISDETTA_GITHUB_TOKEN}"/<redacted>}
  fi
  echo "disdetta action failed: '${command}' exited ${status}" >&2
  exit 70
}
trap 'on_error "$?" "${BASH_COMMAND}"' ERR

# json_probe reads a one line JSON document with a runtime and prints the
# line it found. It fails when the runtime is missing, when it cannot run,
# or when it does not read the document as JSON.
json_probe() {
  local runtime=$1
  case "${runtime}" in
    python3|python)
      if ! "${runtime}" -c '
import json, sys
try:
    document = json.loads(sys.stdin.read())
except ValueError:
    sys.exit(2)
if not isinstance(document, dict) or document.get("probe") != "ok":
    sys.exit(3)
sys.stdout.write("ok\n")
'; then
        return 1
      fi
      ;;
    node|nodejs)
      if ! "${runtime}" -e '
const fs = require("fs");
let document;
try {
  document = JSON.parse(fs.readFileSync(0, "utf8"));
} catch (error) {
  process.exit(2);
}
if (!document || document.probe !== "ok") process.exit(3);
process.stdout.write("ok\n");
'; then
        return 1
      fi
      ;;
    *)
      return 1
      ;;
  esac
  return 0
}

# json_runtime prints the name of a small runtime able to read JSON. Every
# candidate is tried on a real input: a runtime that exists but cannot run,
# like the Microsoft Store stub of python3 on Windows, is skipped.
json_runtime() {
  local candidate output
  local probe_input='{"probe":"ok"}'
  local probe_output='ok'
  for candidate in python3 python node nodejs; do
    command -v "${candidate}" >/dev/null 2>&1 || continue
    if ! output=$(printf '%s\n' "${probe_input}" | json_probe "${candidate}" 2>/dev/null); then
      continue
    fi
    # python on Windows writes CRLF: the carriage return is not part of the
    # answer of the probe.
    output=${output//$'\r'/}
    [[ "${output}" == "${probe_output}" ]] || continue
    printf '%s\n' "${candidate}" || return 1
    return 0
  done
  echo "no usable JSON runtime: tried python3, python, node, nodejs" >&2
  return 1
}

# release_page_fields prints one line per release of a GitHub releases API
# response, as "<tag>|<draft>|<prerelease>".
#
# The page is read strictly, and it fails closed. Every record has to be
# an object with a tag name that is a string and with a draft flag and a
# prerelease flag that are booleans. A record that is not an object, a
# field that is missing or that has another type, and a page that is not
# a list are refused: a record read as a stable release because one of
# its fields was malformed would name an archive that nobody signed.
# The whole page is refused, never only the malformed record.
release_page_fields() {
  local page_file=$1
  local runtime output
  if ! runtime=$(json_runtime); then
    echo "reading the GitHub API response needs a working JSON runtime; pin an exact version instead" >&2
    return 1
  fi
  case "${runtime}" in
    python3|python)
      if ! output=$("${runtime}" -c '
import json, sys


def refuse(reason):
    sys.stderr.write("the releases API response is malformed: " + reason + "\n")
    sys.exit(3)


try:
    with open(sys.argv[1], "rb") as handle:
        page = json.load(handle)
except OSError:
    refuse("the response cannot be read")
except ValueError:
    refuse("the response is not valid JSON")
if not isinstance(page, list):
    refuse("the response is not a list of releases")
for release in page:
    if not isinstance(release, dict):
        refuse("a record of the list is not an object")
    tag = release.get("tag_name")
    draft = release.get("draft")
    prerelease = release.get("prerelease")
    if not isinstance(tag, str):
        refuse("a record of the list has no tag name")
    if not isinstance(draft, bool) or not isinstance(prerelease, bool):
        refuse("a record of the list has no boolean draft and prerelease")
    sys.stdout.write(tag + "|" + ("true" if draft else "false") + "|" + ("true" if prerelease else "false") + "\n")
' "${page_file}"); then
        return 1
      fi
      ;;
    node|nodejs)
      if ! output=$("${runtime}" -e '
const fs = require("fs");

function refuse(reason) {
  // The message is written on the file descriptor itself: a write that is
  // buffered would be lost when the process ends.
  fs.writeSync(2, "the releases API response is malformed: " + reason + "\n");
  process.exit(3);
}

let page;
try {
  page = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
} catch (error) {
  refuse("the response is not valid JSON");
}
if (!Array.isArray(page)) refuse("the response is not a list of releases");
for (const release of page) {
  if (release === null || typeof release !== "object" || Array.isArray(release)) {
    refuse("a record of the list is not an object");
  }
  const tag = release.tag_name;
  const draft = release.draft;
  const prerelease = release.prerelease;
  if (typeof tag !== "string") refuse("a record of the list has no tag name");
  if (typeof draft !== "boolean" || typeof prerelease !== "boolean") {
    refuse("a record of the list has no boolean draft and prerelease");
  }
  process.stdout.write(tag + "|" + (draft ? "true" : "false") + "|" + (prerelease ? "true" : "false") + "\n");
}
' "${page_file}"); then
        return 1
      fi
      ;;
    *)
      echo "unsupported JSON runtime: ${runtime}" >&2
      return 1
      ;;
  esac
  printf '%s\n' "${output}" || return 1
  return 0
}

# api_get prints the body of an api.github.com request. The token is passed
# through a curl config read from stdin, so it never appears in argv. Use it
# for api.github.com calls only: release asset downloads run without an
# Authorization header.
#
# Every call to curl starts with -q: curl reads its configuration file
# (.curlrc, in CURL_HOME or in HOME) unless -q is the very first argument.
# An inherited .curlrc can turn the tracing on, and the trace prints the
# Authorization header of the config in the log.
api_get() {
  local url=$1
  if [[ -n "${DISDETTA_GITHUB_TOKEN:-}" ]]; then
    if ! printf 'header = "Authorization: Bearer %s"\n' "${DISDETTA_GITHUB_TOKEN}" |
      curl -q --fail --location --silent --show-error --retry 3 -K - "${url}"; then
      return 1
    fi
  else
    if ! curl -q --fail --location --silent --show-error --retry 3 "${url}"; then
      return 1
    fi
  fi
  return 0
}

# download_asset saves a release asset. No credential is sent: release
# assets are public. The call starts with -q, like every call to curl.
download_asset() {
  local url=$1
  local output=$2
  if ! curl -q --fail --location --silent --show-error --retry 3 --output "${output}" "${url}"; then
    return 1
  fi
  return 0
}

# resolve_major_release prints the latest stable v<major>.x.y release tag. The
# release list is read page by page from the GitHub API, and the highest
# matching tag wins.
resolve_major_release() {
  local major=$1
  local repository=$2
  local directory=$3
  local page=1 max_pages=20
  local page_file fields line_count
  local best_tag="" best_minor=-1 best_patch=-1
  local tag draft prerelease minor patch

  while [[ "${page}" -le "${max_pages}" ]]; do
    page_file="${directory}/releases-${page}.json"
    if ! api_get "https://api.github.com/repos/${repository}/releases?per_page=100&page=${page}" > "${page_file}"; then
      echo "failed to list the releases of ${repository}" >&2
      return 1
    fi
    if ! fields=$(release_page_fields "${page_file}"); then
      echo "unexpected GitHub releases API response" >&2
      return 1
    fi
    # A runtime that writes CRLF, like python on Windows, must not change
    # the fields.
    fields=${fields//$'\r'/}
    if [[ -z "${fields}" ]]; then
      line_count=0
    else
      # The count tells whether another page has to be read: a count that
      # cannot be read stops the run, it never ends the list early.
      if ! line_count=$(printf '%s\n' "${fields}" | wc -l | tr -d '[:space:]'); then
        echo "failed to count the releases of ${repository}" >&2
        return 1
      fi
      if [[ ! "${line_count}" =~ ^[0-9]+$ ]]; then
        echo "failed to count the releases of ${repository}" >&2
        return 1
      fi
    fi
    while IFS='|' read -r tag draft prerelease; do
      [[ -n "${tag}" ]] || continue
      [[ "${draft}" == "false" && "${prerelease}" == "false" ]] || continue
      if [[ "${tag}" =~ ^v${major}\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
        minor=${BASH_REMATCH[1]}
        patch=${BASH_REMATCH[2]}
        if (( minor > best_minor )) || { (( minor == best_minor )) && (( patch > best_patch )); }; then
          best_minor=${minor}
          best_patch=${patch}
          best_tag=${tag}
        fi
      fi
    done <<< "${fields}"
    if [[ "${line_count}" -lt 100 ]]; then
      break
    fi
    page=$((page + 1))
  done
  if [[ "${page}" -gt "${max_pages}" ]]; then
    echo "warning: stopped after ${max_pages} pages of releases" >&2
  fi
  if [[ -z "${best_tag}" ]]; then
    echo "no stable v${major}.x.y release found in ${repository}" >&2
    return 1
  fi
  printf '%s\n' "${best_tag}" || return 1
  return 0
}

# verify_archive_checksum compares the archive with the SHA-256 sum published
# in checksums.txt.
#
# The entry has to name the archive exactly. The record of the checksum file
# is "<hash><separator><name>", where the separator is two spaces or a space
# and an asterisk, and the name is the rest of the line. A record that names
# another file, that holds more fields, or that is written twice for the
# archive is not the entry of the archive, and it is refused.
verify_archive_checksum() {
  local archive_path=$1
  local checksums_path=$2
  local archive_name=$3
  local expected actual

  if ! expected=$(awk -v file="${archive_name}" '
    {
      line = $0
      sub(/\r$/, "", line)
      if (length(line) < 67) next
      hash = substr(line, 1, 64)
      if (hash ~ /[^0-9a-fA-F]/) next
      rest = substr(line, 65)
      if (substr(rest, 1, 2) == "  ") {
        name = substr(rest, 3)
      } else if (substr(rest, 1, 2) == " *") {
        name = substr(rest, 3)
      } else {
        next
      }
      if (name != file) next
      count++
      value = hash
    }
    END {
      if (count == 1) { print tolower(value); exit 0 }
      exit 1
    }
  ' "${checksums_path}"); then
    echo "checksums.txt has no unique SHA-256 entry for ${archive_name}" >&2
    return 1
  fi
  if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "checksums.txt has no unique SHA-256 entry for ${archive_name}" >&2
    return 1
  fi
  # The status of the hasher is checked: a hasher that prints a sum and
  # then fails must never be taken for a sum that was read. The sum is
  # lowered on both sides, because the checksum file may hold it in upper
  # case.
  if command -v sha256sum >/dev/null 2>&1; then
    if ! actual=$(sha256sum < "${archive_path}" | awk '{print $1}' | tr 'A-F' 'a-f'); then
      echo "the SHA-256 sum of ${archive_name} cannot be read" >&2
      return 1
    fi
  else
    if ! actual=$(shasum -a 256 < "${archive_path}" | awk '{print $1}' | tr 'A-F' 'a-f'); then
      echo "the SHA-256 sum of ${archive_name} cannot be read" >&2
      return 1
    fi
  fi
  if [[ ! "${actual}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "the SHA-256 sum of ${archive_name} cannot be read" >&2
    return 1
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    echo "SHA-256 verification failed for ${archive_name}" >&2
    return 1
  fi
  return 0
}

# archive_listing prints one "<type><TAB><name>" line per member of the
# archive. The type is the type of the member: "-" for a regular file, "l"
# for a symbolic link. The names come from the plain listing and the types
# from the verbose one; both list the members in the same order.
#
# The two listings are written to files of the work directory and read back
# from those files. A process substitution hides the failure of the command
# that produced the listing: the reader would see a listing that stops in
# the middle as a complete one, and a member that comes after the cut
# would never be seen.
archive_listing() {
  local archive_path=$1
  local listing_dir=$2
  local names_file types_file
  local name_count type_count

  names_file="${listing_dir}/member-names"
  types_file="${listing_dir}/member-types"

  case "${archive_path}" in
    *.zip)
      if ! unzip -Z1 "${archive_path}" > "${names_file}"; then
        return 1
      fi
      if ! unzip -Z "${archive_path}" | archive_types > "${types_file}"; then
        return 1
      fi
      ;;
    *)
      if ! tar -tzf "${archive_path}" > "${names_file}"; then
        return 1
      fi
      if ! tar -tvzf "${archive_path}" | archive_types > "${types_file}"; then
        return 1
      fi
      ;;
  esac

  # A count that cannot be read is a failure: it never ends the listing
  # early and never hides a member.
  if ! name_count=$(wc -l < "${names_file}" | tr -d '[:space:]'); then
    return 1
  fi
  if ! type_count=$(wc -l < "${types_file}" | tr -d '[:space:]'); then
    return 1
  fi
  if [[ ! "${name_count}" =~ ^[0-9]+$ || ! "${type_count}" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if [[ "${name_count}" != "${type_count}" ]]; then
    return 1
  fi
  if ! paste "${types_file}" "${names_file}"; then
    return 1
  fi
  return 0
}

# archive_types reads the verbose listing of an archive and prints the type
# of every member. The listing of GNU tar and the listing of BSD tar both
# start with the mode of the member. A zip made without unix attributes
# shows "?" as the type: it cannot hold a link, so it is read as a regular
# file.
archive_types() {
  awk '
    {
      type = substr($1, 1, 1)
      if (type !~ /^[-dlhbpsc?]$/) next
      if (type != "?" && length($1) < 10) next
      if (type == "?") type = "-"
      print type
    }
  '
}

# allowed_archive_member tells whether a member of a release archive is one
# of the files a release holds. The scanner of the platform is the only
# binary allowed: the archive of a platform never holds the scanner of
# another one.
#
# The names are compared exactly. A member named "./disdetta" is not the
# scanner of the release and is refused: the extraction names the member
# exactly, and the archives of the releases never hold a "./" prefix.
allowed_archive_member() {
  local binary=$1
  local name=$2
  case "${name}" in
    "${binary}") return 0 ;;
    LICENSE|NOTICE|README.md) return 0 ;;
    *) return 1 ;;
  esac
}

# validate_archive refuses an archive that holds a member that escapes the
# extraction directory, that is not a regular file, that is not one of the
# expected files, or that appears more than once. The scanner of the
# platform has to be there exactly once.
validate_archive() {
  local listing=$1
  local binary=$2
  local type name
  local found=0
  local seen=""

  while IFS=$'\t' read -r type name; do
    [[ -n "${name}" ]] || continue
    case "${name}" in
      /*|\\*|[A-Za-z]:*)
        echo "the archive holds the absolute path '${name}'" >&2
        return 1
        ;;
      ..|../*|*/..|*/../*)
        echo "the archive holds the member '${name}' with a '..' component" >&2
        return 1
        ;;
    esac
    if [[ "${type}" != "-" ]]; then
      echo "the archive holds the member '${name}' that is not a regular file" >&2
      return 1
    fi
    if [[ "${seen}" == *$'\n'"${name}"$'\n'* ]]; then
      echo "the archive holds the member '${name}' more than once" >&2
      return 1
    fi
    seen="${seen}"$'\n'"${name}"$'\n"'
    case "${name}" in
      disdetta|disdetta.exe)
        if [[ "${name}" != "${binary}" ]]; then
          echo "the archive holds the scanner of another platform: '${name}'" >&2
          return 1
        fi
        ;;
    esac
    if ! allowed_archive_member "${binary}" "${name}"; then
      echo "the archive holds the unexpected member '${name}'" >&2
      return 1
    fi
    if [[ "${name}" == "${binary}" ]]; then
      found=$((found + 1))
    fi
  done <<< "${listing}"

  if [[ "${found}" -ne 1 ]]; then
    echo "the archive does not hold ${binary}" >&2
    return 1
  fi
  return 0
}

# extract_binary extracts the scanner from the release archive. The members
# of the archive are checked first, and only the binary is extracted. The
# listings of the members are written to the work directory.
extract_binary() {
  local archive_path=$1
  local binary=$2
  local destination=$3
  local listing

  if ! listing=$(archive_listing "${archive_path}" "${work_dir}"); then
    echo "the members of ${archive_path##*/} cannot be read" >&2
    return 1
  fi
  if ! validate_archive "${listing}" "${binary}"; then
    return 1
  fi
  case "${archive_path}" in
    *.zip)
      if ! unzip -q -o "${archive_path}" "${binary}" -d "${destination}"; then
        return 1
      fi
      ;;
    *)
      if ! tar -xzf "${archive_path}" -C "${destination}" "${binary}"; then
        return 1
      fi
      ;;
  esac
  if ! chmod +x "${destination}/${binary}"; then
    return 1
  fi
  return 0
}

main() {
  # github.token is masked by the runner. Keep the token out of every child
  # process: curl gets it only as a header, and only for the API call that
  # resolves a floating tag.
  export -n DISDETTA_GITHUB_TOKEN 2>/dev/null || true

  local format fail_on path repository requested_version version major
  local os arch archive base_url executable status cli_format sarif_file
  local binary runner_temp uname_s uname_m sarif_dir sarif_marker explanation
  local -a args

  format=${DISDETTA_INPUT_FORMAT:-}
  fail_on=${DISDETTA_INPUT_FAIL_ON:-}
  path=${DISDETTA_INPUT_PATH:-}
  repository=${DISDETTA_ACTION_REPOSITORY:-}

  case "${format}" in
    text|json|sarif) ;;
    *) usage_error "format must be text, json or sarif" ;;
  esac
  case "${fail_on}" in
    none|low|medium|high) ;;
    *) usage_error "fail-on must be none, low, medium or high" ;;
  esac
  if [[ ! "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    usage_error "invalid action repository"
  fi
  if [[ -z "${path}" ]]; then
    usage_error "path must not be empty"
  fi
  # A path that starts with a dash is a path: it is passed to the scanner
  # after a double dash, in a quoted array.

  runner_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
  if ! work_dir=$(mktemp -d "${runner_temp%/}/disdetta.XXXXXX"); then
    action_error "failed to create the work directory under ${runner_temp}"
  fi

  requested_version=${DISDETTA_VERSION:-${DISDETTA_ACTION_REF:-}}
  if [[ "${requested_version}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    version=${requested_version}
  elif [[ "${requested_version}" =~ ^v(0|[1-9][0-9]*)$ ]]; then
    major=${BASH_REMATCH[1]}
    if ! version=$(resolve_major_release "${major}" "${repository}" "${work_dir}"); then
      exit 70
    fi
  elif [[ "${requested_version}" =~ ^[0-9a-fA-F]{40}$ ]]; then
    usage_error "the action is pinned by commit SHA: set the version input to an exact release tag, for example v0.1.0"
  else
    usage_error "version must be an exact vMAJOR.MINOR.PATCH tag or a vMAJOR alias"
  fi

  # Every API call is done: drop the token before any release asset download.
  unset DISDETTA_GITHUB_TOKEN

  # The platform is read with its status checked: a uname that prints a
  # platform and then fails must never be taken for a platform that was
  # read.
  if ! uname_s=$(uname -s); then
    action_error "failed to detect the operating system of the runner"
  fi
  case "${uname_s}" in
    Linux*) os=linux ;;
    Darwin*) os=darwin ;;
    MINGW*|MSYS*|CYGWIN*) os=windows ;;
    *) action_error "unsupported runner OS: ${uname_s}" ;;
  esac
  if ! uname_m=$(uname -m); then
    action_error "failed to detect the architecture of the runner"
  fi
  case "${uname_m}" in
    x86_64|amd64) arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) action_error "unsupported runner architecture: ${uname_m}" ;;
  esac
  if [[ "${os}" == windows && "${arch}" == arm64 ]]; then
    action_error "no release is published for windows/arm64"
  fi

  archive="disdetta_${version}_${os}_${arch}.tar.gz"
  if [[ "${os}" == windows ]]; then
    archive="disdetta_${version}_${os}_${arch}.zip"
  fi
  base_url="https://github.com/${repository}/releases/download/${version}"

  if ! download_asset "${base_url}/${archive}" "${work_dir}/${archive}"; then
    action_error "failed to download ${archive} for ${version}"
  fi
  if ! download_asset "${base_url}/checksums.txt" "${work_dir}/checksums.txt"; then
    action_error "failed to download checksums.txt for ${version}"
  fi
  if ! download_asset "${base_url}/checksums.txt.sigstore.json" "${work_dir}/checksums.txt.sigstore.json"; then
    action_error "failed to download checksums.txt.sigstore.json for ${version}"
  fi

  if ! command -v cosign >/dev/null 2>&1; then
    action_error "cosign is required to verify checksums.txt"
  fi
  if ! cosign verify-blob \
    --bundle "${work_dir}/checksums.txt.sigstore.json" \
    --certificate-identity "${SIGNING_IDENTITY}${version}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    "${work_dir}/checksums.txt"; then
    action_error "the signature of checksums.txt does not match the release workflow of this repository"
  fi

  if ! verify_archive_checksum "${work_dir}/${archive}" "${work_dir}/checksums.txt" "${archive}"; then
    action_error "the archive does not match the signed checksums.txt"
  fi

  if [[ "${os}" == windows ]]; then
    binary=disdetta.exe
  else
    binary=disdetta
  fi
  if ! mkdir -p "${work_dir}/bin"; then
    action_error "failed to create the extraction directory"
  fi
  if ! extract_binary "${work_dir}/${archive}" "${binary}" "${work_dir}/bin"; then
    action_error "the archive ${archive} cannot be used"
  fi
  executable="${work_dir}/bin/${binary}"

  case "${format}" in
    text) cli_format=table ;;
    json) cli_format=json ;;
    sarif) cli_format=sarif ;;
  esac
  args=(scan --format "${cli_format}" --fail-on "${fail_on}" -- "${path}")

  status=0
  if [[ "${format}" == sarif ]]; then
    sarif_file=${DISDETTA_SARIF_FILE:-${runner_temp}/disdetta-results.sarif}
    if ! sarif_dir=$(dirname "${sarif_file}"); then
      action_error "failed to read the directory of the SARIF report"
    fi
    if ! mkdir -p "${sarif_dir}"; then
      action_error "failed to create the directory of the SARIF report"
    fi
    # The report is opened before the scanner runs: a report that cannot be
    # written is a failure of the action, and never the exit code of the
    # scanner.
    if ! : > "${sarif_file}"; then
      action_error "failed to open the SARIF report for writing"
    fi
    # The marker tells a redirection that failed apart from the exit code
    # of the scanner: when the redirection fails, the scanner never runs
    # and the marker is never written.
    sarif_marker="${work_dir}/scanner-ran"
    ( if ! : > "${sarif_marker}"; then exit 70; fi
      exec "${executable}" "${args[@]}" ) > "${sarif_file}" || status=$?
    if [[ ! -e "${sarif_marker}" ]]; then
      action_error "the SARIF report could not be written"
    fi
    # Only a report that was written is uploaded to code scanning.
    if [[ ( "${status}" -eq 0 || "${status}" -eq 1 || "${status}" -eq 3 ) \
      && -s "${sarif_file}" && -n "${GITHUB_OUTPUT:-}" ]]; then
      echo "sarif-written=true" >> "${GITHUB_OUTPUT}"
    fi
  else
    "${executable}" "${args[@]}" || status=$?
  fi

  # Only the codes of the scanner reach the caller. Anything else means the
  # scanner did not run to the end.
  case "${status}" in
    0|1|2|3) ;;
    *) action_error "the scanner exited with the unexpected code ${status}" ;;
  esac

  # The explanation is assigned, never read from a command substitution: a
  # substitution that fails quietly would leave the run without a reason.
  case "${status}" in
    0) explanation="scan complete, no finding at or above the threshold" ;;
    1) explanation="policy failed, at least one finding at or above the threshold" ;;
    2) explanation="usage error or fatal error" ;;
    3) explanation="policy passed but the scan is incomplete" ;;
    *) explanation="unknown exit code" ;;
  esac
  echo "disdetta exited with code ${status}: ${explanation}"
  exit "${status}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

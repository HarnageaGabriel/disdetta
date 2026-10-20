#!/usr/bin/env bash
set -euo pipefail

# Offline tests for the disdetta composite action. Nothing here touches the
# network: curl, cosign, tar, unzip, mktemp and uname are replaced by stubs,
# and the scanner is a fake binary that records how it was called.
#
# The archives of the release security checks are also built with the real
# tar and read with the real unzip, so the parser is checked against the
# listings of the real tools and not only against the stubs.
#
# The tools these tests need are:
#
#   bash    the shell that runs this script
#   tar     builds the real tar archives
#   unzip   reads the real zip archives
#   python  builds the real zip archives, with the zipfile module, and
#           reads the release list of the API
#   node    an alternative to python for the release list of the API
#   curl    reads the .curlrc of the runner
#
# A missing tool is a failure of the run, and the message names it: only
# the cases that need a real symbolic or hard link may be skipped, because
# the operating system may not be able to create one.
echo "action/run_test.sh: needs bash, tar, unzip, a python with the zipfile module, curl, and a python or node runtime that can read JSON"

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/disdetta-action-test.XXXXXX")
cleanup() { rm -rf -- "${test_root}"; }
trap cleanup EXIT
stub_dir=${test_root}/bin
state_dir=${test_root}/state
mkdir -p "${stub_dir}" "${state_dir}"

fail() {
  echo "action/run_test.sh: FAIL: $1" >&2
  exit 1
}

# skip_count counts the cases that could not run on this machine. Only the
# cases that need a real symbolic or hard link are counted: the operating
# system may not be able to create one.
skip_count=0

skip() {
  skip_count=$((skip_count + 1))
  echo "action/run_test.sh: SKIP: $1"
}

assert_contains() {
  local haystack=$1
  local needle=$2
  [[ "${haystack}" == *"${needle}"* ]] || fail "expected to find '${needle}' in the output: ${haystack}"
}

assert_missing() {
  local haystack=$1
  local needle=$2
  [[ "${haystack}" != *"${needle}"* ]] || fail "did not expect to find '${needle}' in the output: ${haystack}"
}

# usable_runtime_path prints the path of a runtime that can really read
# JSON. It prints nothing when the machine has no such runtime: on
# Windows, the python3 of the Microsoft Store exists but cannot run.
usable_runtime_path() {
  local candidate=$1
  local path
  path=$(command -v "${candidate}" 2>/dev/null) || return 1
  case "${candidate}" in
    python3|python)
      "${path}" -c 'import json' >/dev/null 2>&1 || return 1
      ;;
    node|nodejs)
      "${path}" -e 'JSON.parse("1")' >/dev/null 2>&1 || return 1
      ;;
    *)
      return 1
      ;;
  esac
  printf '%s\n' "${path}"
}

# working_runtime prints the name and the path of a runtime that can really
# read JSON, separated by a pipe. It prints nothing when the machine has no
# such runtime.
working_runtime() {
  local candidate path
  for candidate in python3 python node nodejs; do
    path=$(usable_runtime_path "${candidate}") || continue
    printf '%s|%s\n' "${candidate}" "${path}"
    return 0
  done
  return 1
}

# python_runtime prints the path of a python that can really run a script.
# It prints nothing when the machine has none: on Windows, the python3 of
# the Microsoft Store exists but cannot run.
python_runtime() {
  local candidate path
  for candidate in python3 python; do
    path=$(command -v "${candidate}" 2>/dev/null) || continue
    if "${path}" -c 'import zipfile' >/dev/null 2>&1; then
      printf '%s\n' "${path}"
      return 0
    fi
  done
  return 1
}

# require_tool fails the run when a tool the tests need is missing. A case
# that cannot run would hide a problem of the action, so a missing tool is
# a failure and not a skipped case.
require_tool() {
  local tool=$1
  local reason=$2
  command -v "${tool}" >/dev/null 2>&1 || fail "${tool} is required by these tests: ${reason}"
}

require_tool tar "the real tar archives are built with it"
require_tool unzip "the real zip archives are read with it"
require_tool curl "the .curlrc of the runner is probed with it"
if ! python_runtime >/dev/null 2>&1; then
  fail "a python runtime with the zipfile module is required by these tests: the real zip archives are built with it"
fi
runtime_info=$(working_runtime) || runtime_info=""
if [[ -z "${runtime_info}" ]]; then
  fail "a python or node runtime that can read JSON is required by these tests: the release list of the API is read with it"
fi

# release_list is the answer of the GitHub releases API. It holds a draft, a
# prerelease, a higher major and the release the action has to pick.
release_list=${test_root}/releases.json
cat > "${release_list}" <<'EOF'
[
  {"tag_name": "v1.0.0", "draft": false, "prerelease": false},
  {"tag_name": "v0.3.0-rc.1", "draft": false, "prerelease": true},
  {"tag_name": "v0.2.0", "draft": false, "prerelease": false},
  {"tag_name": "v0.1.0", "draft": false, "prerelease": false},
  {"tag_name": "v0.4.0", "draft": true, "prerelease": false}
]
EOF

# archive_manifest is the content of the release archive the stub tar and the
# stub unzip work with. A line holds the name of a member; a line that starts
# with "link:" is a symbolic link.
archive_manifest=${test_root}/manifest

# write_manifest writes the members of the fake archive of the stub tar and
# the stub unzip.
write_manifest() {
  local member
  : > "${archive_manifest}"
  for member in "$@"; do
    printf '%s\n' "${member}" >> "${archive_manifest}"
  done
}

# The archive of a linux or a darwin release holds the scanner without an
# extension; the archive of a windows release holds disdetta.exe.
write_manifest disdetta LICENSE NOTICE README.md

# archive_sha256_file holds the SHA-256 sum of the fake archive the stub curl
# writes. It is computed once, with the real hasher of the machine, so that
# the tests can put a hasher that fails in front of the PATH.
archive_sha256_file=${state_dir}/archive-sha256
if command -v sha256sum >/dev/null 2>&1; then
  printf 'fake disdetta archive' | sha256sum | awk '{print $1}' > "${archive_sha256_file}"
else
  printf 'fake disdetta archive' | shasum -a 256 | awk '{print $1}' > "${archive_sha256_file}"
fi
archive_sha256=$(<"${archive_sha256_file}")

cat > "${stub_dir}/uname" <<'EOF'
#!/usr/bin/env bash
# A fake uname: it prints the platform of the test, and it can print it and
# fail at the same time.
if [[ "${TEST_UNAME_FAIL:-0}" == 1 ]]; then
  if [[ "${1:-}" == -m ]]; then
    printf '%s\n' "${TEST_UNAME_M:-x86_64}"
  else
    printf '%s\n' "${TEST_UNAME_S:-Linux}"
  fi
  exit 50
fi
if [[ "${1:-}" == -m ]]; then
  printf '%s\n' "${TEST_UNAME_M:-x86_64}"
else
  printf '%s\n' "${TEST_UNAME_S:-Linux}"
fi
EOF

cat > "${stub_dir}/curl" <<'EOF'
#!/usr/bin/env bash
state=${TEST_STATE_DIR}
count_file="${state}/curl-count"
count=0
[[ -f "${count_file}" ]] && count=$(<"${count_file}")
printf '%s' "$((count + 1))" > "${count_file}"
printf '%s\n' "$@" > "${state}/curl-argv-${count}"
: > "${state}/curl-stdin-${count}"
output=
url=
while (($#)); do
  case "$1" in
    --output) output=$2; shift 2 ;;
    -K)
      if [[ "${2:-}" == "-" ]]; then cat > "${state}/curl-stdin-${count}"; fi
      shift 2
      ;;
    --retry) shift 2 ;;
    -q) shift ;;
    --fail|--location|--silent|--show-error) shift ;;
    *) url=$1; shift ;;
  esac
done
case "${url}" in
  https://api.github.com/*)
    cat "${TEST_RELEASE_LIST}"
    ;;
  */checksums.txt)
    if [[ "${TEST_BAD_CHECKSUM:-0}" == 1 ]]; then
      sha=0000000000000000000000000000000000000000000000000000000000000000
    else
      sha=$(<"${state}/archive-sha256")
    fi
    name=$(cat "${state}/archive-name")
    # The style of the entry decides how the checksum file is written: the
    # action has to accept the exact record and refuse every other one.
    case "${TEST_CHECKSUM_STYLE:-normal}" in
      normal)
        printf '%s  %s\n' "${sha}" "${name}" > "${output}"
        ;;
      star)
        printf '%s *%s\n' "${sha}" "${name}" > "${output}"
        ;;
      upper)
        printf '%s  %s\n' "$(printf '%s' "${sha}" | tr 'a-f' 'A-F')" "${name}" > "${output}"
        ;;
      crlf)
        printf '%s  %s\r\n' "${sha}" "${name}" > "${output}"
        ;;
      extra)
        printf '%s  %s extra\n' "${sha}" "${name}" > "${output}"
        ;;
      duplicate)
        printf '%s  %s\n%s  %s\n' "${sha}" "${name}" "${sha}" "${name}" > "${output}"
        ;;
      prefix)
        printf '%s  %s%s\n' "${sha}" "x" "${name}" > "${output}"
        ;;
      suffix)
        printf '%s  %s.bak\n' "${sha}" "${name}" > "${output}"
        ;;
      *)
        printf '%s  %s\n' "${sha}" "${name}" > "${output}"
        ;;
    esac
    ;;
  */checksums.txt.sigstore.json)
    if [[ "${TEST_MISSING_SIGNATURE:-0}" == 1 ]]; then
      echo "curl: (22) The requested URL returned error: 404" >&2
      exit 22
    fi
    printf '%s\n' '{}' > "${output}"
    ;;
  */disdetta_*)
    printf '%s' 'fake disdetta archive' > "${output}"
    printf '%s\n' "${url##*/}" > "${state}/archive-name"
    printf '%s' "${output}" > "${state}/archive-path"
    ;;
esac
# A curl that answers and then fails: the answer was never read, so the
# action has to refuse it.
if [[ "${TEST_CURL_FAIL:-0}" == 1 ]]; then
  echo "curl: (18) transfer closed with outstanding read data remaining" >&2
  exit 18
fi
EOF

cat > "${stub_dir}/cosign" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "${TEST_STATE_DIR}/cosign-args"
if [[ "${TEST_COSIGN_FAIL:-0}" == 1 ]]; then
  echo "cosign: invalid signature" >&2
  exit 9
fi
EOF

cat > "${stub_dir}/tar" <<'EOF'
#!/usr/bin/env bash
# A fake tar: it lists or extracts the members of the manifest of the test
# and writes a fake scanner.
manifest=${TEST_ARCHIVE_MANIFEST:-}
mode=extract
verbose=0
destination=
archive=
member=
while (($#)); do
  case "$1" in
    -C) destination=$2; shift 2 ;;
    --) shift ;;
    -*)
      case "$1" in
        *t*) mode=list ;;
        *x*) mode=extract ;;
      esac
      case "$1" in
        *v*) verbose=1 ;;
      esac
      shift ;;
    *)
      if [[ -z "${archive}" ]]; then archive=$1; else member=$1; fi
      shift ;;
  esac
done
if [[ "${mode}" == list ]]; then
  if [[ "${TEST_TAR_FAIL:-}" == list ]]; then
    echo "tar: unexpected EOF in the archive" >&2
    exit 2
  fi
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    case "${line}" in
      link:*)
        name=${line#link:}
        if [[ "${verbose}" -eq 1 ]]; then
          printf '%s\n' "lrwxrwxrwx 0/0 0 2024-01-01 00:00 ${name} -> /target"
        else
          printf '%s\n' "${name}"
        fi
        ;;
      *)
        if [[ "${verbose}" -eq 1 ]]; then
          printf '%s\n' "-rw-r--r-- 0/0 0 2024-01-01 00:00 ${line}"
        else
          printf '%s\n' "${line}"
        fi
        ;;
    esac
  done < "${manifest}"
  # A tar that lists the members and then fails: the listing was never
  # read, so the action has to refuse the archive.
  if [[ "${TEST_TAR_FAIL:-}" == list_after ]]; then
    echo "tar: unexpected EOF in the archive" >&2
    exit 50
  fi
  exit 0
fi
if [[ "${TEST_TAR_FAIL:-}" == extract ]]; then
  echo "tar: cannot extract: unexpected EOF in the archive" >&2
  exit 2
fi
mkdir -p "${destination}" || exit 1
cat > "${destination}/${member}" <<'CHILD'
#!/usr/bin/env bash
if [[ -n "${DISDETTA_GITHUB_TOKEN+x}" ]]; then
  printf '%s\n' present > "${TEST_STATE_DIR}/token"
else
  printf '%s\n' absent > "${TEST_STATE_DIR}/token"
fi
printf '%s\n' "$@" > "${TEST_STATE_DIR}/args"
printf '%s\0' "$@" > "${TEST_STATE_DIR}/args-nul"
printf '%s\n' '{"version":"2.1.0","runs":[]}'
exit "${TEST_EXIT_CODE:-0}"
CHILD
chmod +x "${destination}/${member}"
EOF

cat > "${stub_dir}/unzip" <<'EOF'
#!/usr/bin/env bash
# A fake unzip: it lists or extracts the members of the manifest of the test
# and writes a fake scanner.
manifest=${TEST_ARCHIVE_MANIFEST:-}
mode=extract
verbose=0
destination=
archive=
member=
while (($#)); do
  case "$1" in
    -Z1) mode=list; verbose=0; shift ;;
    -Z) mode=list; verbose=1; shift ;;
    -d) destination=$2; shift 2 ;;
    -*) shift ;;
    *)
      if [[ -z "${archive}" ]]; then archive=$1; else member=$1; fi
      shift ;;
  esac
done
if [[ "${mode}" == list ]]; then
  if [[ "${TEST_UNZIP_FAIL:-}" == list ]]; then
    echo "zipinfo: cannot find or open ${archive}" >&2
    exit 9
  fi
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    case "${line}" in
      link:*)
        name=${line#link:}
        if [[ "${verbose}" -eq 1 ]]; then
          printf '%s\n' "lrwxrwxrwx  3.0 unx        5 bx stor 24-Jan-01 00:00 ${name}"
        else
          printf '%s\n' "${name}"
        fi
        ;;
      *)
        if [[ "${verbose}" -eq 1 ]]; then
          printf '%s\n' "-rw-r--r--  3.0 unx        5 tx stor 24-Jan-01 00:00 ${line}"
        else
          printf '%s\n' "${line}"
        fi
        ;;
    esac
  done < "${manifest}"
  # An unzip that lists the members and then fails: the listing was never
  # read, so the action has to refuse the archive.
  if [[ "${TEST_UNZIP_FAIL:-}" == list_after ]]; then
    echo "zipinfo: cannot find or open ${archive}" >&2
    exit 50
  fi
  exit 0
fi
if [[ "${TEST_UNZIP_FAIL:-}" == extract ]]; then
  echo "unzip: cannot find or open ${archive}" >&2
  exit 9
fi
mkdir -p "${destination}" || exit 1
cat > "${destination}/${member}" <<'CHILD'
#!/usr/bin/env bash
if [[ -n "${DISDETTA_GITHUB_TOKEN+x}" ]]; then
  printf '%s\n' present > "${TEST_STATE_DIR}/token"
else
  printf '%s\n' absent > "${TEST_STATE_DIR}/token"
fi
printf '%s\n' "$@" > "${TEST_STATE_DIR}/args"
printf '%s\0' "$@" > "${TEST_STATE_DIR}/args-nul"
printf '%s\n' '{"version":"2.1.0","runs":[]}'
exit "${TEST_EXIT_CODE:-0}"
CHILD
chmod +x "${destination}/${member}"
EOF

cat > "${stub_dir}/mktemp" <<'EOF'
#!/usr/bin/env bash
if [[ "${TEST_MKTEMP_FAIL:-0}" == 1 ]]; then
  echo "mktemp: failed to create the temporary directory" >&2
  exit 1
fi
template=
previous=
for argument in "$@"; do
  if [[ "${previous}" == "-d" ]]; then template=${argument}; fi
  previous=${argument}
done
if [[ -z "${template}" ]]; then
  template=${TMPDIR:-/tmp}/disdetta-stub.XXXXXX
fi
mkdir -p "${template}" || exit 1
printf '%s\n' "${template}"
EOF

chmod +x "${stub_dir}"/*

# fail_stub_dir holds the tools that print a plausible answer and then fail.
# The action is run with them in front of the PATH: every status has to be
# checked, a tool that fails after it printed must never be taken for a tool
# that answered.
fail_stub_dir=${test_root}/fail-stubs
mkdir -p "${fail_stub_dir}/hasher" "${fail_stub_dir}/count" "${fail_stub_dir}/trim"
mkdir -p "${fail_stub_dir}/curl" "${fail_stub_dir}/tar"
mkdir -p "${fail_stub_dir}/unzip" "${fail_stub_dir}/awk"

cat > "${fail_stub_dir}/hasher/sha256sum" <<EOF
#!/usr/bin/env bash
# A hasher that prints the expected sum and then fails.
printf '%s\n' "${archive_sha256}"
exit 50
EOF

cat > "${fail_stub_dir}/count/wc" <<'EOF'
#!/usr/bin/env bash
# A wc that prints a count and then fails.
printf '%s\n' '5'
exit 50
EOF

cat > "${fail_stub_dir}/trim/tr" <<'EOF'
#!/usr/bin/env bash
# A tr that prints a value and then fails.
printf '%s\n' '5'
exit 50
EOF

cat > "${fail_stub_dir}/curl/curl" <<'EOF'
#!/usr/bin/env bash
# A curl that answers and then fails: the answer was never read.
"${TEST_STUB_DIR}/curl" "$@" || true
exit 50
EOF

cat > "${fail_stub_dir}/tar/tar" <<'EOF'
#!/usr/bin/env bash
# A tar that lists the members and then fails: the listing was never read.
"${TEST_STUB_DIR}/tar" "$@" || true
exit 50
EOF

cat > "${fail_stub_dir}/unzip/unzip" <<'EOF'
#!/usr/bin/env bash
# An unzip that lists the members and then fails: the listing was never
# read.
"${TEST_STUB_DIR}/unzip" "$@" || true
exit 50
EOF

cat > "${fail_stub_dir}/awk/awk" <<'EOF'
#!/usr/bin/env bash
# An awk that prints the expected sum and then fails: the sum was never
# read.
printf '%s\n' "$(<"${TEST_STATE_DIR}/archive-sha256")"
exit 50
EOF

chmod +x "${fail_stub_dir}/hasher/sha256sum" "${fail_stub_dir}/count/wc" "${fail_stub_dir}/trim/tr"
chmod +x "${fail_stub_dir}/curl/curl" "${fail_stub_dir}/tar/tar"
chmod +x "${fail_stub_dir}/unzip/unzip" "${fail_stub_dir}/awk/awk"

# runtime_stub_dir holds the runtimes the action finds first on PATH: a
# python3 that fails like the stub of the Microsoft Store, and the working
# runtime of the machine under the name of the next candidate. The action
# has to walk over the broken one and keep going.
runtime_stub_dir=${test_root}/runtime-stubs
mkdir -p "${runtime_stub_dir}"

cat > "${runtime_stub_dir}/python3" <<'EOF'
#!/usr/bin/env bash
echo "Python was not found; run without arguments to install from the Microsoft Store" >&2
: > "${TEST_STATE_DIR}/python3-called"
exit 49
EOF
chmod +x "${runtime_stub_dir}/python3"

# lying_runtime_dir holds the runtimes that print the answer the probe
# expects and then fail: a runtime that cannot read JSON must never be
# taken for a runtime that read it.
lying_runtime_dir=${test_root}/lying-runtime-stubs
mkdir -p "${lying_runtime_dir}"
for candidate in python3 python node nodejs; do
  cat > "${lying_runtime_dir}/${candidate}" <<'EOF'
#!/usr/bin/env bash
# A runtime that prints the expected answer and then fails.
: > "${TEST_STATE_DIR}/lying-runtime-called"
printf '%s\n' 'ok'
exit 50
EOF
  chmod +x "${lying_runtime_dir}/${candidate}"
done

# lying_first_runtime_dir holds the first candidate that lies and the
# working runtime of the machine under the name of the next candidate: the
# action has to walk over the runtime that lies and read the release list
# with the next one.
lying_first_runtime_dir=${test_root}/lying-first-runtime-stubs
mkdir -p "${lying_first_runtime_dir}"
cp "${lying_runtime_dir}/python3" "${lying_first_runtime_dir}/python3"

if [[ -n "${runtime_info}" ]]; then
  runtime_name=${runtime_info%%|*}
  runtime_path=${runtime_info#*|}
  case "${runtime_name}" in
    python3|python) fallback_name=python ;;
    *) fallback_name=node ;;
  esac
  cat > "${runtime_stub_dir}/${fallback_name}" <<EOF
#!/usr/bin/env bash
exec "${runtime_path}" "\$@"
EOF
  chmod +x "${runtime_stub_dir}/${fallback_name}"
  # The working runtime is also offered under the name of the candidate
  # that follows the one that lies: the action walks over the runtime
  # that lies and finds a runtime that reads the release list.
  cat > "${lying_first_runtime_dir}/${fallback_name}" <<EOF
#!/usr/bin/env bash
exec "${runtime_path}" "\$@"
EOF
  chmod +x "${lying_first_runtime_dir}/${fallback_name}"
fi

# no_runtime_dir holds runtimes that all fail: the action has to give up and
# say which candidates it tried.
no_runtime_dir=${test_root}/no-runtime-stubs
mkdir -p "${no_runtime_dir}"
for candidate in python3 python node nodejs; do
  cat > "${no_runtime_dir}/${candidate}" <<'EOF'
#!/usr/bin/env bash
echo "this runtime cannot run" >&2
exit 49
EOF
  chmod +x "${no_runtime_dir}/${candidate}"
done

ACTION_REF=v0.2.0
VERSION=""
RELEASE_LIST_FILE="${release_list}"
FORMAT=text
FAIL_ON=high
EXIT_CODE=0
COSIGN_FAIL=0
MISSING_SIGNATURE=0
BAD_CHECKSUM=0
CHECKSUM_STYLE=normal
CURL_FAIL=0
MKTEMP_FAIL=0
TAR_FAIL=""
UNZIP_FAIL=""
UNAME_S=Linux
UNAME_M=x86_64
UNAME_FAIL=0
INPUT_PATH="."
GITHUB_OUTPUT_FILE="${state_dir}/github-output"
SARIF_FILE="${test_root}/disdetta-results.sarif"
output=""
last_status=0
PATH_PREFIX=""

reset_state() {
  rm -f "${state_dir}/args" "${state_dir}/args-nul" "${state_dir}/token"
  rm -f "${state_dir}/github-output"
  rm -f "${state_dir}/python3-called" "${state_dir}/lying-runtime-called"
  rm -f "${state_dir}"/curl-*
}

run_action() {
  env \
    PATH="${PATH_PREFIX}${stub_dir}:${PATH}" \
    RUNNER_TEMP="${test_root}" \
    TEST_STATE_DIR="${state_dir}" \
    TEST_STUB_DIR="${stub_dir}" \
    TEST_RELEASE_LIST="${RELEASE_LIST_FILE}" \
    TEST_COSIGN_FAIL="${COSIGN_FAIL}" \
    TEST_CURL_FAIL="${CURL_FAIL}" \
    TEST_EXIT_CODE="${EXIT_CODE}" \
    TEST_MISSING_SIGNATURE="${MISSING_SIGNATURE}" \
    TEST_BAD_CHECKSUM="${BAD_CHECKSUM}" \
    TEST_CHECKSUM_STYLE="${CHECKSUM_STYLE}" \
    TEST_MKTEMP_FAIL="${MKTEMP_FAIL}" \
    TEST_TAR_FAIL="${TAR_FAIL}" \
    TEST_UNZIP_FAIL="${UNZIP_FAIL}" \
    TEST_ARCHIVE_MANIFEST="${archive_manifest}" \
    TEST_UNAME_S="${UNAME_S}" \
    TEST_UNAME_M="${UNAME_M}" \
    TEST_UNAME_FAIL="${UNAME_FAIL}" \
    DISDETTA_ACTION_REPOSITORY=HarnageaGabriel/disdetta \
    DISDETTA_GITHUB_TOKEN=super-secret-token \
    DISDETTA_ACTION_REF="${ACTION_REF}" \
    DISDETTA_INPUT_PATH="${INPUT_PATH}" \
    DISDETTA_INPUT_FORMAT="${FORMAT}" \
    DISDETTA_INPUT_FAIL_ON="${FAIL_ON}" \
    DISDETTA_VERSION="${VERSION}" \
    DISDETTA_SARIF_FILE="${SARIF_FILE}" \
    GITHUB_OUTPUT="${GITHUB_OUTPUT_FILE}" \
    bash "${repo_root}/action/run.sh"
}

run_action_capture() {
  last_status=0
  output=$(run_action 2>&1) || last_status=$?
}

# assert_path_after_ddash checks that the scanner got the path as the
# positional argument that follows the double dash.
assert_path_after_ddash() {
  local expected=$1
  local actual
  actual=$(awk 'previous == "--" { print; exit } { previous = $0 }' "${state_dir}/args")
  [[ "${actual}" == "${expected}" ]] || fail "the scanner did not get '${expected}' after the double dash: '${actual}'"
}

# assert_path_after_ddash_exact checks the same, byte for byte, with the
# arguments of the scanner read from a file that separates them with a
# null byte: a path that holds a newline is one argument, not two lines.
assert_path_after_ddash_exact() {
  local expected=$1
  local argument previous="" found=""
  while IFS= read -r -d '' argument; do
    if [[ "${previous}" == "--" ]]; then
      found=${argument}
      break
    fi
    previous=${argument}
  done < "${state_dir}/args-nul"
  [[ "${found}" == "${expected}" ]] || fail "the scanner did not get '${expected}' after the double dash: '${found}'"
}

# 1. A plain run: the scanner is called with the documented flags, the token
# never reaches it, and cosign checked the identity of the release workflow.
reset_state
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
[[ "$(<"${state_dir}/token")" == absent ]] || fail "the GitHub token reached the scanner"
assert_missing "${output}" "super-secret-token"
grep -Fx -- scan "${state_dir}/args" >/dev/null || fail "the scanner was not called with the scan command"
grep -Fx -- --format "${state_dir}/args" >/dev/null || fail "the format flag is missing"
grep -Fx -- table "${state_dir}/args" >/dev/null || fail "the text format must map to the table format"
grep -Fx -- --fail-on "${state_dir}/args" >/dev/null || fail "the fail-on flag is missing"
grep -Fx -- high "${state_dir}/args" >/dev/null || fail "the default threshold must be high"
grep -Fx -- -- "${state_dir}/args" >/dev/null || fail "the path must be passed after a double dash"
grep -Fx -- . "${state_dir}/args" >/dev/null || fail "the path is missing"
grep -F -- 'release.yml@refs/tags/v0.2.0' "${state_dir}/cosign-args" >/dev/null || fail "the signing identity does not carry the tag"
grep -F -- 'https://token.actions.githubusercontent.com' "${state_dir}/cosign-args" >/dev/null || fail "the issuer is missing"
grep -F -- '--bundle' "${state_dir}/cosign-args" >/dev/null || fail "the signature bundle is missing"
grep -A3 '^  fail-on:' "${repo_root}/action.yml" | grep -F "default: high" >/dev/null || fail "the fail-on default changed"
grep -A3 '^  format:' "${repo_root}/action.yml" | grep -F "default: text" >/dev/null || fail "the format default changed"

# 2. The token stays inside curl: it is never in argv, and the asset
# downloads carry no Authorization header.
if grep -qF -- 'super-secret-token' "${state_dir}"/curl-argv-*; then
  fail "the token leaked into curl argv"
fi
if grep -qF -- 'Authorization' "${state_dir}"/curl-argv-*; then
  fail "the Authorization header leaked into curl argv"
fi

# 3. A floating vMAJOR ref is resolved through the releases API: the token is
# sent there, and the latest stable v0 release is downloaded.
reset_state
ACTION_REF=v0
VERSION=""
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
grep -qF -- 'api.github.com/repos/HarnageaGabriel/disdetta/releases' "${state_dir}/curl-argv-0" || fail "the releases API was not called"
assert_missing "${output}" "super-secret-token"
grep -qF -- '-K' "${state_dir}/curl-argv-0" || fail "the token was not passed through a curl config"
grep -qF -- 'header = "Authorization: Bearer super-secret-token"' "${state_dir}/curl-stdin-0" >/dev/null || fail "the token was not sent to the API"
if grep -qF -- 'super-secret-token' "${state_dir}"/curl-argv-*; then
  fail "the token leaked into curl argv"
fi
if grep -qF -- 'Authorization' "${state_dir}/curl-stdin-1 "${state_dir}/curl-stdin-2 "${state_dir}/curl-stdin-3" 2>/dev/null; then
  fail "an asset download carried an Authorization header"
fi
grep -qF -- 'disdetta_v0.2.0_linux_amd64.tar.gz' "${state_dir}"/curl-argv-* || fail "the latest stable v0 release was not downloaded"
grep -qF -- 'disdetta_v0.4.0' "${state_dir}"/curl-argv-* && fail "a draft release was downloaded"
grep -qF -- 'disdetta_v1.0.0' "${state_dir}"/curl-argv-* && fail "a release of another major was downloaded"
grep -F -- 'release.yml@refs/tags/v0.2.0' "${state_dir}/cosign-args" >/dev/null || fail "the resolved tag is not in the signing identity"

# 4. An exact ref is used as it is: no API call.
reset_state
ACTION_REF=v0.1.0
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
if grep -qF -- 'api.github.com' "${state_dir}"/curl-argv-*; then
  fail "the releases API was called for an exact tag"
fi
grep -qF -- 'disdetta_v0.1.0_linux_amd64.tar.gz' "${state_dir}"/curl-argv-* || fail "the exact release was not downloaded"

# 5. A SHA pin without the version input stops with a clear message.
reset_state
ACTION_REF=0123456789abcdef0123456789abcdef01234567
VERSION=""
run_action_capture
[[ "${last_status}" -eq 64 ]] || fail "expected exit 64, got ${last_status}: ${output}"
assert_contains "${output}" "pinned by commit SHA"
assert_contains "${output}" "version input"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran despite the SHA pin"
ACTION_REF=v0.2.0

# 6. A checksum mismatch stops the run before the scanner.
reset_state
BAD_CHECKSUM=1
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "SHA-256 verification failed"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a broken checksum"
BAD_CHECKSUM=0

# 7. A missing signature bundle stops the run.
reset_state
MISSING_SIGNATURE=1
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "failed to download checksums.txt.sigstore.json"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran without a signature"
MISSING_SIGNATURE=0

# 8. A signature that does not verify stops the run.
reset_state
COSIGN_FAIL=1
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "does not match the release workflow"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an unverified checksum file"
COSIGN_FAIL=0

# 9. The scanner exit code is passed through, and explained in the log.
reset_state
EXIT_CODE=0
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
assert_contains "${output}" "disdetta exited with code 0"
assert_contains "${output}" "scan complete"
reset_state
EXIT_CODE=1
run_action_capture
[[ "${last_status}" -eq 1 ]] || fail "expected exit 1, got ${last_status}: ${output}"
assert_contains "${output}" "disdetta exited with code 1"
assert_contains "${output}" "policy failed"
reset_state
EXIT_CODE=3
run_action_capture
[[ "${last_status}" -eq 3 ]] || fail "expected exit 3, got ${last_status}: ${output}"
assert_contains "${output}" "disdetta exited with code 3"
assert_contains "${output}" "incomplete"

# 10. An unknown platform stops the run with a clear message.
reset_state
UNAME_S=SunOS
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "unsupported runner OS"
UNAME_S=Linux
reset_state
UNAME_M=riscv64
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "unsupported runner architecture"
UNAME_M=x86_64

# 11. Invalid inputs are rejected before anything is downloaded.
reset_state
FORMAT=xml
run_action_capture
[[ "${last_status}" -eq 64 ]] || fail "expected exit 64, got ${last_status}: ${output}"
assert_contains "${output}" "format must be text, json or sarif"
FORMAT=text
reset_state
FAIL_ON=critical
run_action_capture
[[ "${last_status}" -eq 64 ]] || fail "expected exit 64, got ${last_status}: ${output}"
assert_contains "${output}" "fail-on must be none, low, medium or high"
FAIL_ON=high

# 12. SARIF is written to a file under the runner temp directory, and the
# upload step is told that the report is there.
reset_state
FORMAT=sarif
EXIT_CODE=0
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
[[ -s "${test_root}/disdetta-results.sarif" ]] || fail "the SARIF file was not written"
grep -qF '"version":"2.1.0"' "${test_root}/disdetta-results.sarif" || fail "the SARIF file does not hold the report"
grep -qF 'sarif-written=true' "${state_dir}/github-output" || fail "the sarif-written output is missing"

# 13. A failing policy still leaves a SARIF file to upload.
reset_state
FORMAT=sarif
EXIT_CODE=1
run_action_capture
[[ "${last_status}" -eq 1 ]] || fail "expected exit 1, got ${last_status}: ${output}"
grep -qF 'sarif-written=true' "${state_dir}/github-output" || fail "the sarif-written output is missing"
EXIT_CODE=0
FORMAT=text

# 14. The exit code 2 of the scanner is passed through unchanged.
reset_state
EXIT_CODE=2
run_action_capture
[[ "${last_status}" -eq 2 ]] || fail "expected exit 2, got ${last_status}: ${output}"
assert_contains "${output}" "disdetta exited with code 2"
assert_contains "${output}" "usage error"
EXIT_CODE=0

# 15. A code the scanner never returns is a failure of the action, not a
# finding.
reset_state
EXIT_CODE=5
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "unexpected code 5"
EXIT_CODE=0

# 16. A setup failure of the action ends with 70, never with the code of the
# command that failed.
reset_state
MKTEMP_FAIL=1
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "failed to create the work directory"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran after a setup failure"
MKTEMP_FAIL=0

reset_state
TAR_FAIL=list
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "cannot be read"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an unreadable archive"
TAR_FAIL=""

reset_state
TAR_FAIL=extract
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "cannot be used"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an archive that cannot be extracted"
TAR_FAIL=""

# 17. The windows archive goes through the same checks.
write_manifest disdetta.exe LICENSE NOTICE README.md
reset_state
UNAME_S=MINGW64_NT-10.0
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
grep -qF -- 'disdetta_v0.2.0_windows_amd64.zip' "${state_dir}"/curl-argv-* || fail "the windows archive was not downloaded"
UNAME_S=Linux

reset_state
UNAME_S=MINGW64_NT-10.0
UNZIP_FAIL=extract
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "cannot be used"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an archive that cannot be extracted"
UNZIP_FAIL=""
UNAME_S=Linux
write_manifest disdetta LICENSE NOTICE README.md

# 18. An archive that holds a member that escapes the extraction directory is
# refused.
reset_state
write_manifest disdetta LICENSE NOTICE README.md '../evil'
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "'..' component"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an unsafe archive"

# 19. An archive that holds an absolute path is refused.
reset_state
write_manifest disdetta LICENSE NOTICE README.md '/etc/passwd'
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "absolute path"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an unsafe archive"

# 20. An archive that holds a link is refused.
reset_state
write_manifest disdetta LICENSE NOTICE README.md 'link:disdetta'
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "not a regular file"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an unsafe archive"

# 21. An archive that holds an unexpected file is refused.
reset_state
write_manifest disdetta LICENSE NOTICE README.md evil
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "unexpected member"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an unsafe archive"

# 22. An archive without the scanner is refused.
reset_state
write_manifest LICENSE NOTICE README.md
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "does not hold disdetta"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an archive without a binary"

# 23. The scanner of another platform is refused.
reset_state
write_manifest disdetta disdetta.exe LICENSE NOTICE README.md
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "another platform"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an archive of another platform"

# 24. A member that appears twice is refused.
reset_state
write_manifest disdetta disdetta LICENSE NOTICE README.md
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "more than once"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an archive that holds a member twice"

reset_state
write_manifest disdetta LICENSE LICENSE NOTICE README.md
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "more than once"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an archive that holds a member twice"
write_manifest disdetta LICENSE NOTICE README.md

# 25. An unexpected failure of the action ends with 70 and says what failed.
reset_state
FORMAT=sarif
GITHUB_OUTPUT_FILE="${state_dir}/github-output-directory"
mkdir -p "${GITHUB_OUTPUT_FILE}"
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "disdetta action failed"
GITHUB_OUTPUT_FILE="${state_dir}/github-output"
FORMAT=text

# 26. A python3 that exists but cannot run, like the stub of the Microsoft
# Store, does not stop the action: the next runtime reads the release list.
if [[ -z "${runtime_info}" ]]; then
  fail "this machine has no working JSON runtime: python and node are needed by the action"
fi
reset_state
PATH_PREFIX="${runtime_stub_dir}:"
ACTION_REF=v0
VERSION=""
run_action_capture
PATH_PREFIX=""
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
[[ -e "${state_dir}/python3-called" ]] || fail "the broken python3 was never tried"
grep -qF -- 'disdetta_v0.2.0_linux_amd64.tar.gz' "${state_dir}"/curl-argv-* || fail "the version was not resolved with the next runtime"
grep -F -- 'release.yml@refs/tags/v0.2.0' "${state_dir}/cosign-args" >/dev/null || fail "the resolved tag is not in the signing identity"
ACTION_REF=v0.2.0

# 27. When no runtime works, the action stops with 70 and names the
# candidates it tried.
reset_state
PATH_PREFIX="${no_runtime_dir}:"
ACTION_REF=v0
VERSION=""
run_action_capture
PATH_PREFIX=""
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "tried python3, python, node, nodejs"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran without a JSON runtime"
ACTION_REF=v0.2.0

# 28. A hasher that prints the expected sum and then fails is refused: the
# sum was never read.
reset_state
PATH_PREFIX="${fail_stub_dir}/hasher:"
run_action_capture
PATH_PREFIX=""
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "SHA-256 sum"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a hasher that failed"

# 29. A wc that prints a count and then fails stops the run.
reset_state
PATH_PREFIX="${fail_stub_dir}/count:"
run_action_capture
PATH_PREFIX=""
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a wc that failed"

# 30. The number of the releases that cannot be read stops the run: the
# list of the releases is never cut short.
reset_state
PATH_PREFIX="${fail_stub_dir}/count:"
ACTION_REF=v0
VERSION=""
run_action_capture
PATH_PREFIX=""
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "failed to count the releases"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a wc that failed"
ACTION_REF=v0.2.0

# 31. A tr that prints a value and then fails stops the run.
reset_state
PATH_PREFIX="${fail_stub_dir}/trim:"
run_action_capture
PATH_PREFIX=""
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a tr that failed"

# 32. A uname that prints a platform and then fails stops the run.
reset_state
UNAME_FAIL=1
run_action_capture
UNAME_FAIL=0
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "failed to detect the operating system"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a uname that failed"

# 33. A path with spaces and a path that starts with a dash are scanned as
# they are: the scanner gets them after the double dash.
reset_state
INPUT_PATH="dir with spaces"
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
assert_path_after_ddash "dir with spaces"

reset_state
INPUT_PATH="-rf"
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
assert_path_after_ddash "-rf"
INPUT_PATH="."

# The real archives of the tests below are built with the real tar and read
# with the real unzip: the parser is checked against the listings of the
# real tools and not only against the stubs.
real_dir=${test_root}/real
mkdir -p "${real_dir}"

# can_make_symlink tells whether the machine can create a real symbolic
# link and can store it in an archive as a link member. Under MSYS and Git
# Bash for Windows, ln -s copies the file unless MSYS=winsymlinks is set:
# the archive built there holds a regular file and the test of a link
# member cannot run.
can_make_symlink() {
  local probe_dir=${real_dir}/symlink-probe
  local probe_archive=${real_dir}/symlink-probe.tar.gz
  local listing
  rm -rf -- "${probe_dir}" 2>/dev/null || return 1
  rm -f -- "${probe_archive}" 2>/dev/null || return 1
  mkdir -p -- "${probe_dir}" || return 1
  printf 'probe\n' > "${probe_dir}/target" || return 1
  ln -s -- target "${probe_dir}/link" 2>/dev/null || return 1
  [[ -L "${probe_dir}/link" ]] || return 1
  tar -czf "${probe_archive}" -C "${probe_dir}" target link 2>/dev/null || return 1
  listing=$(tar -tvf "${probe_archive}" 2>/dev/null) || return 1
  if ! printf '%s\n' "${listing}" | awk '$1 ~ /^l/ { found = 1 } END { exit(found ? 0 : 1) }'; then
    return 1
  fi
  rm -rf -- "${probe_dir}" 2>/dev/null || true
  rm -f -- "${probe_archive}" 2>/dev/null || true
  return 0
}

# build_real_tar builds a real tar archive that holds the files of a release
# and one more member. The kind tells what the extra member is: "valid" (the
# files of a release), "abs" (a member with an absolute path), "dotdot" (a
# member with a ".." component), "link" (a symbolic link), "hard" (a hard
# link), "file" (an unexpected file), "twice" (the scanner twice), "exe"
# (the scanner of another platform), "newline" (a member whose name holds a
# newline), "dot" (the scanner behind a "./" prefix) and "dir" (a directory
# entry). The function returns 1 when the machine cannot build that member:
# the caller skips the case.
build_real_tar() {
  local archive=$1
  local kind=$2
  local tree=${real_dir}/tree
  local abs_dir newline_member
  rm -rf -- "${tree}"
  mkdir -p -- "${tree}" || return 1
  printf 'scanner\n' > "${tree}/disdetta" || return 1
  printf 'license\n' > "${tree}/LICENSE" || return 1
  printf 'notice\n' > "${tree}/NOTICE" || return 1
  printf 'readme\n' > "${tree}/README.md" || return 1
  case "${kind}" in
    valid)
      tar -czf "${archive}" -C "${tree}" disdetta LICENSE NOTICE README.md 2>/dev/null || return 1
      ;;
    abs)
      mkdir -p -- "${real_dir}/abs" || return 1
      printf 'absolute\n' > "${real_dir}/abs/evil" || return 1
      abs_dir=$(cd -- "${real_dir}/abs" && pwd -P) || return 1
      tar -czPf "${archive}" -C "${tree}" disdetta LICENSE NOTICE README.md "${abs_dir}/evil" 2>/dev/null || return 1
      ;;
    dotdot)
      printf 'dotdot\n' > "${real_dir}/evil" || return 1
      tar -czPf "${archive}" -C "${tree}" disdetta LICENSE NOTICE README.md ../evil 2>/dev/null || return 1
      ;;
    link)
      ln -s LICENSE -- "${tree}/evil" 2>/dev/null || return 1
      tar -czf "${archive}" -C "${tree}" disdetta LICENSE NOTICE README.md evil 2>/dev/null || return 1
      ;;
    hard)
      ln -- "${tree}/disdetta" "${tree}/evil" 2>/dev/null || return 1
      tar -czf "${archive}" -C "${tree}" disdetta LICENSE NOTICE README.md evil 2>/dev/null || return 1
      ;;
    file)
      printf 'evil\n' > "${tree}/evil" || return 1
      tar -czf "${archive}" -C "${tree}" disdetta LICENSE NOTICE README.md evil 2>/dev/null || return 1
      ;;
    twice)
      tar -czf "${archive}" -C "${tree}" disdetta disdetta LICENSE NOTICE README.md 2>/dev/null || return 1
      ;;
    exe)
      printf 'windows\n' > "${tree}/disdetta.exe" || return 1
      tar -czf "${archive}" -C "${tree}" disdetta disdetta.exe LICENSE NOTICE README.md 2>/dev/null || return 1
      ;;
    newline)
      newline_member=$(printf '%b' 'evil\nname')
      printf 'evil\n' > "${tree}/${newline_member}" || return 1
      tar -czf "${archive}" -C "${tree}" disdetta LICENSE NOTICE README.md "${newline_member}" 2>/dev/null || return 1
      ;;
    dot)
      tar -czf "${archive}" -C "${tree}" ./disdetta LICENSE NOTICE README.md 2>/dev/null || return 1
      ;;
    dir)
      mkdir -p -- "${tree}/subdir" || return 1
      printf 'inside\n' > "${tree}/subdir/inside" || return 1
      tar -czf "${archive}" -C "${tree}" disdetta LICENSE NOTICE README.md subdir 2>/dev/null || return 1
      ;;
    *)
      return 1
      ;;
  esac
  return 0
}

# build_real_zip builds a real zip archive with the same members as
# build_real_tar. The archives are written with the python zipfile module
# because the zip command cannot store a member with an absolute path or a
# ".." component; the real unzip reads them.
cat > "${real_dir}/build_zip.py" <<'PYTHON'
import sys
import zipfile

archive = sys.argv[1]
kind = sys.argv[2]
binary = sys.argv[3]

members = [
    (binary, "scanner", 0o100755),
    ("LICENSE", "license", 0o100644),
    ("NOTICE", "notice", 0o100644),
    ("README.md", "readme", 0o100644),
]

if kind == "file":
    members.append(("evil", "evil", 0o100644))
elif kind == "twice":
    members.append((binary, "scanner", 0o100755))
elif kind == "exe":
    other = "disdetta" if binary == "disdetta.exe" else "disdetta.exe"
    members.append((other, "other platform", 0o100644))
elif kind == "link":
    members.append(("evil", "LICENSE", 0o120777))
elif kind == "abs":
    members.append(("/etc/passwd", "absolute", 0o100644))
elif kind == "dotdot":
    members.append(("../evil", "dotdot", 0o100644))
elif kind == "newline":
    members.append(("evil\nname", "newline", 0o100644))
elif kind == "dot":
    members[0] = ("./" + binary, "scanner", 0o100755)
elif kind != "valid":
    sys.exit(1)

# The archive is made as a Unix zip: the reader has to read the mode of the
# member, so that a symbolic link is seen as a link and not as a regular
# file.
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
    for name, content, mode in members:
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = mode << 16
        handle.writestr(info, content)
PYTHON

build_real_zip() {
  local archive=$1
  local kind=$2
  local binary=$3
  local runtime
  runtime=$(python_runtime) || return 1
  if ! "${runtime}" -W ignore "${real_dir}/build_zip.py" "${archive}" "${kind}" "${binary}"; then
    return 1
  fi
  return 0
}

# validate_real_archive runs the validation of the action on a real archive.
# It prints what the action said and returns 0 when the archive is accepted,
# 70 when it is refused. The listings of the members are written to a
# directory of their own, like the work directory of the action.
validate_real_archive() {
  local archive=$1
  local binary=$2
  local listing_dir
  listing_dir=$(mktemp -d "${test_root}/listing.XXXXXX") || return 70
  bash -c '
    set -Eeuo pipefail
    source "$1"
    listing=""
    if ! listing=$(archive_listing "$2" "$3"); then
      echo "the members of the archive cannot be read" >&2
      exit 70
    fi
    if ! validate_archive "${listing}" "$4"; then
      exit 70
    fi
    exit 0
  ' bash "${repo_root}/action/run.sh" "${archive}" "${listing_dir}" "${binary}"
}

# real_archive_count prints the number of members of a real archive that
# carry that name.
real_archive_count() {
  local archive=$1
  local member=$2
  case "${archive}" in
    *.zip) unzip -Z1 "${archive}" | grep -Fxc -- "${member}" ;;
    *) tar -tzf "${archive}" 2>/dev/null | grep -Fxc -- "${member}" ;;
  esac
}

# real_archive_link_type prints the type of the link member of a real
# archive: "l" for a symbolic link and "h" for a hard link. It prints
# nothing when the archive holds no link member at all, which happens when
# the machine copied the file instead of linking it.
real_archive_link_type() {
  local archive=$1
  local listing
  case "${archive}" in
    *.zip) listing=$(unzip -Z "${archive}" 2>/dev/null) || return 1 ;;
    *) listing=$(tar -tvf "${archive}" 2>/dev/null) || return 1 ;;
  esac
  printf '%s\n' "${listing}" | awk '
    {
      type = substr($1, 1, 1)
      if (type != "l" && type != "h") next
      print type
      exit
    }
  '
}

# check_real_archive builds a real archive of that kind and runs the
# validation of the action on it. The message is the one the action has to
# print; an empty message means that the archive has to be accepted.
check_real_archive() {
  local builder=$1
  local kind=$2
  local binary=$3
  local message=$4
  local extension=$5
  local archive=${real_dir}/${kind}.${extension}
  local member count status=0 output link_type

  # A tar archive with a symbolic link needs a machine that can really
  # create one: under MSYS and Git Bash for Windows, ln -s copies the file
  # unless MSYS=winsymlinks is set. The case is skipped there and it runs
  # for real on Linux and on macOS.
  if [[ "${kind}" == link && "${extension}" != zip ]] && ! can_make_symlink; then
    skip "this machine cannot create a real symbolic link: the ${kind} archive would hold a regular file"
    return 0
  fi

  # A builder that fails is a failure of the test, and not a skip: a case
  # that cannot run would hide a problem of the action. Only the cases
  # that need a link may be skipped, because the operating system may not
  # be able to create one.
  if ! "${builder}" "${archive}" "${kind}" "${binary}"; then
    if [[ "${kind}" == link || "${kind}" == hard ]]; then
      skip "this machine cannot build the ${kind} archive"
      return 0
    fi
    fail "this machine cannot build the ${kind} archive"
  fi
  case "${kind}" in
    abs)
      if [[ "${extension}" == zip ]]; then
        member="/etc/passwd"
      else
        member="$(cd -- "${real_dir}/abs" && pwd -P)/evil"
      fi
      ;;
    dotdot) member="../evil" ;;
    link|hard|file) member="evil" ;;
    twice) member="${binary}" ;;
    exe)
      if [[ "${binary}" == "disdetta.exe" ]]; then member="disdetta"; else member="disdetta.exe"; fi
      ;;
    dot) member="./${binary}" ;;
    dir) member="subdir/" ;;
    newline) member="" ;;
    *) member="" ;;
  esac
  count=$(real_archive_count "${archive}" "${member}" || true)
  if [[ "${kind}" == twice ]]; then
    if [[ "${count}" != 2 ]]; then
      fail "this machine cannot store the member ${member} twice"
    fi
  elif [[ -n "${member}" && "${count}" -lt 1 ]]; then
    fail "this machine cannot store the member ${member}"
  fi
  # A link member has to be a real link. A machine that copies the file
  # instead of linking it stores a regular file, and the validator would
  # refuse the archive for another reason. The listing of the archive tells
  # what it really holds: the case is skipped there and it runs for real
  # everywhere else.
  if [[ "${kind}" == link || "${kind}" == hard ]]; then
    link_type=$(real_archive_link_type "${archive}" || true)
    if [[ -z "${link_type}" ]]; then
      skip "the ${kind} archive holds no link member: this machine cannot create one"
      return 0
    fi
    if [[ "${kind}" == link && "${link_type}" != l ]]; then
      skip "the ${kind} archive holds a ${link_type} member and not a symbolic link"
      return 0
    fi
    if [[ "${kind}" == hard && "${link_type}" != h ]]; then
      skip "the ${kind} archive holds a ${link_type} member and not a hard link"
      return 0
    fi
  fi
  output=$(validate_real_archive "${archive}" "${binary}" 2>&1) || status=$?
  if [[ -z "${message}" ]]; then
    [[ "${status}" -eq 0 ]] || fail "the ${kind} archive was refused: ${output}"
    return 0
  fi
  [[ "${status}" -eq 70 ]] || fail "the ${kind} archive was accepted: ${output}"
  # The message can hold alternatives separated by a bar: the tools do not
  # store a member that appears twice the same way.
  local alternative found=0
  local -a alternatives=()
  IFS='|' read -r -a alternatives <<< "${message}"
  for alternative in "${alternatives[@]}"; do
    if [[ "${output}" == *"${alternative}"* ]]; then
      found=1
    fi
  done
  [[ "${found}" -eq 1 ]] || fail "the ${kind} archive was refused without the expected message: ${output}"
}

# 34. The real archives of a release are checked with the real tar.
check_real_archive build_real_tar valid disdetta "" tar.gz
check_real_archive build_real_tar abs disdetta "absolute path" tar.gz
check_real_archive build_real_tar dotdot disdetta "'..' component" tar.gz
check_real_archive build_real_tar link disdetta "not a regular file" tar.gz
check_real_archive build_real_tar hard disdetta "not a regular file" tar.gz
check_real_archive build_real_tar file disdetta "unexpected member" tar.gz
check_real_archive build_real_tar twice disdetta "more than once|not a regular file" tar.gz
check_real_archive build_real_tar exe disdetta "another platform" tar.gz
# A member whose name holds a newline is not a file of the release: it is
# refused. The tools print such a name escaped or split over two lines, so
# the refusal is the same in both cases.
check_real_archive build_real_tar newline disdetta "unexpected member|cannot be read" tar.gz
# A member behind a "./" prefix is not the scanner of the release either:
# the extraction names the member exactly, and the archives of the releases
# never hold such a prefix.
check_real_archive build_real_tar dot disdetta "unexpected member" tar.gz
# A directory entry is not a regular file.
check_real_archive build_real_tar dir disdetta "not a regular file" tar.gz

# 35. The real archives of a windows release are checked with the real zip.
# The tools they need are checked at the top of this script: a missing
# tool is a failure of the run, and not a skipped case.
check_real_archive build_real_zip valid disdetta.exe "" zip
check_real_archive build_real_zip abs disdetta.exe "absolute path" zip
check_real_archive build_real_zip dotdot disdetta.exe "'..' component" zip
check_real_archive build_real_zip link disdetta.exe "not a regular file" zip
check_real_archive build_real_zip file disdetta.exe "unexpected member" zip
check_real_archive build_real_zip twice disdetta.exe "more than once" zip
check_real_archive build_real_zip exe disdetta.exe "another platform" zip
check_real_archive build_real_zip newline disdetta.exe "unexpected member|cannot be read" zip
check_real_archive build_real_zip dot disdetta.exe "unexpected member" zip

# 36. Every call to curl starts with -q: curl reads its configuration file
# (.curlrc, in CURL_HOME or in HOME) unless -q is the very first argument,
# and an inherited configuration can turn the tracing on and print the
# Authorization header of the config in the log.
reset_state
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
curl_call_count=0
for argv_file in "${state_dir}"/curl-argv-*; do
  [[ -e "${argv_file}" ]] || continue
  first_argument=""
  IFS= read -r first_argument < "${argv_file}" || true
  [[ "${first_argument}" == "-q" ]] || fail "a call to curl does not start with -q: '${first_argument}'"
  curl_call_count=$((curl_call_count + 1))
done
[[ "${curl_call_count}" -ge 1 ]] || fail "no call to curl was recorded"

reset_state
ACTION_REF=v0
VERSION=""
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
for argv_file in "${state_dir}"/curl-argv-*; do
  [[ -e "${argv_file}" ]] || continue
  first_argument=""
  IFS= read -r first_argument < "${argv_file}" || true
  [[ "${first_argument}" == "-q" ]] || fail "the call to curl that carries the token does not start with -q: '${first_argument}'"
done
ACTION_REF=v0.2.0

# curl_is_too_old tells whether the curl of the machine is too old for
# the trace option of a configuration file. The option was added in curl
# 7.49.0: an older curl cannot write the trace, so the control call
# without -q cannot read the configuration file either.
curl_is_too_old() {
  local version major minor
  version=$(curl --version 2>/dev/null | head -1) || return 1
  version=${version#curl }
  version=${version%% *}
  major=${version%%.*}
  minor=${version#*.}
  minor=${minor%%.*}
  [[ "${major}" =~ ^[0-9]+$ ]] || return 1
  [[ "${minor}" =~ ^[0-9]+$ ]] || return 1
  if (( major < 7 )); then
    return 0
  fi
  if (( major == 7 && minor < 49 )); then
    return 0
  fi
  return 1
}

# 37. The real curl never reads the .curlrc of the runner: a configuration
# file that turns the tracing on must not put the token of the API in the
# log. The probe has to have teeth: the same call without -q has to read
# the configuration file, otherwise the probe proves nothing.
probe_dir=${test_root}/curl-probe
mkdir -p "${probe_dir}" || fail "failed to create the directory of the curl probe"
probe_sentinel="sentinel-token-of-the-curl-probe"
probe_home=${probe_dir}
probe_url="file://${probe_dir}/payload.txt"
# A native curl does not understand the paths of a POSIX shell: the
# paths of the probe are translated when the machine can translate them.
if command -v cygpath >/dev/null 2>&1; then
  probe_home=$(cygpath -m "${probe_dir}")
  probe_url="file:///$(cygpath -m "${probe_dir}/payload.txt")"
fi
printf 'trace-ascii = "%s"\n' "${probe_home}/trace.txt" > "${probe_dir}/.curlrc"
printf 'payload\n' > "${probe_dir}/payload.txt"
probe_status=0
probe_output=$(CURL_HOME="${probe_home}" curl -q --fail --silent --show-error -K - "${probe_url}" <<EOF 2>&1
header = "Authorization: Bearer ${probe_sentinel}"
EOF
) || probe_status=$?
if [[ "${probe_status}" -ne 0 ]]; then
  fail "the real curl cannot read a local file: the .curlrc probe did not run"
fi
assert_missing "${probe_output}" "${probe_sentinel}"
assert_missing "${probe_output}" "Read config file"
if [[ -e "${probe_dir}/trace.txt" ]]; then
  fail "the real curl read the .curlrc of the runner: the trace file was written"
fi
# The probe has teeth when the same call without -q reads the
# configuration file: the trace file is written then.
CURL_HOME="${probe_home}" curl --fail --silent --show-error -K - "${probe_url}" >/dev/null 2>&1 <<EOF
header = "Authorization: Bearer ${probe_sentinel}"
EOF
if [[ ! -e "${probe_dir}/trace.txt" ]]; then
  if curl_is_too_old; then
    fail "the real curl is too old for the trace option of a configuration file: the .curlrc probe has no teeth"
  fi
  fail "the .curlrc probe has no teeth: the control call without -q did not read the .curlrc"
fi

# 38. The entry of the checksum file has to name the archive exactly: the
# hash may be in upper case and the file may end with a carriage return,
# but a name with another word, a name of another file and a name that is
# written twice are refused.
for checksum_style in normal star upper crlf; do
  reset_state
  CHECKSUM_STYLE=${checksum_style}
  run_action_capture
  [[ "${last_status}" -eq 0 ]] || fail "the ${checksum_style} checksum entry was refused: ${output}"
  [[ -e "${state_dir}/args" ]] || fail "the scanner did not run with the ${checksum_style} checksum entry"
done
for checksum_style in extra duplicate prefix suffix; do
  reset_state
  CHECKSUM_STYLE=${checksum_style}
  run_action_capture
  [[ "${last_status}" -eq 70 ]] || fail "the ${checksum_style} checksum entry was accepted: ${output}"
  assert_contains "${output}" "checksums.txt has no unique SHA-256 entry"
  [[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a ${checksum_style} checksum entry"
done
CHECKSUM_STYLE=normal

# 39. A SARIF report that cannot be written is a failure of the action, and
# never the exit code of the scanner.
reset_state
FORMAT=sarif
SARIF_FILE="${state_dir}/sarif-directory"
mkdir -p "${SARIF_FILE}"
run_action_capture
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a SARIF report that cannot be written"
SARIF_FILE="${test_root}/disdetta-results.sarif"
FORMAT=text

# 40. The exit codes of the scanner pass through with a SARIF report too.
reset_state
FORMAT=sarif
EXIT_CODE=3
run_action_capture
[[ "${last_status}" -eq 3 ]] || fail "expected exit 3, got ${last_status}: ${output}"
grep -qF 'sarif-written=true' "${state_dir}/github-output" >/dev/null || fail "the sarif-written output is missing"
EXIT_CODE=0
FORMAT=text

# 41. A curl that answers and then fails is refused: the answer was never
# read.
reset_state
PATH_PREFIX="${fail_stub_dir}/curl:"
run_action_capture
PATH_PREFIX=""
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a curl that failed"

# 42. A tar that lists the members and then fails is refused: the listing
# was never read, and a listing that stops in the middle would hide the
# members that come after it.
reset_state
PATH_PREFIX="${fail_stub_dir}/tar:"
run_action_capture
PATH_PREFIX=""
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "cannot be read"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a tar that failed"

# 43. An unzip that lists the members and then fails is refused.
reset_state
PATH_PREFIX="${fail_stub_dir}/unzip:"
UNAME_S=MINGW64_NT-10.0
run_action_capture
PATH_PREFIX=""
UNAME_S=Linux
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "cannot be read"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an unzip that failed"

# 44. An awk that prints the sum and then fails is refused: the sum was
# never read.
reset_state
PATH_PREFIX="${fail_stub_dir}/awk:"
run_action_capture
PATH_PREFIX=""
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with an awk that failed"

# 45. A runtime that prints the answer of the probe and then fails is never
# used. When every runtime lies, the action gives up and says which
# candidates it tried.
reset_state
PATH_PREFIX="${lying_runtime_dir}:"
ACTION_REF=v0
VERSION=""
run_action_capture
PATH_PREFIX=""
ACTION_REF=v0.2.0
[[ "${last_status}" -eq 70 ]] || fail "expected exit 70, got ${last_status}: ${output}"
assert_contains "${output}" "tried python3, python, node, nodejs"
[[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with a runtime that lies"

# 46. The action walks over the runtime that lies and reads the release
# list with the next one.
reset_state
PATH_PREFIX="${lying_first_runtime_dir}:"
ACTION_REF=v0
VERSION=""
run_action_capture
PATH_PREFIX=""
ACTION_REF=v0.2.0
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
[[ -e "${state_dir}/lying-runtime-called" ]] || fail "the runtime that lies was never tried"
grep -qF -- 'disdetta_v0.2.0_linux_amd64.tar.gz' "${state_dir}"/curl-argv-* || fail "the release was not resolved with the next runtime"

# 47. A path with glob characters and a path that holds a newline are
# scanned as they are: the scanner gets them after the double dash, byte
# for byte.
reset_state
INPUT_PATH='dir/*.txt'
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
assert_path_after_ddash_exact 'dir/*.txt'

reset_state
INPUT_PATH=$(printf '%b' 'dir\nname')
run_action_capture
[[ "${last_status}" -eq 0 ]] || fail "expected exit 0, got ${last_status}: ${output}"
assert_path_after_ddash_exact "$(printf '%b' 'dir\nname')"
INPUT_PATH="."

# 48. The parser of the release list fails closed: a page that is not a
# list of releases, a record that is not an object, a tag that is not a
# string and a draft or a prerelease that is not a boolean are refused by
# every runtime of the machine that can read them. A valid page still
# resolves the highest stable v0 release.
malformed_dir=${test_root}/malformed
mkdir -p "${malformed_dir}"
cat > "${malformed_dir}/draft-string.json" <<'EOF'
[{"tag_name": "v0.2.0", "draft": "true", "prerelease": false}]
EOF
cat > "${malformed_dir}/prerelease-missing.json" <<'EOF'
[{"tag_name": "v0.2.0", "draft": false}]
EOF
cat > "${malformed_dir}/tag-number.json" <<'EOF'
[{"tag_name": 2, "draft": false, "prerelease": false}]
EOF
cat > "${malformed_dir}/non-object.json" <<'EOF'
["v0.2.0"]
EOF
cat > "${malformed_dir}/top-object.json" <<'EOF'
{"tag_name": "v0.2.0", "draft": false, "prerelease": false}
EOF
malformed_pages="draft-string prerelease-missing tag-number non-object top-object"

# runtime_pin_dir builds a directory of runtimes that leaves the action
# with one usable runtime: the one that is named. The other candidates
# are replaced by a runtime that cannot run, so that the action has to
# read the release list with the one of the case.
runtime_pin_dir() {
  local wanted=$1
  local real_path=$2
  local dir=${test_root}/pin-${wanted}
  local candidate
  mkdir -p "${dir}" || return 1
  for candidate in python3 python node nodejs; do
    if [[ "${candidate}" == "${wanted}" ]]; then
      cat > "${dir}/${candidate}" <<EOF
#!/usr/bin/env bash
exec "${real_path}" "\$@"
EOF
    else
      cat > "${dir}/${candidate}" <<'EOF'
#!/usr/bin/env bash
echo "this runtime cannot run" >&2
exit 49
EOF
    fi
    chmod +x "${dir}/${candidate}"
  done
  printf '%s\n' "${dir}"
}

checked_runtimes=0
for candidate in python3 python node nodejs; do
  checked_path=$(usable_runtime_path "${candidate}") || {
    echo "action/run_test.sh: note: the ${candidate} runtime is not installed: its parser is not checked"
    continue
  }
  checked_runtimes=$((checked_runtimes + 1))
  pin_dir=$(runtime_pin_dir "${candidate}" "${checked_path}") || fail "failed to build the directory of the runtime ${candidate}"
  # A valid page still resolves the highest stable v0 release.
  reset_state
  PATH_PREFIX="${pin_dir}:"
  ACTION_REF=v0
  VERSION=""
  RELEASE_LIST_FILE="${release_list}"
  run_action_capture
  PATH_PREFIX=""
  ACTION_REF=v0.2.0
  [[ "${last_status}" -eq 0 ]] || fail "the ${candidate} runtime did not resolve the release: ${output}"
  grep -qF -- 'disdetta_v0.2.0_linux_amd64.tar.gz' "${state_dir}"/curl-argv-* || fail "the ${candidate} runtime did not resolve the highest stable v0 release"
  # Every malformed page is refused, and the scanner never runs.
  for malformed in ${malformed_pages}; do
    reset_state
    PATH_PREFIX="${pin_dir}:"
    ACTION_REF=v0
    VERSION=""
    RELEASE_LIST_FILE="${malformed_dir}/${malformed}.json"
    run_action_capture
    PATH_PREFIX=""
    ACTION_REF=v0.2.0
    [[ "${last_status}" -eq 70 ]] || fail "the ${candidate} runtime accepted the malformed page ${malformed}: ${output}"
    assert_contains "${output}" "releases API response is malformed"
    [[ ! -e "${state_dir}/args" ]] || fail "the scanner ran with the malformed page ${malformed}"
  done
done
[[ "${checked_runtimes}" -ge 1 ]] || fail "no JSON runtime is installed: the release list cannot be read"

# 49. The output of a function is checked: a function that prints an
# answer it cannot write returns a failure, and never a success.
output_dir=${test_root}/output-check
mkdir -p "${output_dir}"
output_page=${output_dir}/releases.json
cp "${release_list}" "${output_page}"

# check_output_failure runs a function of the action with an output that
# cannot be written, and fails when the function returns a success.
#
# The mode "full" writes the output of the function to /dev/full, so that
# the write fails with a full device. The mode "printf" replaces printf
# with a function that fails on the answer of the function under test, so
# that the check runs on every machine.
check_output_failure() {
  local function=$1
  local mode=$2
  shift 2
  local status=0
  bash -c '
    set -uo pipefail
    source "$1"
    trap - ERR
    set +e
    # The name of the variable of the page is not the one of the action:
    # resolve_major_release hides a variable of its own.
    release_page=$2
    function_name=$3
    mode=$4
    shift 4
    api_get() { cat "${release_page}"; }
    expected=$("${function_name}" "$@" 2>/dev/null)
    if [[ -z "${expected}" ]]; then
      echo "the function ${function_name} printed no answer" >&2
      exit 3
    fi
    if [[ "${mode}" == "printf" ]]; then
      printf() {
        local format=$1
        shift
        if [[ "${format}" == "%s\n" && "$#" -eq 1 && "${1}" == "${expected}" ]]; then
          echo "printf: write error" >&2
          return 1
        fi
        builtin printf "${format}" "$@"
      }
      "${function_name}" "$@" >/dev/null 2>&1
    else
      if [[ ! -c /dev/full ]]; then
        echo "/dev/full does not exist on this machine" >&2
        exit 4
      fi
      "${function_name}" "$@" >/dev/full 2>/dev/null
    fi
    status=$?
    if [[ "${status}" -eq 0 ]]; then
      echo "the function ${function_name} returned success although its output failed" >&2
      exit 1
    fi
    exit 0
  ' bash "${repo_root}/action/run.sh" "${output_page}" "${function}" "${mode}" "$@" || status=$?
  case "${status}" in
    0) ;;
    4) echo "action/run_test.sh: note: /dev/full does not exist on this machine: the output failure of ${function} is checked with a failing printf" ;;
    *) fail "the function ${function} returned success although its output failed" ;;
  esac
}

check_output_failure json_runtime printf
check_output_failure release_page_fields printf "${output_page}"
check_output_failure resolve_major_release printf 0 HarnageaGabriel/disdetta "${output_dir}"
if [[ -c /dev/full ]]; then
  check_output_failure json_runtime full
  check_output_failure release_page_fields full "${output_page}"
  check_output_failure resolve_major_release full 0 HarnageaGabriel/disdetta "${output_dir}"
else
  echo "action/run_test.sh: note: /dev/full does not exist on this machine: the output failure is checked with a failing printf"
fi

echo "action/run_test.sh: skipped ${skip_count} case(s)"
echo "action/run_test.sh: PASS"

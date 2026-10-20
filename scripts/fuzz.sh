#!/bin/sh
set -eu

fuzztime=${1:-30s}
targets=$(mktemp "${TMPDIR:-/tmp}/disdetta-fuzz.XXXXXX")
trap 'rm -f "$targets"' EXIT HUP INT TERM

go list ./... | while IFS= read -r package; do
	go test "$package" -list '^Fuzz' | while IFS= read -r target; do
		case "$target" in
			Fuzz*) printf '%s %s\n' "$package" "$target" ;;
		esac
	done
done >"$targets"

if [ ! -s "$targets" ]; then
	echo "no fuzz targets found" >&2
	exit 1
fi

while IFS=' ' read -r package target; do
	echo "==> $package: $target ($fuzztime)"
	if output=$(go test "$package" -run='^$' -fuzz="^${target}$" -fuzztime="$fuzztime" 2>&1); then
		printf '%s\n' "$output"
		continue
	else
		status=$?
	fi
	printf '%s\n' "$output" >&2
	package_dir=$(go list -f '{{.Dir}}' "$package")
	crasher=$(printf '%s\n' "$output" | sed -n 's|.*\(testdata/fuzz/[^[:space:]]*\).*|\1|p' | tail -n 1)
	if [ -n "$crasher" ]; then
		echo "crashing input: $package_dir/$crasher" >&2
	else
		echo "crashing input (if written): $package_dir/testdata/fuzz/$target/" >&2
	fi
	exit "$status"
done <"$targets"

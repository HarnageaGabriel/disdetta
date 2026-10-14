#!/bin/sh
# Coverage floors (spec section 10; review 02 F16): internal/imageref,
# internal/detect and internal/report must stay at or above 80% statements.
#
# Usage: sh scripts/cover-floors.sh [coverage.out]
set -eu

profile="${1:-coverage.out}"
floors="internal/imageref:80 internal/detect:80 internal/report:80"

if [ ! -f "$profile" ]; then
	echo "coverage-floors: profile $profile not found" >&2
	exit 1
fi

awk -v floors="$floors" '
BEGIN {
	n = split(floors, parts, " ")
	for (i = 1; i <= n; i++) {
		split(parts[i], pair, ":")
		pkg = pair[1]
		floor[pkg] = pair[2] + 0
		order[i] = pkg
	}
}
/^mode:/ { next }
NF >= 3 {
	file = $1
	sub(/:[0-9]+\.[0-9]+,.*/, "", file)
	statements = $2 + 0
	count = $3 + 0
	for (i = 1; i <= n; i++) {
		pkg = order[i]
		if (file ~ ("(^|/)" pkg "/")) {
			total[pkg] += statements
			if (count > 0) {
				covered[pkg] += statements
			}
			break
		}
	}
}
END {
	failed = 0
	for (i = 1; i <= n; i++) {
		pkg = order[i]
		if (total[pkg] == 0) {
			printf "coverage-floors: %s: no coverage data\n", pkg
			failed = 1
			continue
		}
		percent = covered[pkg] / total[pkg] * 100
		printf "coverage-floors: %s %.1f%% (floor %d%%)\n", pkg, percent, floor[pkg]
		if (percent + 0.0001 < floor[pkg]) {
			printf "coverage-floors: %s below floor: %.1f%% < %d%%\n", pkg, percent, floor[pkg]
			failed = 1
		}
	}
	if (failed) {
		printf "coverage-floors: FAILED\n"
	}
	exit failed
}
' "$profile"
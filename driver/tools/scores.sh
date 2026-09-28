#!/bin/bash
# Summarise fingerprint verification from fprintd's journal (logging set up by
# install-driver.sh).
#
#   driver/tools/scores.sh [SINCE]      e.g. driver/tools/scores.sh "7 days ago" (default)
#
# Counts every verify result fprintd reported (lock screen, login, sudo, fprintd-verify),
# including retries such as "too fast", with the best matcher score of each swipe (>= 40 is a
# match). Scores from fprintd's duplicate check during enrollment are not counted.
since="${1:-7 days ago}"
journalctl -u fprintd --since "$since" -o short-unix --no-pager 2>/dev/null |
	awk -v since="$since" '
	/ score -?[0-9]+\/[0-9]+/ {
		match($0, / score -?[0-9]+\//); s = substr($0, RSTART + 7, RLENGTH - 8) + 0
		if ($1 - last > 1) best = s; else if (s > best) best = s
		last = $1; scored = 1
		next
	}
	/(verify|identify)_cb: result / {
		r = $NF; n++; count[r]++
		if (scored && $1 - last <= 2) {
			if (r ~ /no-match$/) low = low " " best
			else if (r ~ /-match$/) { ms++; msum += best; if (!mmin || best < mmin) mmin = best }
		}
		scored = 0
	}
	END {
		if (!n) { print "no verification logged since " since; exit }
		printf "%d results since %s:\n", n, since
		for (r in count) printf "  %-28s %d\n", r, count[r]
		if (ms) printf "matches: average score %.0f, lowest %d (40 needed)\n", msum / ms, mmin
		if (low != "") printf "no-match best scores:%s\n", low
	}'

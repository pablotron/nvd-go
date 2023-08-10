#!/usr/bin/env ruby
# frozen_string_literal: true

#
# format-tests.rb: Read output of `scripts/random-vectors.js` from
# stdin, write elements for `tests` array in `TestVectorScores()` in
# `cvss/v3{0,1}/scores_test.go` to standard output.
#
# Examples:
#
#   # generate test vectors and scores for cvss/v30/scores_test.go
#   scripts/random-vectors.js v30 | scripts/format-test-scores.rb
#
#   # generate test vectors and scores for cvss/v31/scores_test.go
#   scripts/random-vectors.js v31 | scripts/format-test-scores.rb
#

require 'json'

# templates
T = {
  # row template
  row: '{ name: "%<vector>s", val: "%<vector>s", exp: cvss.MustParseScores(%<base>s, %<temporal>s, %<env>s) },',

  # non-nil score
  score_ptr: 'fp(%s)',

  # nil score
  score_nil: 'nil',
}

def maybe_score(v)
  T[v == '0.0' ? :score_nil : :score_ptr] % [v]
end

# read rows from stdin, format as tests, write to stdout
puts(JSON(STDIN.read).map do |row|
  T[:row] % {
    vector: row[0],
    base: row[1],
    temporal: maybe_score(row[2]),
    env: maybe_score(row[3]),
  }
end.join("\n"))

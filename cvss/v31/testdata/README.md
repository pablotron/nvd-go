CVSS v3.1 Test Data
===================

* `gen-scores.rb`: Read vulnerabilities from source path, extract CVSS
  v3.1 vector strings, base scores, and base severities for each
  vulnerability, and write gzip-compressed, JSON-encoded results to
  destination path.
* `v31-scores.json.gz`: output from `get-scores.rb`.  Used by
  `TestMoreVectorScores()` in `../scores_test.go`.

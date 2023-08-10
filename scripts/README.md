# Utility Scripts

Miscellaneous scripts used to generate code and tests.

* `gen-enums.rb`: Generate enumerated string constant code and unit
  tests in `cvss/{v2,v30,v31}/enums{,_test}.go`
* `format-tests.rb`: Read output of `random-vectors.js` from stdin,
  write test entries for `TestVectorScores()` to stdout.
* `random-vectors.js`: Generate random CVSS v3.1 vectors and their
  base, temporal, and environmental scores.
* `cvsscalc30.js`: Calculator code from official NVD CVSS v3.0
  calculator.  Used by `random-vectors.js` to generate expected scores.
* `cvsscalc31.js`: Calculator code from official NVD CVSS v3.1
  calculator.  Used by `random-vectors.js` to generate expected scores.

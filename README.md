# nvd-go

[Go][] module for interacting with [NVD][] data.  Includes support for
the following data types:

* [Common Platform Enumeration (CPE)][cpe] names and match strings.
* [Common Vulnerability and Exposures (CVE)][cve] identifiers.
* [Common Vulnerability Scoring System (CVSS)][cvss] vectors (v2.0, v3.0, and v3.1).
* [NVD REST 2.0 API][api].

**Note:** In order to use the NVD API package, you need to [obtain an
NVD API key from NIST][api-key].

## Documentation

TODO

## Usage

Several examples are available in the `examples/` directory.

## Tests

Use the following make targets to run the test suite, linters, and check
code coverage:

* `test`: Run unit tests.
* `check`: Run linters (`go vet`, `staticcheck`, `golangci-lint`, and `govulncheck`).
* `cov`: Generate code coverage report.
* `covhtml`: Generate HTML-formatted code coverage report.

Use the `test` make target to run the test suite:

## License

TODO: MIT-0

[cpe]: https://en.wikipedia.org/wiki/Common_Platform_Enumeration
  "Common Platform Enumeration."
[cve]: https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures
  "Common Vulnerabilities and Exposures."
[cvss]: https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System
  "Common Vulnerability Scoring System."
[go]: https://go.dev/
  "Go programming language."
[nvd]: https://nvd.nist.gov/
  "National Vulnerability Database."
[api]: https://nvd.nist.gov/developers/
  "NVD Application Programming Interface."
[api-key]: https://nvd.nist.gov/developers/start-here
  "Obtain an NVD REST 2.0 API key from NIST."

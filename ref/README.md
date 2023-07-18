# Reference Data

Use the `gen-enums.rb` script to generate a [Go][] package from the
given [JSON Schema][] file.

Example:

    # generate cvss31/cvss31.go from 
    ./gen-enums.rb cvss31 < cvss-v3.1.json > cvss31/cvss31.go

## Endpoints

NVD API endpoints and documentation.

### Data Sources

* Documentation: <https://nvd.nist.gov/developers/data-sources>
* API Endpoint: <https://services.nvd.nist.gov/rest/json/source/2.0>

### Products

* Documentation: <https://nvd.nist.gov/developers/products>

#### CPE API

* Endpoint: <https://services.nvd.nist.gov/rest/json/cpes/2.0>

#### Match Criteria API

* Endpoint: <https://services.nvd.nist.gov/rest/json/cpematch/2.0>

### Vulnerabilities

#### CVE API

* Documentation: <https://nvd.nist.gov/developers/vulnerabilities>
* Endpoint: <https://services.nvd.nist.gov/rest/json/cves/2.0>

#### CVE Change History API

* Endpoint: <https://services.nvd.nist.gov/rest/json/cvehistory/2.0>

[go]: https://go.dev/
  "Go programming language."
[json schema]: https://json-schema.org/
  "JSON schema."

package nvd_api

import (
  "errors"
  "fmt"
  "pablotron.org/nvd-go/cpe"
  "pablotron.org/nvd-go/cve"
  "pablotron.org/nvd-go/cvss"
  "pablotron.org/nvd-go/cwe"
  "pablotron.org/nvd-go/rfc3339"
  "pablotron.org/nvd-go/url-params"
)

// Search parameters for `Cves()` method.
type CveParams struct {
  CpeName *cpe.Name `url:"cpeName"`
  CveId *cve.Id `url:"cveId"`
  CvssV2Metrics string `url:"cvssV2Metrics"`
  CvssV2Severity cvss.Severity `url:"cvssV2Severity"`
  CvssV3Metrics string `url:"cvssV3Metrics"`
  CvssV3Severity cvss.Severity `url:"cvssV3Severity"`
  CweId *cwe.Id `url:"cweId"`
  HasCertAlerts bool `url:"hasCertAlerts"`
  HasCertNotes bool `url:"hasCertNotes"`
  HasKev bool `url:"hasKev"`
  HasOval bool `url:"hasOval"`
  IsVulnerable bool `url:"isVulnerable"`
  KeywordExactMatch bool `url:"keywordExactMatch"`
  KeywordSearch string `url:"keywordSearch"`
  LastModStartDate *rfc3339.Time `url:"lastModStartDate"`
  LastModEndDate *rfc3339.Time `url:"lastModEndDate"`
  NoRejected bool `url:"noRejected"`
  PubStartDate *rfc3339.Time `url:"pubStartDate"`
  PubEndDate *rfc3339.Time `url:"pubEndDate"`
  ResultsPerPage uint `url:"resultsPerPage"`
  StartIndex uint `url:"startIndex"`
  SourceIdentifier string `url:"sourceIdentifier"`
  VersionStart string `url:"versionStart"`
  VersionStartType VersionType `url:"versionStartType"`
  VersionEnd string `url:"versionEnd"`
  VersionEndType VersionType `url:"versionEndType"`
  VirtualMatchString *cpe.Match `url:"virtualMatchString"`
}

// Error returned by Check() if both CVSS V2 metrics and CVSS V3 metrics
// are provided.
var errCveParamsInvalidMetricsPair = errors.New("cannot include both CVSS V2 metrics and CVSS V3 metrics")

// Error returned by Check() if both CVSS V2 severity and CVSS V3
// severity are provided.
var errCveParamsInvalidSeverityPair = errors.New("cannot include both CVSS V2 severity and CVSS V3 severity")

// Error returned by Check() if the given CVSS V2 severity is not a
// valid CVSS V2 severity.
var errCveParamsInvalidV2Severity = errors.New("invalid CVSS V2 severity")

// Error returned by Check() if the given CVSS V3 severity is not a
// valid CVSS V3 severity.
var errCveParamsInvalidV3Severity = errors.New("invalid CVSS V3 severity")

// Error returned by Check() if IsVulnerable is set without
// providing a CpeName.
var errCveParamsIsVulnerableWithoutCpeName = errors.New("isVulnerable without cpeName")

// Error returned by Check() if both IsVulnerable and VirtualMatchString
// are set.
var errCveParamsIsVulnerableWithVirtualMatchString = errors.New("isVulnerable with virtualMatchString")

// Error returned by Check() if KeywordExactMatch is set without
// providing a KeywordSearch value.
var errCveParamsKeywordExactMatch = errors.New("keywordExactMatch without keywordSearch")

// Error returned by Check() if versionEnd is set without
// versionEndType.
var errCveParamsMissingVersionEndType = errors.New("versionEnd without versionEndType")

// Error returned by Check() if versionEndType is set without
// versionEnd.
var errCveParamsMissingVersionEnd = errors.New("versionEndType without versionEnd")

// Error returned by Check() if versionStart is set without
// versionStartType.
var errCveParamsMissingVersionStartType = errors.New("versionStart without versionStartType")

// Error returned by Check() if versionStartType is set without
// versionStart.
var errCveParamsMissingVersionStart = errors.New("versionStartType without versionStart")

// maximum value for CveParams ResultsPerPage parameter.
const cveParamsMaxResultsPerPage = 2000

// Check CVE parameters for validity.
func (cp CveParams) Check() error {
  // check for invalid v2 and v3 metrics combination
  if cp.CvssV2Metrics != "" && cp.CvssV3Metrics != "" {
    return errCveParamsInvalidMetricsPair
  }

  // check for invalid v2 and v3 severity combination
  if cp.CvssV2Severity != cvss.Unknown && cp.CvssV3Severity != cvss.Unknown {
    return errCveParamsInvalidSeverityPair
  }

  // check for invalid cvss v2 severity
  if cp.CvssV2Severity != cvss.Unknown && !cvss.V2.ValidSeverity(cp.CvssV2Severity) {
    return errCveParamsInvalidV2Severity
  }

  // check for invalid cvss v3 severity
  if cp.CvssV3Severity != cvss.Unknown && !cvss.V30.ValidSeverity(cp.CvssV3Severity) {
    return errCveParamsInvalidV3Severity
  }

  // check results per page
  if cp.ResultsPerPage > cveParamsMaxResultsPerPage {
    return fmt.Errorf("results per page out of bounds: %d > %d", cp.ResultsPerPage, cveParamsMaxResultsPerPage)
  }

  // if isVulnerable is provided, cpeName is required
  if cp.IsVulnerable && cp.CpeName == nil {
    return errCveParamsIsVulnerableWithoutCpeName
  }

  // check for both isVulnerable and virtualMatchString
  if cp.IsVulnerable && cp.VirtualMatchString != nil {
    return errCveParamsIsVulnerableWithVirtualMatchString
  }

  // check for keywordExactMatch w/o keywordSearch
  if cp.KeywordExactMatch && cp.KeywordSearch == "" {
    return errCveParamsKeywordExactMatch
  }

  // check lastMod date range validity
  if err := checkDateRange("lastMod", cp.LastModStartDate, cp.LastModEndDate); err != nil {
    return err
  }

  // check pubDate date range validity
  if err := checkDateRange("pub", cp.PubStartDate, cp.PubEndDate); err != nil {
    return err
  }

  // check for versionEnd without versionEndType
  if cp.VersionEnd != "" && cp.VersionEndType == DefaultVersionType {
    return errCveParamsMissingVersionEndType
  } else if cp.VersionEnd == "" && cp.VersionEndType != DefaultVersionType {
    return errCveParamsMissingVersionEnd
  }

  // check for versionStart without versionStartType
  if cp.VersionStart != "" && cp.VersionStartType == DefaultVersionType {
    return errCveParamsMissingVersionStartType
  } else if cp.VersionStart == "" && cp.VersionStartType != DefaultVersionType {
    return errCveParamsMissingVersionStart
  }

  // TODO: enforce VirtualMatchString parameter constraints

  // return success
  return nil
}

// Get parameters encoded as URL query string.
//
// Returns an error if any of the search parameters are invalid or if an
// invalid combination of search parameters was provided.
func (cp *CveParams) QueryString() (string, error) {
  // check for invalid parameter combinations
  if err := cp.Check(); err != nil {
    return "", err
  }

  // encode parameters as URL query string
  return url_params.Encode(cp)
}

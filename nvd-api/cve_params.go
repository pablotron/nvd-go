package nvd_api

import (
  "errors"
  "fmt"
  "pmdn.org/nvd-go/cpe"
  "pmdn.org/nvd-go/cve"
  "pmdn.org/nvd-go/cvss"
  "pmdn.org/nvd-go/cwe"
  "pmdn.org/nvd-go/rfc3339"
  "pmdn.org/nvd-go/url-params"
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

// Error returned by Check() if IsVulernable is set without
// providing a CpeName.
var errCveParamsIsVulnerableWithoutCpeName = errors.New("isVulnerable without cpeName")

// Error returned by Check() if both IsVulernable and VirtualMatchString
// are set.
var errCveParamsIsVulnerableWithVirtualMatchString = errors.New("isVulnerable with virtualMatchString")

// Error returned by Check() if IsVulernable is set without
// providing a CpeName.
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

// maximum value for ResultsPerPage parameter.
const maxResultsPerPage = 2000

// maximum number of days for date ranges
const maxDateRangeDays = 120.0

func checkDateRange(name string, start, end *rfc3339.Time) error {
  if start == nil && end == nil {
    return nil
  } else if start != nil && end == nil {
    return fmt.Errorf("missing %sEndDate", name)
  } else if start == nil && end != nil {
    return fmt.Errorf("missing %sStartDate", name)
  }

  // convert start to time.Time
  startTime, err := start.Time()
  if err != nil {
    return fmt.Errorf("invalid %sStartDate: %w", name, err)
  }

  // convert end to time.Time
  endTime, err := end.Time()
  if err != nil {
    return fmt.Errorf("invalid %sEndDate: %w", name, err)
  }

  // get duration between start and end (in days)
  days := endTime.Sub(*startTime).Hours() * 24.0

  // check for valid date range duration
  if days < 0.0 || days > maxDateRangeDays {
    return fmt.Errorf("%s date range duration out of range: %f", name, days)
  }

  // return success
  return nil
}

// Check CVE parameters for validity.
func (cp CveParams) Check() error {
  // check for invalid v2 and v3 metrics combination
  if cp.CvssV2Metrics != "" && cp.CvssV3Metrics != "" {
    return errCveParamsInvalidMetricsPair
  }

  // check for invalid v2 and v3 metrics combination
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
  if cp.ResultsPerPage > maxResultsPerPage {
    return fmt.Errorf("results per page out of bounds: %d > %d", cp.ResultsPerPage, maxResultsPerPage)
  }

  // if isVulnerable is provided, cpeName is required
  if cp.IsVulnerable && cp.CpeName == nil {
    return errCveParamsIsVulnerableWithoutCpeName
  }

  // check for both isVulnerable and virtualMatchString
  if cp.IsVulnerable && cp.VirtualMatchString != nil {
    return errCveParamsIsVulnerableWithVirtualMatchString
  }

  // check for both isVulnerable and virtualMatchString
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

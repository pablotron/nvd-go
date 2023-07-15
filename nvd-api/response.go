package nvd_api

import "pmdn.org/nvd-go/rfc3339"

// API response
type Response struct {
  ResultsPerPage int `json:"resultsPerPage"`
  StartIndex int `json:"startIndex"`
  TotalResults int `json:"totalResults"`
  Format string `json:"format"`
  Version string `json:"version"`
  Timestamp *rfc3339.Time `json:"timestamp"`
  Vulnerabilities *[]Vulnerability `json:"vulnerabilities"`
}

package nvd_api

import (
  "pmdn.org/nvd-go/rfc3339"
)

// NVD API response.
type Response struct {
  ResultsPerPage uint `json:"resultsPerPage"`
  StartIndex uint `json:"startIndex"`
  TotalResults uint `json:"totalResults"`
  Format Format `json:"format"`
  Version VersionString `json:"version"`
  Timestamp *rfc3339.DateTime `json:"timestamp"`
  Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
  CveChanges []CveChange `json:"cveChanges,omitempty"`
  Products []Product `json:"products,omitempty"`
  MatchStrings []MatchString `json:"matchStrings,omitempty"`
  Sources []Source `json:"sources,omitempty"`
}

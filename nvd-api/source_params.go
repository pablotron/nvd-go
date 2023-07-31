package nvd_api

import (
  "fmt"
  "pmdn.org/nvd-go/rfc3339"
  "pmdn.org/nvd-go/url-params"
)

// Search parameters for `Sources()` method.
type SourceParams struct {
  LastModStartDate *rfc3339.Time `url:"lastModStartDate"`
  LastModEndDate *rfc3339.Time `url:"lastModEndDate"`
  SourceIdentifier string `url:"sourceIdentifier"`
  ResultsPerPage uint `url:"resultsPerPage"`
  StartIndex uint `url:"startIndex"`
}

// maximum value for SourceParams ResultsPerPage parameter.
const sourceParamsMaxResultsPerPage = 1000

// Check source parameters for validity.
func (p SourceParams) Check() error {
  // check results per page
  if p.ResultsPerPage > sourceParamsMaxResultsPerPage {
    return fmt.Errorf("results per page out of bounds: %d > %d", p.ResultsPerPage, sourceParamsMaxResultsPerPage)
  }

  // check lastMod date range validity
  if err := checkDateRange("lastMod", p.LastModStartDate, p.LastModEndDate); err != nil {
    return err
  }

  // return success
  return nil
}

// Get source parameters encoded as URL query string.
//
// Returns an error if any of the search parameters are invalid or if an
// invalid combination of search parameters was provided.
func (p *SourceParams) QueryString() (string, error) {
  // check for invalid parameter combinations
  if err := p.Check(); err != nil {
    return "", err
  }

  // encode parameters as URL query string
  return url_params.Encode(p)
}

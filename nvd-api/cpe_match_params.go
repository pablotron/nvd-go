package nvd_api

import (
  "fmt"
  "github.com/google/uuid"
  "pmdn.org/nvd-go/cpe"
  "pmdn.org/nvd-go/cve"
  "pmdn.org/nvd-go/rfc3339"
  "pmdn.org/nvd-go/url-params"
)

// Search parameters for `CpeMatches()` method.
type CpeMatchParams struct {
  CveId *cve.Id `url:"cveId"`
  LastModStartDate *rfc3339.Time `url:"lastModStartDate"`
  LastModEndDate *rfc3339.Time `url:"lastModEndDate"`
  MatchCriteriaId uuid.UUID `url:"matchCriteriaId"`
  MatchStringSearch *cpe.Match `url:"matchStringSearch"`
  ResultsPerPage uint `url:"resultsPerPage"`
  StartIndex uint `url:"startIndex"`
}

// maximum value for CpeMatchParams ResultsPerPage parameter.
const cpeMatchParamsMaxResultsPerPage = 5000

// Check CPE match parameters for validity.
func (p CpeMatchParams) Check() error {
  // check results per page
  if p.ResultsPerPage > cpeMatchParamsMaxResultsPerPage {
    return fmt.Errorf("results per page out of bounds: %d > %d", p.ResultsPerPage, cpeMatchParamsMaxResultsPerPage)
  }

  // check lastMod date range validity
  if err := checkDateRange("lastMod", p.LastModStartDate, p.LastModEndDate); err != nil {
    return err
  }

  // return success
  return nil
}

// Get CPE match parameters encoded as URL query string.
//
// Returns an error if any of the search parameters are invalid or if an
// invalid combination of search parameters was provided.
func (p *CpeMatchParams) QueryString() (string, error) {
  // check for invalid parameter combinations
  if err := p.Check(); err != nil {
    return "", err
  }

  // encode parameters as URL query string
  return url_params.Encode(p)
}

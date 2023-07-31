package nvd_api

import (
  "errors"
  "fmt"
  "github.com/google/uuid"
  "pmdn.org/nvd-go/cpe"
  "pmdn.org/nvd-go/rfc3339"
  "pmdn.org/nvd-go/url-params"
)

// Search parameters for `Cpes()` method.
type CpeParams struct {
  CpeNameId uuid.UUID `url:"cpeNameId"`
  CpeMatchString *cpe.Match `url:"cpeMatchString"`
  KeywordExactMatch bool `url:"keywordExactMatch"`
  KeywordSearch string `url:"keywordSearch"`
  LastModStartDate *rfc3339.Time `url:"lastModStartDate"`
  LastModEndDate *rfc3339.Time `url:"lastModEndDate"`
  MatchCriteriaId uuid.UUID `url:"matchCriteriaId"`
  ResultsPerPage uint `url:"resultsPerPage"`
  StartIndex uint `url:"startIndex"`
}

// Error returned by Check() if KeywordExactMatch is set without
// providing a KeywordSearch value.
var errCpeParamsKeywordExactMatch = errors.New("keywordExactMatch without keywordSearch")

// maximum value for CpeParams ResultsPerPage parameter.
const cpeParamsMaxResultsPerPage = 10000

// Check CPE parameters for validity.
func (p CpeParams) Check() error {
  // check results per page
  if p.ResultsPerPage > cpeParamsMaxResultsPerPage {
    return fmt.Errorf("results per page out of bounds: %d > %d", p.ResultsPerPage, cpeParamsMaxResultsPerPage)
  }

  // check for keywordExactMatch w/o keywordSearch
  if p.KeywordExactMatch && p.KeywordSearch == "" {
    return errCpeParamsKeywordExactMatch
  }

  // check lastMod date range validity
  if err := checkDateRange("lastMod", p.LastModStartDate, p.LastModEndDate); err != nil {
    return err
  }

  // return success
  return nil
}

// Get CPE parameters encoded as URL query string.
//
// Returns an error if any of the search parameters are invalid or if an
// invalid combination of search parameters was provided.
func (p *CpeParams) QueryString() (string, error) {
  // check for invalid parameter combinations
  if err := p.Check(); err != nil {
    return "", err
  }

  // encode parameters as URL query string
  return url_params.Encode(p)
}

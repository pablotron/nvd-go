package nvd_api

import (
  "fmt"
  "pablotron.org/nvd-go/cve"
  "pablotron.org/nvd-go/rfc3339"
  "pablotron.org/nvd-go/url-params"
)

// Search parameters for `CveHistory()` method.
type CveHistoryParams struct {
  CveId *cve.Id `url:"cveId"`
  ChangeStartDate *rfc3339.Time `url:"changeStartDate"`
  ChangeEndDate *rfc3339.Time `url:"changeEndDate"`
  EventName cve.EventName `url:"eventName"`
  ResultsPerPage uint `url:"resultsPerPage"`
  StartIndex uint `url:"startIndex"`
}

// maximum value for CveHistoryParams ResultsPerPage parameter.
const cveHistoryParamsMaxResultsPerPage = 5000

// Check CVE parameters for validity.
func (p CveHistoryParams) Check() error {
  // check results per page
  if p.ResultsPerPage > cveHistoryParamsMaxResultsPerPage {
    return fmt.Errorf("results per page out of bounds: %d > %d", p.ResultsPerPage, cveHistoryParamsMaxResultsPerPage)
  }

  // check lastMod date range validity
  if err := checkDateRange("change", p.ChangeStartDate, p.ChangeEndDate); err != nil {
    return err
  }

  // return success
  return nil
}

// Get parameters encoded as URL query string.
//
// Returns an error if any of the parameters are invalid or if an
// invalid combination of parameters was provided.
func (p *CveHistoryParams) QueryString() (string, error) {
  // check for invalid parameter combinations
  if err := p.Check(); err != nil {
    return "", err
  }

  // encode parameters as URL query string
  return url_params.Encode(p)
}

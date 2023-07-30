// NVD API client
package nvd_api

import (
  "fmt"
  net_url "net/url"
  "pmdn.org/nvd-go/rfc3339"
)

// Default NVD API URL.
var DefaultUrl = net_url.URL {
  Scheme: "https",
  Host: "services.nvd.nist.gov",
  Path: "/rest/json",
}

// maximum number of days for date ranges
const maxDateRangeDays = 120.0

// Check for valid date range.  Used by CveParams.Check() and
// CveHistoryParams.Check().
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

// NVD API client
package nvd_api

import (
  net_url "net/url"
)

// Default NVD API URL.
var DefaultUrl = net_url.URL {
  Scheme: "https",
  Host: "services.nvd.nist.gov",
  Path: "/rest/json",
}

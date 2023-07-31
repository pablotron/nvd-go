package nvd_api

import (
  "pmdn.org/nvd-go/rfc3339"
)
// NVD API data source.
type Source struct {
  ContactEmail string `json:"contactEmail"`
  LastModified rfc3339.DateTime `json:"lastModified"`
  Created rfc3339.DateTime `json:"published"`
  V2AcceptanceLevel *AcceptanceLevel `json:"v2AcceptanceLevel"`
  V3AcceptanceLevel *AcceptanceLevel `json:"v3AcceptanceLevel"`
  CweAcceptanceLevel *AcceptanceLevel `json:"cweAcceptanceLevel"`
  SourceIdentifiers []string `json:"sourceIdentifiers"`
}

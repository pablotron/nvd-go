package nvd_api

import (
  "pmdn.org/nvd-go/rfc3339"
)
// NVD API data source.
type Source struct {
  // FIXME: not documented in `source_api_json_2.0.schema`, but present
  // in `responses/sources-20.json.gz`.
  Name string `json:"name"`
  ContactEmail string `json:"contactEmail"`
  LastModified rfc3339.DateTime `json:"lastModified"`
  Created rfc3339.DateTime `json:"published"`
  V2AcceptanceLevel *AcceptanceLevel `json:"v2AcceptanceLevel"`
  V3AcceptanceLevel *AcceptanceLevel `json:"v3AcceptanceLevel"`
  CweAcceptanceLevel *AcceptanceLevel `json:"cweAcceptanceLevel"`
  SourceIdentifiers []string `json:"sourceIdentifiers"`
}

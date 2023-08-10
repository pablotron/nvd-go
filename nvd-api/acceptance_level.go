package nvd_api

import "pablotron.org/nvd-go/rfc3339"

// Source acceptance level.
type AcceptanceLevel struct {
  Description string `json:"description"`
  LastModified rfc3339.DateTime `json:"lastModified"`
}

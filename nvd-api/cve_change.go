package nvd_api

import (
  "github.com/google/uuid"
  "pablotron.org/nvd-go/cve"
  "pablotron.org/nvd-go/rfc3339"
)

type CveChange struct {
  Change struct {
    Id cve.Id `json:"id"`
    EventName cve.EventName `json:"eventName"`
    CveChangeId uuid.UUID `json:"cveChangeId"`
    SourceIdentifier *string `json:"sourceIdentifier"`
    Created rfc3339.DateTime `json:"created"`
    Details []struct {
      Action string `json:"action"` // TODO: enum Added/Changed/Removed
      Type string `json:"type"`
      OldValue string `json:"oldValue"`
      NewValue string `json:"newValue"`
    } `json:"details"`
  } `json:"change"`
}

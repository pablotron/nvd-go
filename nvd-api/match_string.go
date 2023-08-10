package nvd_api

import (
  "github.com/google/uuid"
  "pablotron.org/nvd-go/cpe"
  "pablotron.org/nvd-go/rfc3339"
)

type MatchString struct {
  MatchString struct {
    Criteria cpe.Match `json:"criteria"`
    MatchCriteriaId uuid.UUID `json:"matchCriteriaId"`
    VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
    VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
    VersionEndExcluding string `json:"versionEndExcluding,omitempty"`
    VersionEndIncluding string `json:"versionEndIncluding,omitempty"`
    Created rfc3339.DateTime `json:"created"`
    LastModified rfc3339.DateTime `json:"lastModified"`
    CpeLastModified rfc3339.DateTime `json:"cpeLastModified"`
    Status string `json:"string"`
    Matches []struct {
      CpeName cpe.Match `json:"cpeName"`
      CpeNameId uuid.UUID `json:"cpeNameId"`
    } `json:"matches"`
  } `json:"matchString"`
}

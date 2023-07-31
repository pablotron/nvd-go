package nvd_api

import (
  "github.com/google/uuid"
  "pmdn.org/nvd-go/cpe"
  "pmdn.org/nvd-go/rfc3339"
)

type Product struct {
  Cpe struct {
    Deprecated bool `json:"deprecated"`
    CpeName cpe.Name `json:"cpeName"`
    CpeNameId uuid.UUID `url:"cpeNameId"`
    LastModified *rfc3339.DateTime `json:"lastModified"`
    Created *rfc3339.DateTime `json:"created"`
    Titles []LangString `json:"titles"`

    Refs []struct {
      // FIXME: the type of this element is "RefUrl", but the
      // reference URLs pattern in `ref/cpe_api_json_2.0.schema`
      // is less constrained than the reference URL pattern in
      // `ref/cve_api_json_2.0.schema`.
      Ref RefUrl `json:"url"`
      Type RefType `json:"type"`
    } `json:"refs"`

    DeprecatedBy []struct {
      CpeName cpe.Name `json:"cpeName"`
      CpeNameId uuid.UUID `url:"cpeNameId"`
    } `json:"deprecatedBy"`

    Deprecates []struct {
      CpeName cpe.Name `json:"cpeName"`
      CpeNameId uuid.UUID `url:"cpeNameId"`
    } `json:"deprecates"`
  } `json:"cpe"`
}

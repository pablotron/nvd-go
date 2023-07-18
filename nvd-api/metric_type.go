package nvd_api

import "fmt"

// CVSS metric type (primary or secondary).
type MetricType byte

const (
  InvalidMetricType MetricType = iota
  Primary // AND
  Secondary // OR
)

// Unmarshal metric type
func (t *MetricType) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "Primary":
    *t = Primary
    return nil
  case "Secondary":
    *t = Secondary
    return nil
  default:
    return fmt.Errorf("invalid metric type: \"%s\"", s)
  }
}

// Marshal metric type to text.
func (t *MetricType) MarshalText() ([]byte, error) {
  return []byte(t.String()), nil
}

// Convert metric type to string.
func (t MetricType) String() string {
  switch t {
  case Primary:
    return "Primary"
  case Secondary:
    return "Secondary"
  default:
    return ""
  }
}

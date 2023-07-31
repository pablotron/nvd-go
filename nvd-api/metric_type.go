package nvd_api

import "fmt"

// CVSS metric type (primary or secondary).
type MetricType uint8

const (
  InvalidMetricType MetricType = iota
  Primary // Primary
  Secondary // Secondary
)

// Map of string to metric type.  Used by `UnmarshalText()`.
var metricTypeStrMap = map[string]MetricType {
  "Primary": Primary,
  "Secondary": Secondary,
}

// Unmarshal metric type from text.
func (t *MetricType) UnmarshalText(b []byte) error {
  s := string(b)
  if nt, ok := metricTypeStrMap[s]; ok {
    *t = nt
    return nil
  } else {
    return fmt.Errorf("invalid metric type: \"%s\"", s)
  }
}

// Marshal metric type to text.
func (t *MetricType) MarshalText() ([]byte, error) {
  return []byte(t.String()), nil
}

// Map of metric type to string.  Used by `String()`.
var metricTypeStrs = [...]string {
  "", // InvalidMetricType
  "Primary", // Primary
  "Secondary", // Secondary
}

// Convert metric type to string.
func (t MetricType) String() string {
  if int(t) < len(metricTypeStrs) {
    return metricTypeStrs[int(t)]
  } else {
    return ""
  }
}

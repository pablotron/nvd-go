package nvd_api

import "fmt"

type Format uint8

const (
  FormatUnknown Format = iota
  FormatCve
  FormatCveHistory
  FormatCpe
  FormatCpeMatch
  FormatSource
)

// string to format map
var formatMap = map[string]Format {
  "NVD_CVE": FormatCve,
  "NVD_CVEHistory": FormatCveHistory,
  "NVD_CPE": FormatCpe,
  "NVD_CPEMatchString": FormatCpeMatch,
  "NVD_SOURCE": FormatSource,
}

// Unmarshal byte slice as format.
func (f *Format) UnmarshalText(b []byte) error {
  s := string(b)
  if nf, ok := formatMap[s]; ok {
    *f = nf
    return nil
  } else {
    return fmt.Errorf("unknown format string: \"%s\"", s)
  }
}

// format strings
var formatStrs = [...]string {
  "",
  "NVD_CVE",
  "NVD_CVEHistory",
  "NVD_CPE",
  "NVD_CPEMatchString",
  "NVD_SOURCE",
}

// Convert format to string.
func (f Format) String() string {
  if int(f) < len(formatStrs) {
    return formatStrs[uint8(f)]
  } else {
    return ""
  }
}

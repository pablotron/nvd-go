package cve

import "fmt"

// CVE history event name.
type EventName uint8

const (
  None EventName = iota
  InitialAnalysis
  Reanalysis
  CveModified
  ModifiedAnalysis
  CveTranslated
  VendorComment
  CveSourceUpdate
  CpeDeprecationRemap
  CweRemap
  CveRejected
  CveUnrejected
)

// string to event name map
var eventNameMap = map[string]EventName {
  "Initial Analysis": InitialAnalysis,
  "Reanalysis": Reanalysis,
  "CVE Modified": CveModified,
  "Modified Analysis": ModifiedAnalysis,
  "CVE Translated": CveTranslated,
  "Vendor Comment": VendorComment,
  "CVE Source Update": CveSourceUpdate,
  "CPE Deprecation Remap": CpeDeprecationRemap,
  "CWE Remap": CweRemap,
  "CVE Rejected": CveRejected,
  "CVE Unrejected": CveUnrejected,
}

// Convert string to event name.
func (e *EventName) UnmarshalText(b []byte) error {
  s := string(b)
  if ne, ok := eventNameMap[s]; ok {
    *e = ne
    return nil
  } else {
    return fmt.Errorf("unknown event name: \"%s\"", s)
  }
}

// event name strings
var eventNames = [...]string {
  "", // None
  "Initial Analysis", // InitialAnalysis
  "Reanalysis", // Reanalysis
  "CVE Modified", // CveModified
  "Modified Analysis", // ModifiedAnalysis
  "CVE Translated", // CveTranslated
  "Vendor Comment", // VendorComment
  "CVE Source Update", // CveSourceUpdate
  "CPE Deprecation Remap", // CpeDeprecationRemap
  "CWE Remap", // CweRemap
  "CVE Rejected", // CveRejected
  "CVE Unrejected", // CveUnrejected
}

// Convert event name to string.
func (e EventName) String() string {
  if int(e) < len(eventNames) {
    return eventNames[uint8(e)]
  } else {
    return ""
  }
}

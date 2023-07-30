package cve

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

// event name string map
var eventNames = [...]string {
  "", // None
  "Initial Analysis", // InitialAnalysis
  "Renalysis", // Reanalysis
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

package nvd_api

import "fmt"

// Product reference type.
type RefType uint8

const (
  UnknownRefType RefType = iota
  AdvisoryRefType // Advisory
  ChangeLogRefType // Change Log
  ProductRefType // Product
  ProjectRefType // Project
  VendorRefType // Vendor
  VersionRefType // Version
)

// string to reference type map
var refTypeMap = map[string]RefType {
  "Advisory": AdvisoryRefType,
  "Change Log": ChangeLogRefType,
  "Product": ProductRefType,
  "Project": ProjectRefType,
  "Vendor": VendorRefType,
  "Version": VersionRefType,
}

// Unmarshal reference type from byte slice.
func (t *RefType) UnmarshalText(b []byte) error {
  s := string(b)
  if nt, ok := refTypeMap[s]; ok {
    *t = nt
    return nil
  } else {
    return fmt.Errorf("unknown reference type: \"%s\"", s)
  }
}

// Product reference type strings.
var refTypeStrs = [...]string {
  "", // UnknownRefType
  "Advisory", // AdvisoryRefType
  "Change Log", // ChangeLogRefType
  "Product", // ProductRefType
  "Project", // ProjectRefType
  "Vendor", // VendorRefType
  "Version", // VersionRefType
}

// Convert reference type to string.
func (t RefType) String() string {
  if int(t) < len(refTypeStrs) {
    return refTypeStrs[uint8(t)]
  } else {
    return ""
  }
}

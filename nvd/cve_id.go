package nvd

import (
  "fmt"
  "strings"
  "strconv"
)

// CVE identifier.
type CveId uint32

// Name, minimum and maximum numeric value for each CVE ID component.
var cveIdComponents = [2]struct {
  name string
  min, max uint64
} {
  { name: "year", min: 1900, max: 1900 + 255 },
  { name: "number", min: 0, max: (1 << 24) - 1 },
}

// Minimum CVE ID year
var minCveIdYear = uint32(cveIdComponents[0].min)

// Create new CVE identifier from string.  Returns error if the given
// string could not be parsed as a CVE identifier.
func NewCveId(s string) (*CveId, error) {
  // split into component strings
  vals := strings.Split(s, "-")

  // check component count
  if len(vals) != 3 {
    return nil, fmt.Errorf("invalid CVE ID component count: %d != 3", len(vals))
  }

  // check for "CVE" prefix
  if vals[0] != "CVE" {
    return nil, fmt.Errorf("missing CVE prefix")
  }

  // parse numeric components
  var ns [2]uint32
  for i, val := range(vals[1:]) {
    // get component data
    c := cveIdComponents[i]

    // parse component string
    n, err := strconv.ParseUint(val, 10, 32)
    if err != nil {
      return nil, fmt.Errorf("invalid %s \"%s\": %w", c.name, val, err)
    }

    // check numeric component range
    if n < c.min || n > c.max {
      return nil, fmt.Errorf("%s out of range: %d != [%d, %d]", c.name, n, c.min, c.max)
    }

    // add to results
    ns[i] = uint32(n)
  }

  // encode result as u32
  r := CveId((((ns[0] - minCveIdYear) & 0xff) << 24) | (ns[1] & 0xffffff))

  // return result
  return &r, nil
}

// Parse given string as CVE ID.  Panics if the given string could not
// be parsed as a CVE ID.
func MustParseCveId(s string) *CveId {
  if id, err := NewCveId(s); err == nil {
    return id
  } else {
    panic(err)
  }
}

// Return CVE ID as string or "" if the given CVE ID is nil.
func (id *CveId) String() string {
  if id != nil {
    return fmt.Sprintf("CVE-%04d-%04d", id.Year(), id.Num())
  } else {
    return ""
  }
}

// Get year component of CVE ID.
func (id *CveId) Year() uint32 {
  if id != nil {
    return (uint32(*id) >> 24) + minCveIdYear
  } else {
    return 0
  }
}

// Get number component of CVE ID.
func (id *CveId) Num() uint32 {
  if id != nil {
    return uint32(*id) & 0xffffff
  } else {
    return 0
  }
}

package cve

import (
  "encoding/json"
  "fmt"
  "strings"
  "strconv"
)

// CVE identifier.
//
// CVE identifiers are stored internally as an unsigned, 32-bit integer
// by limiting the range of the year component of the CVE ID to the
// range [1900, 2155] (inclusive) and the range of the number component
// of the CVE ID to the range [0, 2**24] (inclusive).
type Id uint32

// Name, minimum and maximum numeric value for each CVE ID component.
var idComponents = [2]struct {
  name string
  min, max uint64
} {
  { name: "year", min: 1900, max: 1900 + 255 },
  { name: "number", min: 0, max: (1 << 24) - 1 },
}

// Minimum CVE ID year
var minIdYear = uint32(idComponents[0].min)

// Parse CVE identifier from string.  Returns error if the given
// string could not be parsed as a CVE identifier.
func ParseId(s string) (*Id, error) {
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
    c := idComponents[i]

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
  r := Id((((ns[0] - minIdYear) & 0xff) << 24) | (ns[1] & 0xffffff))

  // return result
  return &r, nil
}

// Parse given string as CVE ID.  Panics if the given string could not
// be parsed as a CVE ID.
func MustParseId(s string) *Id {
  if id, err := ParseId(s); err == nil {
    return id
  } else {
    panic(err)
  }
}

// Return CVE ID as string or "" if the given CVE ID is nil.
func (id *Id) String() string {
  if id != nil {
    return fmt.Sprintf("CVE-%04d-%04d", id.Year(), id.Num())
  } else {
    return ""
  }
}

// Get year component of CVE ID.
func (id *Id) Year() uint32 {
  if id != nil {
    return (uint32(*id) >> 24) + minIdYear
  } else {
    return 0
  }
}

// Get number component of CVE ID.
func (id *Id) Num() uint32 {
  if id != nil {
    return uint32(*id) & 0xffffff
  } else {
    return 0
  }
}

// Unmarshal JSON string as CVE ID.
func (id *Id) UnmarshalJSON(b []byte) error {
  // unmarshal string
  var s string
  if err := json.Unmarshal(b, &s); err != nil {
    return err
  }

  // parse string
  new_id, err := ParseId(s)
  if err != nil {
    return err
  }

  *id = *new_id
  return nil
}

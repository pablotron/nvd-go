package cve

import (
  "encoding/json"
  "fmt"
  "regexp"
  "strconv"
)

// CVE identifier (ID).
//
// CVE IDs are stored internally as an unsigned, 32-bit integer
// by limiting the range of the year component of the CVE ID to the
// range [1900, 2155] (inclusive) and the range of the number component
// of the CVE ID to the range [0, 2**24] (inclusive).
type Id uint32

// Name, minimum and maximum numeric value for each CVE ID component.
var idComponents = [2]struct {
  name string
  min, max uint32
} {
  { name: "year", min: 1900, max: 1900 + 255 },
  { name: "number", min: 0, max: (1 << 24) - 1 },
}

// CVE ID regular expression
var idRe = regexp.MustCompile(`^CVE-(\d{4})-(\d{4,8})$`)

// Minimum CVE ID year
var minIdYear = uint32(idComponents[0].min)

// Parse CVE identifier from string.  Returns error if the given
// string could not be parsed as a CVE identifier.
func ParseId(s string) (*Id, error) {
  var ns [2]uint32
  md := idRe.FindStringSubmatch(s)
  if md == nil {
    return nil, fmt.Errorf("invalid CVE ID string: \"%s\"", s)
  }

  // parse year and number
  for i, c := range(idComponents) {
    // parse uint64
    u64, err := strconv.ParseUint(md[i + 1], 10, 32)
    if err != nil {
      return nil, err
    }

    // convert to u32, check range
    ns[i] = uint32(u64)
    if ns[i] < c.min || ns[i] > c.max {
      return nil, fmt.Errorf("%s out of range: %d != [%d, %d]", c.name, ns[i], c.min, c.max)
    }
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

// Unmarshal text as CVE ID.
func (id *Id) UnmarshalText(b []byte) error {
  // parse string
  new_id, err := ParseId(string(b))
  if err != nil {
    return err
  }

  *id = *new_id
  return nil
}

// Marshal CVE ID as JSON string.
func (id Id) MarshalJSON() ([]byte, error) {
  return json.Marshal(id.String())
}

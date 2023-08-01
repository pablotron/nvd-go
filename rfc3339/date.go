package rfc3339

import (
  "encoding/json"
  "fmt"
  "regexp"
  "strconv"
)

// ISO-8601 date.
//
// Note: Years are clamped to the range [0, 9999] (inclusive).
type Date uint32

// Parse numeric date component into uint32 or return error 
func parseDateComponent(name, s string, min, max uint64) (uint32, error) {
  // parse numeric value
  val, err := strconv.ParseUint(s, 10, 32)
  if err != nil {
    return 0, fmt.Errorf("invalid %s \"%s\": %w", name, s, err)
  }

  // check range
  if val < min || val > max {
    return 0, fmt.Errorf("invalid %s \"%s\": out of range [%d, %d]", name, s, min, max)
  }

  return uint32(val), nil
}

// maximum days for each month
var maxMonthDays = []uint32 { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }

// Return error if the number of days exceeds the maximum for the month.
//
// Note: no leap year check is done.
func checkMonthDays(month, day uint32) error {
  // check month
  if month < 1 || month > 12 {
    return fmt.Errorf("month out of range: %d", month)
  }

  // check month day
  if max := maxMonthDays[month - 1]; day < 1 || day > max {
    return fmt.Errorf("day %d out of range [1, %d]", day, max)
  }

  // return success
  return nil
}

// regular expression to match date strings.
var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// Parse string as RFC3339 date.
func ParseDate(s string) (*Date, error) {
  if !dateRe.MatchString(s) {
    return nil, fmt.Errorf("invalid date string: \"%s\"", s)
  }

  // parse year
  year, err := parseDateComponent("year", s[0:4], 0, 9999)
  if err != nil {
    return nil, err
  }

  // parse month
  month, err := parseDateComponent("month", s[5:7], 1, 12)
  if err != nil {
    return nil, err
  }

  // parse day
  day, err := parseDateComponent("day", s[8:], 1, 31)
  if err != nil {
    return nil, err
  }

  // check number of days for month
  // (no leap year checking is done)
  if err := checkMonthDays(month, day); err != nil {
    return nil, err
  }

  // build result
  r := Date((year << 9) | (month << 5) | day)
  return &r, nil
}

// Parse string as RFC3339 date or panic on error.
func MustParseDate(s string) *Date {
  if d, err := ParseDate(s); err == nil {
    return d
  } else {
    panic(err)
  }
}

// Get year component of date.
func (d Date) Year() uint32 {
  return uint32(d) >> 9
}

// Get month component of date.
func (d Date) Month() uint32 {
  return (uint32(d) >> 5) & 0xf
}

// Get day component of date.
func (d Date) Day() uint32 {
  return uint32(d) & 0x1f
}

// Return date as RFC3339-formatting string (YYYY-MM-DD).
func (d Date) String() string {
  return fmt.Sprintf("%04d-%02d-%02d", d.Year(), d.Month(), d.Day())
}

// Unmarshal text as date.
func (d *Date) UnmarshalText(b []byte) error {
  // parse string as date
  nd, err := ParseDate(string(b))
  if err != nil {
    return err
  }

  // save date, return success
  *d = *nd
  return nil;
}

// Marshal date as JSON.
func (d Date) MarshalJSON() ([]byte, error) {
  return json.Marshal(d.String())
}

package cvss

import (
  "encoding/json"
  "fmt"
)

// Individual CVSS score.
//
// Note: since scores range from 0.0 to 10.0 with one decimal place of
// precision, they can be safely represented as a uint8.
type Score uint8

// Parse score from floating point value or return error if the floating
// point value is out of range.
func ParseScore(val float64) (Score, error) {
  // check score range
  if val < 0.0 || val > 10.0 {
    return Score(0), fmt.Errorf("score %f out of range [0, 10]", val)
  }

  // convert to score, return success
  return Score(uint8(10.0 * val)), nil
}

// Parse floating point value as score or panic if the floating point
// value is out of range.
func MustParseScore(val float64) Score {
  if s, err := ParseScore(val); err == nil {
    return s
  } else {
    panic(err)
  }
}

// Return string representation of score.
func (s Score) String() string {
  return fmt.Sprintf("%d.%d", s / 10, s % 10)
}

// Return floating point representation of score.
func (s Score) Float() float32 {
  return float32(s) / 10.0
}

// Score to severity mapping.
var scoreSeverities = []struct {
  min       uint8     // min score (inclusive)
  max       uint8     // max score (inclusive)
  severity  Severity  // severity
} {
  {  0,   0, None },
  {  1,  39, Low },
  { 40,  69, Medium },
  { 70,  89, High },
  { 90, 100, Critical },
}

// Return score severity.
//
// Returns Unknown if the score does not map to a known severity.
//
// Score severity is based on mapping from section 5 of CVSS 3.1
// specification.
func (s Score) Severity() Severity {
  for _, row := range(scoreSeverities) {
    if uint8(s) >= row.min && uint8(s) <= row.max {
      return row.severity
    }
  }

  // return unknown severity
  return Unknown
}

// Unmarshal score from JSON.
func (s *Score) UnmarshalJSON(b []byte) error {
  // unmarshal float
  var f float64
  if err := json.Unmarshal(b, &f); err != nil {
    return err
  }

  // parse float as score
  ns, err := ParseScore(f)
  if err != nil {
    return err
  }

  // save score, return success
  *s = ns
  return nil
}

// Marshal score as JSON.
func (s Score) MarshalJSON() ([]byte, error) {
  return json.Marshal(s.Float())
}

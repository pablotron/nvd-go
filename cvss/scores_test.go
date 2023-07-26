package cvss

import (
  "testing"
)

func TestNewScores(t *testing.T) {
  invalidScore := 11.0
  validScore := 10.0

  // test out of bound errors
  failTests := []struct {
    name    string // test name
    base    float64 // base score
    temp    *float64 // temporal score
    env     *float64 // env score
  } {{
    name: "invalid base",
    base: invalidScore,
  }, {
    name: "invalid temporal",
    base: validScore,
    temp:  &invalidScore,
  }, {
    name: "invalid env",
    base: validScore,
    temp: &validScore,
    env: &invalidScore,
  }}

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if got, err := NewScores(test.base, test.temp, test.env); err == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}

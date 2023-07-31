package cvss

import (
  "reflect"
  "testing"
)

func TestNewScores(t *testing.T) {
  fp := func(v float64) *float64 { return &v } // float ptr
  sp := func(v float64) *Score { s := MustParseScore(v); return &s } // score ptr
  invalidScore := 11.0
  validScore := 10.0

  passTests := []struct {
    name string // test name
    base    float64 // base score
    temp    *float64 // temporal score
    env     *float64 // env score
    exp     Scores // expected scores
  } {
    { "base-min", 0, nil, nil, Scores { MustParseScore(0), nil, nil } },
    { "base-max", 10, nil, nil, Scores { MustParseScore(10), nil, nil } },
    { "temp-min", 5, fp(0), nil, Scores { MustParseScore(5), sp(0), nil } },
    { "temp-max", 5, fp(10), nil, Scores { MustParseScore(5), sp(10), nil } },
    { "env-min", 5, fp(6.7), fp(0), Scores { MustParseScore(5), sp(6.7), sp(0) } },
    { "env-max", 5, fp(6.7), fp(10), Scores { MustParseScore(5), sp(6.7), sp(10) } },
  }

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      got, err := NewScores(test.base, test.temp, test.env)
      if err != nil {
        t.Fatal(err)
      }

      if !reflect.DeepEqual(got, test.exp) {
        t.Fatalf("got %v, exp %v", got, test.exp)
      }
    })
  }

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

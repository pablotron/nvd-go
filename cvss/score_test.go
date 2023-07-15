package cvss

import (
  "strconv"
  "testing"
)

func TestParseScore(t *testing.T) {
  // pass tests
  for exp := 0; exp < 100; exp++ {
    val := float64(exp) / 10.0

    t.Run(strconv.FormatInt(int64(exp), 10), func(t *testing.T) {
      got, err := ParseScore(val)
      if err != nil {
        t.Error(err)
      } else if int(got) != exp {
        t.Errorf("got %d, exp %d", int(got), exp)
      }
    })
  }

  // fail tests
  failTests := []float64 { -10.0, -0.1, 10.1, 100.0 }
  for _, val := range(failTests) {
    t.Run(strconv.FormatFloat(val, 'f', 2, 64), func(t *testing.T) {
      if got, err := ParseScore(val); err == nil {
        t.Errorf("got %v, exp error", got)
      }
    })
  }
}

func TestScoreString(t *testing.T) {
  tests := []struct {
    val float64
    exp string
  } {
    { 0.0, "0.0" },
    { 1.0, "1.0" },
    { 1.1, "1.1" },
    { 1.2, "1.2" },
    { 2.0, "2.0" },
    { 7.5, "7.5" },
    { 10.0, "10.0" },
  }

  for _, test := range(tests) {
    t.Run(test.exp, func(t *testing.T) {
      if val, err := ParseScore(test.val); err != nil {
        t.Error(err)
      } else if val.String() != test.exp {
        t.Errorf("got \"%s\", exp \"%s\"", val.String(), test.exp)
      }
    })
  }
}

func TestScoreFloat(t *testing.T) {
  tests := []struct {
    val float64
    exp float32
  } {
    { 0.0, float32(0.0) },
    { 1.0, float32(1.0) },
    { 1.1, float32(1.1) },
    { 1.2, float32(1.2) },
    { 2.0, float32(2.0) },
    { 7.5, float32(7.5) },
    { 7.5, float32(7.5) },
    { 10.0, float32(10.0) },

    // test weird cases
    { 7.59, float32(7.5) },
    { 8.11111111, float32(8.1) },
  }

  for _, test := range(tests) {
    t.Run(strconv.FormatFloat(test.val, 'f', 2, 64), func(t *testing.T) {
      s, err := ParseScore(test.val)
      if err != nil {
        t.Error(err)
        return
      }

      got := s.Float()
      if got != test.exp {
        t.Errorf("got \"%f\", exp \"%f\"", got, test.exp)
      }
    })
  }
}

func TestScoreSeverity(t *testing.T) {
  passTests := []struct {
    val float64
    exp Severity
  } {
    { 0.0, None },
    { 0.1, Low },
    { 3.9, Low },
    { 4.0, Medium },
    { 6.9, Medium },
    { 7.0, High },
    { 8.9, High },
    { 9.0, Critical },
    { 10.0, Critical },
  }

  for _, test := range(passTests) {
    t.Run(strconv.FormatFloat(test.val, 'f', 2, 64), func(t *testing.T) {
      s, err := ParseScore(test.val)
      if err != nil {
        t.Error(err)
        return
      }

      got := s.Severity()
      if got != test.exp {
        t.Errorf("got \"%s\", exp \"%s\"", got, test.exp)
      }
    })
  }

  failTests := []struct {
    val Score
    exp Severity
  } {
    { Score(uint8(110)), Unknown },
  }

  for _, test := range(failTests) {
    t.Run(test.val.String(), func(t *testing.T) {
      got := test.val.Severity()
      if got != test.exp {
        t.Errorf("got \"%s\", exp \"%s\"", got, test.exp)
      }
    })
  }
}

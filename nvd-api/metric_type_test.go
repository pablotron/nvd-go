package nvd_api

import "testing"

func TestMetricTypeUnmarshalText(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp MetricType // expected value
  } {
    { "Primary", Primary },
    { "Secondary", Secondary },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      var got MetricType
      if err := got.UnmarshalText([]byte(test.val)); err != nil {
        t.Fatal(err)
      }

      if got != test.exp {
        t.Fatalf("got %v, exp %v", got, test.exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "garbage", "asdf" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      var got MetricType
      if got.UnmarshalText([]byte(test.val)) == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}

func TestMetricTypeMarshalText(t *testing.T) {
  passTests := []struct {
    val MetricType // test value
    exp string // expected string
  } {
    { Primary, "Primary" },
    { Secondary, "Secondary" },
  }

  for _, test := range(passTests) {
    t.Run(test.exp, func(t *testing.T) {
      gotBytes, err := test.val.MarshalText()
      if err != nil {
        t.Fatal(err)
      }

      got := string(gotBytes)
      if got != test.exp {
        t.Fatalf("got %s, exp %s", got, test.exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val MetricType // test value
  } {
    { "invalid", InvalidMetricType },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if gotBytes, err := test.val.MarshalText(); err == nil {
        got := string(gotBytes)
        if got != "" {
          t.Fatalf("got %s, exp error", got)
        }
      }
    })
  }
}

func TestMetricTypeString(t *testing.T) {
  passTests := []struct {
    val MetricType // test value
    exp string // expected string
  } {
    { Primary, "Primary" },
    { Secondary, "Secondary" },
  }

  for _, test := range(passTests) {
    t.Run(test.exp, func(t *testing.T) {
      got := test.val.String()
      if got != test.exp {
        t.Fatalf("got %s, exp %s", got, test.exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val MetricType // test value
  } {
    { "invalid", InvalidMetricType },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      got := test.val.String()
      if got != "" {
        t.Fatalf("got %s, exp error", got)
      }
    })
  }
}

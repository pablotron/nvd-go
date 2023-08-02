package rfc3339

import (
  "fmt"
  "testing"
  "time"
)

func TestParseDateTime(t *testing.T) {
  passTests := []struct {
    name string // test name
    val string // test value
    exp string // expected time
  } {{
    name: "utc",
    val: "2023-01-02T12:34:56.123",
    exp: "2023-01-02T12:34:56.123",
  }, {
    name: "positive tz",
    val: "2023-01-02T12:34:56.321",
    exp: "2023-01-02T12:34:56.321",
  }, {
    name: "positive tz",
    val: "2023-01-02T12:34:56.456",
    exp: "2023-01-02T12:34:56.456",
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // parse time
      nvdTime, err := ParseDateTime(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // get parsed time
      got, err := nvdTime.Time()
      if err != nil {
        t.Fatal(err)
      }

      // parse expected time
      exp, err := time.Parse(`2006-01-02T15:04:05.999`, test.exp)
      if err != nil {
        t.Fatal(err)
      }

      if !got.Equal(exp) {
        t.Fatalf("time mismatch: got %v, exp %v", got, exp)
      }
    })
  }
}

func TestMustParseDateTime(t *testing.T) {
  passTests := []string {
    "2023-01-02T12:34:56.123",
    "2023-01-02T12:34:56.321",
    "2023-01-02T12:34:56.456",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      defer func() {
        if err := recover(); err != nil {
          t.Fatal(err)
        }
      }()

      // parse string
      _ = MustParseDateTime(test)
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "garbage", "foobar" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      defer func() {
        if recover() == nil {
          t.Fatal("got success, exp error")
        }
      }()

      // parse string
      _ = MustParseDateTime(test.val)
    })
  }

}

func TestDateTimeString(t *testing.T) {
  passTests := []string {
    "2023-01-02T12:34:56.123",
  }

  for _, exp := range(passTests) {
    t.Run(exp, func(t *testing.T) {
      // parse time
      dt, err := ParseDateTime(exp)
      if err != nil {
        t.Fatal(err)
      }

      // convert to string
      got := dt.String()
      if got != exp {
        t.Fatalf("got %s, exp %s", got, exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val *DateTime // test value
  } {
    { "nil", nil },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      exp := ""
      got := test.val.String()
      if got != exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
      }
    })
  }

  t.Run("nil", func(t *testing.T) {
    exp := ""
    got := ((*DateTime)(nil)).String()
    if got != exp {
      t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
    }
  })
}

func TestDateTimeUnmarshalText(t *testing.T) {
  passTests := []string {
    "2023-01-02T12:34:56.123",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      var got DateTime
      if err := got.UnmarshalText([]byte(test)); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "garbage", "foobar" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      var got DateTime
      if got.UnmarshalText([]byte(test.val)) == nil {
        t.Fatalf("got \"%v\", exp error", got)
      }
    })
  }
}

func TestDateTimeMarshalJSON(t *testing.T) {
  passTests := []string {
    "2023-01-02T12:34:56.123",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      gotBytes, err := MustParseDateTime(test).MarshalJSON()
      if err != nil {
        t.Fatal(err)
      }

      exp := fmt.Sprintf("\"%s\"", test)
      got := string(gotBytes)
      if got != exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
      }
    })
  }
}

func TestDateTimeTime(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp string // expected time
  } {
    { "2023-01-02T12:34:56.000", "2023-01-02T12:34:56.000Z" },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      // parse datetime
      got, err := MustParseDateTime(test.val).Time()
      if err != nil {
        t.Fatal(err)
      }

      // parse expected time
      exp, err := time.Parse(time.RFC3339, test.exp)
      if err != nil {
        t.Fatal(err)
      }

      if !got.Equal(exp) {
        t.Fatalf("got %v, exp %v", got, exp)
      }
    })
  }

  t.Run("nil", func(t *testing.T) {
    if got, err := ((*DateTime)(nil)).Time(); err == nil {
      t.Fatalf("got %v, exp error", got)
    }
  })
}

package rfc3339

import (
  "testing"
  "time"
)

func TestParseTime(t *testing.T) {
  passTests := []struct {
    name string // test name
    val string // test value
    exp string // expected time
  } {{
    name: "utc",
    val: "2023-01-02T12:34:56Z",
    exp: "2023-01-02T12:34:56Z",
  }, {
    name: "positive tz",
    val: "2023-01-02T12:34:56+01:00",
    exp: "2023-01-02T12:34:56+01:00",
  }, {
    name: "positive tz",
    val: "2023-01-02T12:34:56-01:00",
    exp: "2023-01-02T12:34:56-01:00",
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // parse time
      nvdTime, err := ParseTime(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // get parsed time
      got, err := nvdTime.Time()
      if err != nil {
        t.Fatal(err)
      }

      // parse expected time
      exp, err := time.Parse(time.RFC3339, test.exp)
      if err != nil {
        t.Fatal(err)
      }

      if !got.Equal(exp) {
        t.Fatalf("time mismatch: got %v, exp %v", got, exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "garbage", "sdlkfjaslkdfj" },
  }

  for _, test := range(failTests) {
    t.Run(test.name ,func(t *testing.T) {
      if got, err := ParseTime(test.val); err == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}

func TestMustParseTime(t *testing.T) {
  passTests := []string {
    "2023-01-02T12:34:56Z",
    "2023-01-02T12:34:56+01:00",
    "2023-01-02T12:34:56-01:00",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      defer func() {
        if err := recover(); err != nil {
          t.Fatal(err)
        }
      }()

      // parse string
      _ = MustParseTime(test)
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "garbage", "sdlkfjaslkdfj" },
  }

  for _, test := range(failTests) {
    t.Run(test.name ,func(t *testing.T) {
      defer func() {
        if recover() == nil {
          t.Fatal("got success, exp error")
        }
      }()

      // parse string
      _ = MustParseTime(test.val)
    })
  }
}

func TestTimeTime(t *testing.T) {
  passTests := []string {
    "2023-01-02T12:34:56Z",
    "2023-01-02T12:34:56+01:00",
    "2023-01-02T12:34:56-01:00",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      // parse time
      got, err := MustParseTime(test).Time()
      if err != nil {
        t.Fatal(err)
      }

      // get expected time
      exp, err := time.Parse(time.RFC3339, test)
      if err != nil {
        t.Fatal(err)
      }

      if !got.Equal(exp) {
        t.Fatalf("got \"%v\", exp \"%v\"", got, exp)
      }
    })
  }

  // test nil time
  t.Run("nil", func(t *testing.T) {
    if got, err := (*Time)(nil).Time(); err == nil {
      t.Fatalf("got \"%v\", exp err", got)
    }
  })
}

func TestTimeString(t *testing.T) {
  passTests := []string {
    "2023-01-02T12:34:56Z",
    "2023-01-02T12:34:56+01:00",
    "2023-01-02T12:34:56-01:00",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      got := MustParseTime(test).String()
      exp := test
      if got != exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
      }
    })
  }

  // test nil time
  t.Run("nil", func(t *testing.T) {
    got := (*Time)(nil).String()
    exp := ""
    if got != exp {
      t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
    }
  })
}

func TestTimeUnmarshalText(t *testing.T) {
  passTests := []string {
    "2023-01-02T12:34:56Z",
    "2023-01-02T12:34:56+01:00",
    "2023-01-02T12:34:56-01:00",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      var got Time
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
    { "garbage", "sdlkfjaldskfj" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      var got Time
      if got.UnmarshalText([]byte(test.val)) == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}

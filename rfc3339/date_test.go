package rfc3339

import (
  "fmt"
  "reflect"
  "testing"
)

func TestParseDateComponent(t *testing.T) {
  // test all possible component values
  testAll := func(name, format string, minVal, maxVal uint64) {
    // test valid values
    for exp := minVal; exp < maxVal + 1; exp++ {
      // build test string
      test := fmt.Sprintf(format, exp)

      t.Run(fmt.Sprintf("%s/%s", name, test), func(t *testing.T) {
        // parse component
        got, err := parseDateComponent(name, test, minVal, maxVal)
        if err != nil {
          t.Fatal(err)
        }

        // check against expected value
        if uint64(got) != uint64(exp) {
          t.Fatalf("got %d, exp %d", got, exp)
        }
      })
    }

    if minVal > 0 {
      // test underflow
      test := fmt.Sprintf(format, minVal - 1)
      t.Run(fmt.Sprintf("%s/%s", name, test), func(t *testing.T) {
        if got, err := parseDateComponent(name, test, minVal, maxVal); err == nil {
          t.Fatalf("got %d, exp error", got)
        }
      })
    }

    {
      // test overflow
      test := fmt.Sprintf(format, maxVal + 1)
      t.Run(fmt.Sprintf("%s/%s", name, test), func(t *testing.T) {
        if got, err := parseDateComponent(name, test, minVal, maxVal); err == nil {
          t.Fatalf("got %d, exp error", got)
        }
      })
    }

    failTests := []struct {
      name string // test name
      val string // test value
    } {
      { "empty", "" },
      { "invalid", "asdf" },
    }

    for _, test := range(failTests) {
      t.Run(fmt.Sprintf("%s/%s", name, test.name), func(t *testing.T) {
        if got, err := parseDateComponent(name, test.val, minVal, maxVal); err == nil {
          t.Fatalf("got %d, exp error", got)
        }
      })
    }
  }

  testAll("year", "%04d", 0, 9999)
  testAll("month", "%02d", 1, 12)
  testAll("day", "%02d", 1, 21)
}

func TestCheckMonthDays(t *testing.T) {
  passTests := []struct {
    month, day uint32
  } {
    { month: 1, day: 1 }, { month: 1, day: 31 }, // jan
    { month: 2, day: 1 }, { month: 2, day: 29 }, // feb
    { month: 3, day: 1 }, { month: 3, day: 31 }, // mar
    { month: 4, day: 1 }, { month: 3, day: 30 }, // apr
    { month: 5, day: 1 }, { month: 5, day: 31 }, // may
    { month: 6, day: 1 }, { month: 6, day: 30 }, // jun
    { month: 7, day: 1 }, { month: 7, day: 31 }, // jul
    { month: 8, day: 1 }, { month: 8, day: 31 }, // aug
    { month: 9, day: 1 }, { month: 9, day: 30 }, // sep
    { month: 10, day: 1 }, { month: 10, day: 31 }, // oct
    { month: 11, day: 1 }, { month: 11, day: 30 }, // nov
    { month: 12, day: 1 }, { month: 12, day: 31 }, // dec
  }

  for _, test := range(passTests) {
    // build test name
    name := fmt.Sprintf("month-%d-day-%d", test.month, test.day)

    t.Run(name, func(t *testing.T) {
      if err := checkMonthDays(test.month, test.day); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name string // test name
    month, day uint32 // test month and day
  } {
    { name: "low month", month: 0, day: 1 },
    { name: "high month", month: 13, day: 1 },
    { name: "low day", month: 1, day: 0 },
    { name: "jan", month: 1, day: 32 },
    { name: "feb", month: 2, day: 30 },
    { name: "mar", month: 3, day: 32 },
    { name: "apr", month: 4, day: 31 },
    { name: "may", month: 5, day: 32 },
    { name: "jun", month: 6, day: 31 },
    { name: "jul", month: 7, day: 32 },
    { name: "aug", month: 8, day: 32 },
    { name: "sep", month: 9, day: 31 },
    { name: "oct", month: 10, day: 32 },
    { name: "nov", month: 11, day: 31 },
    { name: "dec", month: 12, day: 32 },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if err := checkMonthDays(test.month, test.day); err == nil {
        t.Fatalf("got success, exp error")
      }
    })
  }
}

func TestParseDate(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp []uint32 // expected year, month, and day
  } {{
    val: "2023-01-12",
    exp: []uint32 { 2023, 1, 12 },
  }, {
    val: "1923-12-31",
    exp: []uint32 { 1923, 12, 31 },
  }}

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      // parse date
      d, err := ParseDate(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // check components
      got := []uint32 { d.Year(), d.Month(), d.Day() }
      if !reflect.DeepEqual(got, test.exp) {
        t.Fatalf("got %v, exp %v", got, test.exp)
      }

      // check string
      if d.String() != test.val {
        t.Fatalf("got %s, exp %s", d.String(), test.val)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {{
    name: "not iso8601",
    val: "asdf",
  }, {
    name: "zero month",
    val: "1234-00-01",
  }, {
    name: "high month",
    val: "1234-13-01",
  }, {
    name: "zero day",
    val: "1234-01-00",
  }, {
    name: "high day",
    val: "1234-01-32",
  }, {
    name: "invalid month day",
    val: "1234-02-31",
  }}

  for _, test := range(failTests) {
    t.Run(test.val, func(t *testing.T) {
      // parse date
      if d, err := ParseDate(test.val); err == nil {
        t.Fatalf("got %v, exp err", d)
      }
    })
  }
}

package mock_server

import (
  "net/http"
  "net/http/httptest"
  "testing"
)

func TestSendJson(t *testing.T) {
  passTests := []string {
    "cpematch-CVE-2022-32223.json.gz",
    "cpes-2023.json.gz",
    "cvehistory-CVE-2019-1010218.json.gz",
    "cves-1999.json.gz",
    "cves-2023.json.gz",
    "cves-CVE-2023-0001.json.gz",
    "sources-20.json.gz",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      rr := httptest.NewRecorder()
      if err := sendJson(rr, test); err != nil {
        t.Fatal(err)
      }

      t.Run("code", func(t *testing.T) {
        got := rr.Code
        exp := http.StatusOK
        if got != exp {
          t.Fatalf("got %d, exp %d", got, exp)
        }
      })

      t.Run("content-type", func(t *testing.T) {
        got := rr.Header().Get("content-type")
        exp := "application/json"
        if got != exp {
          t.Fatalf("got %s, exp %s", got, exp)
        }
      })
    })
  }

  t.Run("missing file", func(t *testing.T) {
    rr := httptest.NewRecorder()
    if sendJson(rr, "does-not-exist.txt") == nil {
      t.Fatal("got success, exp error")
    }

    // check response code
    t.Run("code", func(t *testing.T) {
      got := rr.Code
      exp := 500
      if got != exp {
        t.Fatalf("got %d, exp %d", got, exp)
      }
    })
  })

  t.Run("non-gzipped file", func(t *testing.T) {
    rr := httptest.NewRecorder()
    if sendJson(rr, "not-gzipped.txt") == nil {
      t.Fatal("got success, exp error")
    }

    // check response code
    t.Run("code", func(t *testing.T) {
      got := rr.Code
      exp := 500
      if got != exp {
        t.Fatalf("got %d, exp %d", got, exp)
      }
    })
  })
}

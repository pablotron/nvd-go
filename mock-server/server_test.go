package mock_server

import (
  "net/http"
  "testing"
)

func TestServerNewClose(t *testing.T) {
  apiKey := "foo"

  // create server
  s, err := New(apiKey)
  if err != nil {
    t.Fatal(err)
  }
  defer s.Close()

  // tests expected to fail
  passTests := []string {
    "/cves/2.0",
    "/cvehistory/2.0",
    "/cpes/2.0",
    "/cpematch/2.0",
    "/source/2.0",
  }

  // run pass tests
  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      // create request w/ header
      r, err := http.NewRequest("", s.Url.JoinPath(test).String(), nil)
      if err != nil {
        t.Fatal(err)
      }

      // add headers
      r.Header.Add("accept", "application/json")
      r.Header.Add("apiKey", apiKey)

      // send request
      w, err := http.DefaultClient.Do(r)
      if err != nil {
        t.Fatal(err)
      }
      defer w.Body.Close()

      // check response code
      t.Run("code", func(t *testing.T) {
        got := w.StatusCode
        exp := http.StatusOK
        if got != exp {
          t.Fatalf("got %d, exp %d", got, exp)
        }
      })

      // check content-type header
      t.Run("content-type", func(t *testing.T) {
        got := w.Header.Get("content-type")
        exp := "application/json"
        if got != exp {
          t.Fatalf("got %s, exp %s", got, exp)
        }
      })
    })
  }

  // tests expected to fail
  failTests := []struct {
    name string // test name
    method string // http method
    url string // request method
    headers map[string]string // request headers
    expCode int // expected status code
  } {{
    name: "bad method",
    method: "POST",
    url: s.Url.String(),
    expCode: http.StatusMethodNotAllowed,
  }, {
    name: "missing accept header",
    method: "GET",
    url: s.Url.String(),
    expCode: http.StatusNotAcceptable,
  }, {
    name: "bad api key",
    method: "GET",
    url: s.Url.String(),
    headers: map[string]string {
      "accept": "application/json",
    },
    expCode: http.StatusUnauthorized,
  }, {
    name: "not found",
    method: "GET",
    url: s.Url.String(),
    headers: map[string]string {
      "apiKey": apiKey,
      "accept": "application/json",
    },
    expCode: http.StatusNotFound,
  }}

  // run fail tests
  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      // create request w/ header
      r, err := http.NewRequest(test.method, test.url, nil)
      if err != nil {
        t.Fatal(err)
      }

      // add headers
      for k, v := range(test.headers) {
        r.Header.Add(k, v)
      }

      // send request
      w, err := http.DefaultClient.Do(r)
      if err != nil {
        t.Fatal(err)
      }
      defer w.Body.Close()

      // check response code
      got := w.StatusCode
      if got != test.expCode {
        t.Fatalf("got %d, exp %d", got, test.expCode)
      }
    })
  }
}

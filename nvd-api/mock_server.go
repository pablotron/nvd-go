package nvd_api

import (
  "compress/gzip"
  "fmt"
  "io"
  "log"
  "net/http"
  "net/http/httptest"
  net_url "net/url"
  "os"
)

// Mock NVD API HTTP server.  Used for Client unit tests.
type MockServer struct {
  Url *net_url.URL // server URL
  s *httptest.Server // server
  apiKey string // api key
}

// Create new mock server.
func NewMockServer(apiKey string) (*MockServer, error) {
  var r MockServer

  // start server
  r.s = httptest.NewServer(&r)

  // parse server url
  url, err := net_url.Parse(r.s.URL)
  if err != nil {
    return nil, err
  }

  // cache api key and url
  r.apiKey = apiKey
  r.Url = url

  return &r, nil
}

// shut down server
func (ms MockServer) Close() {
  ms.s.Close()
}

// Is the given key is a valid API key, and false otherwise.
func (ms MockServer) validApiKey(key string) bool {
  return ms.apiKey == key
}

// map of mock routes to mock responses
var mockRoutes = map[string]string {
  "/cves/2.0": "cves-2023.json.gz",
  "/cvehistory/2.0": "cvehistory-CVE-2019-1010218.json.gz",
  "/cpes/2.0": "cpes-2023.json.gz",
  "/cpematch/2.0": "cpematch-CVE-2022-32223.json.gz",
  "/source/2.0": "sources-20.json.gz",
}

func sendJson(w http.ResponseWriter, name string) error {
  // open source file
  f, err := os.Open(fmt.Sprintf("testdata/responses/%s", name))
  if err != nil {
    http.Error(w, "", http.StatusInternalServerError)
    return err
  }
  defer f.Close()

  // create gzip reader
  gz, err := gzip.NewReader(f)
  if err != nil {
    http.Error(w, "", http.StatusInternalServerError)
    return err
  }
  defer gz.Close()

  // set header, copy content
  w.Header().Add("Content-Type", "application/json")
  if _, err := io.Copy(w, gz); err != nil {
    return err
  }

  // return success
  return nil
}

// HTTP handler.
func (ms MockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  // check request method
  if r.Method != "GET" {
    http.Error(w, "", http.StatusMethodNotAllowed)
    return
  }

  // check request Accept header
  if r.Header.Get("Accept") != "application/json" {
    // FIXME: check this w/ live server
    http.Error(w, "", http.StatusMethodNotAllowed)
    return
  }

  // check request apiKey header
  if !ms.validApiKey(r.Header.Get("apiKey")) {
    // FIXME: check this w/ live server
    http.Error(w, "", http.StatusUnauthorized)
    return
  }

  // get response file name
  name, ok := mockRoutes[r.URL.Path]
  if !ok {
    // FIXME: check this w/ live server
    http.Error(w, "", http.StatusNotFound)
    return
  }

  // send json
  if err := sendJson(w, name); err != nil {
    log.Print(err)
    return
  }
}

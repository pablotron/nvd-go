// Mock NVD API server.  Used for nvd_api.Client unit tests.
package mock_server

import (
  "log"
  "net/http"
  "net/http/httptest"
  net_url "net/url"
)

// Mock NVD API HTTP server.
//
// Used for Client unit tests in `TestClient()`.
type Server struct {
  Url *net_url.URL // server URL
  s *httptest.Server // server
  apiKey string // api key
  routes map[string]Route
}

// Create new mock server with routes.
func NewWithRoutes(apiKey string, routes map[string]Route) (*Server, error) {
  var r Server

  // start server
  r.s = httptest.NewServer(&r)

  // parse server url
  url, err := net_url.Parse(r.s.URL)
  if err != nil {
    return nil, err
  }

  // cache api key, routes, and url
  r.apiKey = apiKey
  r.routes = routes
  r.Url = url

  return &r, nil
}

// Create new mock server with default routes.
func New(apiKey string) (*Server, error) {
  return NewWithRoutes(apiKey, DefaultRoutes)
}

// shut down server
func (ms Server) Close() {
  ms.s.Close()
}

// HTTP handler.
func (ms Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  // check request method
  if r.Method != "GET" {
    http.Error(w, "", http.StatusMethodNotAllowed)
    return
  }

  // check request Accept header
  if r.Header.Get("Accept") != "application/json" {
    // FIXME: check this w/ live server
    http.Error(w, "", http.StatusNotAcceptable)
    return
  }

  // check request apiKey header
  if r.Header.Get("apiKey") != ms.apiKey {
    // FIXME: check this w/ live server
    http.Error(w, "", http.StatusUnauthorized)
    return
  }

  // get route
  route, ok := ms.routes[r.URL.Path]
  if !ok {
    // FIXME: check this w/ live server
    http.Error(w, "", http.StatusNotFound)
    return
  }

  // call route
  if err := route(w, r); err != nil {
    log.Print(err)
    return
  }
}

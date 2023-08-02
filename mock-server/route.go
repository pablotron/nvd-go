// Mock NVD API server.  Used for nvd_api.Client unit tests.
package mock_server

import (
  "net/http"
)

// Mock server route function.
type Route func(w http.ResponseWriter, r *http.Request) error

// default routes (serve up mock responses)
var DefaultRoutes = map[string]Route {
  "/cves/2.0": func(w http.ResponseWriter, r *http.Request) error {
    return sendJson(w, "cves-2023.json.gz")
  },

  "/cvehistory/2.0": func(w http.ResponseWriter, r *http.Request) error {
    return sendJson(w, "cvehistory-CVE-2019-1010218.json.gz")
  },

  "/cpes/2.0": func(w http.ResponseWriter, r *http.Request) error {
    return sendJson(w, "cpes-2023.json.gz")
  },

  "/cpematch/2.0": func(w http.ResponseWriter, r *http.Request) error {
    return sendJson(w, "cpematch-CVE-2022-32223.json.gz")
  },

  "/source/2.0": func(w http.ResponseWriter, r *http.Request) error {
    return sendJson(w, "sources-20.json.gz")
  },
}

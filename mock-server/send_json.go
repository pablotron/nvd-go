package mock_server

import (
  "compress/gzip"
  "fmt"
  "io"
  "net/http"
  "os"
)


// Send compressed JSON file as response.  Used by default mock server
// routes.
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


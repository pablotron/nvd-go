package nvd_api

import (
  "compress/gzip"
  "encoding/json"
  "io"
  "testing"
  "os"
)

func readTestData(t *testing.T, path string) []byte {
  t.Helper()

  // open input file
  f, err := os.Open(path)
  if err != nil {
    t.Fatal(err)
  }
  defer f.Close()

  // create gzip reader
  gz, err := gzip.NewReader(f)
  if err != nil {
    t.Fatal(err)
  }
  defer gz.Close()

  // read contents
  data, err := io.ReadAll(gz)
  if err != nil {
    t.Fatal(err)
  }

  // return file contents
  return data
}

func TestResponse(t *testing.T) {
  // read test response
  data := readTestData(t, "testdata/cves-response.json.gz")

  // unmarshal response
  var r Response
  if err := json.Unmarshal(data, &r); err != nil {
    t.Fatal(err)
  }

  t.Logf("%v", r)
}

package nvd_api

import (
  "compress/gzip"
  "encoding/json"
  "io"
  "testing"
  "os"
)

// Read gzipped test data.
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

func TestResponseUnmarshalJson(t *testing.T) {
  passTests := []struct {
    name string // test name
    path string // test json file
  } {{
    name: "1999",
    path: "testdata/cves-response-1999.json.gz",
  }, {
    name: "2023",
    path: "testdata/cves-response-2023.json.gz",
  }, {
    name: "CVE-2023-0001",
    path: "testdata/response-CVE-2023-0001.json.gz",
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // read response data
      data := readTestData(t, test.path)

      // unmarshal response
      var r Response
      if err := json.Unmarshal(data, &r); err != nil {
        t.Fatal(err)
      }
    })
  }
}

func TestResponseUnmarshalMarshal(t *testing.T) {
  passTests := []struct {
    name string // test name
    path string // test json file
  } {{
    name: "CVE-2023-0001",
    path: "testdata/response-CVE-2023-0001.json.gz",
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // read response data
      data := readTestData(t, test.path)

      // unmarshal response
      var r Response
      if err := json.Unmarshal(data, &r); err != nil {
        t.Fatal(err)
      }

      // marshal response
      gotBytes, err := json.Marshal(&r)
      if err != nil {
        t.Fatal(err)
      }

      exp := string(data)
      got := string(gotBytes)
      if got != exp {
        t.Fatalf("got %s, exp %s", got, exp)
      }
    })
  }
}

//go:build exclude
//
// nvd-sources.go: Get NVD data sources and print the results to
// standard output in JSON format.
//
// Example:
//
// ```
// $ export NVD_API_KEY='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
// $ go run examples/nvd-sources/nvd-sources.go
// ...
// ```
package main

import (
  "context"
  "encoding/json"
  "log"
  "os"
  "pablotron.org/nvd-go/nvd-api"
)

// Get application name from command-line arguments, or return
// "cve-info" otherwise.
func appName() string {
  if len(os.Args) > 0 {
    return os.Args[0]
  } else {
    return "cve-search"
  }
}

func main() {
  ctx := context.Background()

  // default parameters for Sources()
  var sourceParams nvd_api.SourceParams

  // get api key from environment variable
  apiKey := os.Getenv("NVD_API_KEY")

  // create NVD API client
  client := nvd_api.NewClient(apiKey)

  // get sources
  r, err := client.Sources(ctx, sourceParams)
  if err != nil {
    log.Fatal(err)
  }

  // JSON encode, write to stdout
  if err := json.NewEncoder(os.Stdout).Encode(&r); err != nil {
    log.Fatal(err)
  }
}

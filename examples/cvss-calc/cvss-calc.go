//go:build exclude

//
// cvss-calc.go: calculate scores of CVSS vectors given as command-line
// arguments and write the results to standard output in CSV format.
//
// Example:
//
//   # get version and scores for three vectors
//   go run cvss-calc.go "AV:N/AC:L/Au:N/C:N/I:N/A:C" "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:C" "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:R"
//   vector,version,base score,temporal score,environmental score
//   AV:N/AC:L/Au:N/C:N/I:N/A:C,2.0,7.8,n/a,n/a
//   CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:C,3.0,7.3,7.3,n/a
//   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:R,3.1,7.3,7.1,n/a
//
package main

import (
  "encoding/csv"
  "log"
  "os"
  "pablotron.org/nvd-go/cvss/parser"
)

// Convert vector string to CSV row.
func getCsvRow(s string) []string {
  // parse vector string
  v, err := parser.ParseVector(s)
  if err != nil {
    log.Fatal(err)
  }

  // get scores
  scores, err := v.Scores()
  if err != nil {
    log.Fatal(err)
  }

  // get CVSS version string and base score string
  version := v.Version().String()
  baseScore := scores.Base.String()

  // get temporal score string
  tempScore := "n/a"
  if scores.Temporal != nil {
    tempScore = scores.Temporal.String()
  }

  // get env score string
  envScore := "n/a"
  if scores.Env != nil {
    envScore = scores.Env.String()
  }

  // return row
  return []string { s, version, baseScore, tempScore, envScore }
}

// CSV column headers
var csvCols = []string {
  "vector",
  "version",
  "base score",
  "temporal score",
  "environmental score",
}

func main() {
  // get vector strings from command-line arguments
  args := os.Args[1:]

  // populate CSV rows
  rows := append(make([][]string, 0, len(args) + 1), csvCols)
  for _, s := range(args) {
    rows = append(rows, getCsvRow(s))
  }

  // write CSV rows to stdout
  if err := csv.NewWriter(os.Stdout).WriteAll(rows); err != nil {
    log.Fatal(err)
  }
}

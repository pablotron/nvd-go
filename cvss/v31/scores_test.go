package v31

import (
  "bytes"
  "compress/gzip"
  "encoding/json"
  "pmdn.org/nvd-go/cvss"
  "reflect"
  "testing"
  _ "embed"
)

func TestVectorScores(t *testing.T) {
  // return pointer to float
  fp := func(v float64) *float64 {
    return &v
  }

  tests := []struct {
    name string // test name
    val string // v3.1 vector string
    exp cvss.Scores // expected scores
  } {{
    name: "initial",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    exp: cvss.MustParseScores(0.0, nil, nil),
  }, {
    name: "initial I:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    exp: cvss.MustParseScores(9.8, nil, nil),
  }, {
    name: "initial A:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    exp: cvss.MustParseScores(5.3, nil, nil),
  }, {
    name: "AV:A",
    val: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    exp: cvss.MustParseScores(6.3, nil, nil),
  }, {
    name: "AV:L",
    val: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    exp: cvss.MustParseScores(5.9, nil, nil),
  }, {
    name: "AV:P",
    val: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    exp: cvss.MustParseScores(4.3, nil, nil),
  }, {
    name: "AC:H",
    val: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
    exp: cvss.MustParseScores(5.6, nil, nil),
  }, {
    name: "PR:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
    exp: cvss.MustParseScores(6.3, nil, nil),
  }, {
    name: "PR:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L",
    exp: cvss.MustParseScores(4.7, nil, nil),
  }, {
    name: "UI:R",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
    exp: cvss.MustParseScores(6.3, nil, nil),
  }, {
    name: "S:C",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
    exp: cvss.MustParseScores(8.3, nil, nil),
  }, {
    name: "C:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
    exp: cvss.MustParseScores(6.5, nil, nil),
  }, {
    name: "C:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    exp: cvss.MustParseScores(8.6, nil, nil),
  }, {
    name: "I:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
    exp: cvss.MustParseScores(6.5, nil, nil),
  }, {
    name: "I:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
    exp: cvss.MustParseScores(8.6, nil, nil),
  }, {
    name: "A:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    exp: cvss.MustParseScores(6.5, nil, nil),
  }, {
    name: "A:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
    exp: cvss.MustParseScores(8.6, nil, nil),
  }, {
    name: "E:U",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:U",
    exp: cvss.MustParseScores(7.3, fp(6.7), nil),
  }, {
    name: "E:P",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P",
    exp: cvss.MustParseScores(7.3, fp(6.9), nil),
  }, {
    name: "E:F",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:F",
    exp: cvss.MustParseScores(7.3, fp(7.1), nil),
  }, {
    name: "E:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:H",
    exp: cvss.MustParseScores(7.3, fp(7.3), nil),
  }, {
    name: "RL:O",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RL:O",
    exp: cvss.MustParseScores(7.3, fp(7.0), nil),
  }, {
    name: "RL:T",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RL:T",
    exp: cvss.MustParseScores(7.3, fp(7.1), nil),
  }, {
    name: "RL:W",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RL:W",
    exp: cvss.MustParseScores(7.3, fp(7.1), nil),
  }, {
    name: "RL:U",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RL:U",
    exp: cvss.MustParseScores(7.3, fp(7.3), nil),
  }, {
    name: "RC:U",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:U",
    exp: cvss.MustParseScores(7.3, fp(6.8), nil),
  }, {
    name: "RC:R",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:R",
    exp: cvss.MustParseScores(7.3, fp(7.1), nil),
  }, {
    name: "RC:C",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:C",
    exp: cvss.MustParseScores(7.3, fp(7.3), nil),
  }, {
    name: "MAV:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:N/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "MAV:A",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:A/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(6.3)),
  }, {
    name: "MAV:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:L/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(5.9)),
  }, {
    name: "MAV:P",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:P/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(4.3)),
  }, {
    name: "MAC:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:L/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "MAC:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:H/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(5.6)),
  }, {
    name: "MPR:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:N/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "MPR:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:L/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(6.3)),
  }, {
    name: "MPR:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:H/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(4.7)),
  }, {
    name: "MUI:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:N/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "MUI:R",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:R/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(6.3)),
  }, {
    name: "MS:U",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:U/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "MS:C",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:C/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(8.3)),
  }, {
    name: "MC:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:N/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(6.5)),
  }, {
    name: "MC:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:L/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "MC:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:H/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(8.6)),
  }, {
    name: "MI:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:N/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(6.5)),
  }, {
    name: "MI:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:L/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "MI:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:H/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(8.6)),
  }, {
    name: "MA:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:N",
    exp: cvss.MustParseScores(7.3, nil, fp(6.5)),
  }, {
    name: "MA:N",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:L",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "MA:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:H",
    exp: cvss.MustParseScores(7.3, nil, fp(8.6)),
  }, {
    name: "CR:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:L/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(6.9)),
  }, {
    name: "CR:M",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:M/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "CR:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:H/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.7)),
  }, {
    name: "IR:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:L/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(6.9)),
  }, {
    name: "IR:M",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:M/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "IR:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:H/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.7)),
  }, {
    name: "AR:L",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:L/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(6.9)),
  }, {
    name: "AR:M",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:M/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.3)),
  }, {
    name: "AR:H",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:H/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(7.7)),
  }, {
    name: "MPR:H/MS:C",
    val: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:H/MUI:X/MS:C/MC:X/MI:X/MA:X",
    exp: cvss.MustParseScores(7.3, nil, fp(6.6)),
  }}

  for _, test := range(tests) {
    t.Run(test.val, func(t *testing.T) {
      // create vector
      vec, err := ParseVector(test.val)
      if err != nil {
        t.Error(err)
        return
      }

      // get scores
      got, err := vec.Scores()
      if err != nil {
        t.Error(err)
        return
      }

      if !reflect.DeepEqual(got, test.exp) {
        t.Errorf("got %v, exp %v", got, test.exp)
      }
    })
  }
}

//go:embed testdata/v31-scores.json.gz
var v31ScoresData []byte

func TestMoreVectorScores(t *testing.T) {
  var tests []struct {
    Vector Vector `json:"vector"`
    Score cvss.Score `json:"score"`
    Severity cvss.Severity `json:"severity"`
  }

  // uncompress test data
  gz, err := gzip.NewReader(bytes.NewBuffer(v31ScoresData))
  if err != nil {
    t.Fatal(err)
  }
  defer gz.Close()

  // decode json
  if err = json.NewDecoder(gz).Decode(&tests); err != nil {
    t.Fatal(err)
  }

  for _, test := range(tests) {
    t.Run(test.Vector.String(), func(t *testing.T) {
      // get scores
      scores, err := test.Vector.Scores()
      if err != nil {
        t.Fatal(err)
      }

      t.Run("score", func(t *testing.T) {
        got := scores.Base
        exp := test.Score
        if got != exp {
          t.Fatalf("got %s, exp %s", got, exp)
        }
      })

      t.Run("severity", func(t *testing.T) {
        got := scores.Base.Severity()
        exp := test.Severity
        if got != exp {
          t.Fatalf("got %s, exp %s", got, exp)
        }
      })
    })
  }
}

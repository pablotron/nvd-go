package v2

import (
  "pmdn.org/nvd-go/cvss"
  "reflect"
  "testing"
)

func TestVectorScores(t *testing.T) {
  // return pointer to float if float is non-zero
  fp := func(v float64) *float64 {
    if v > 0.0 {
      return &v
    } else {
      return nil
    }
  }

  // test vectors from section 3.3
  tests := []struct {
    name  string // test name
    val   string // test cvss v2 vector string
    exp   cvss.Scores // expected scores
  } {{
    name: "CVE-2002-0392/base", // 3.3.1
    val:  "AV:N/AC:L/Au:N/C:N/I:N/A:C",
    exp:  cvss.MustParseScores(7.8, fp(0.0), fp(0.0)),
  }, {
    name: "CVE-2002-0392/temporal", // 3.3.1
    val:  "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C",
    exp:  cvss.MustParseScores(7.8, fp(6.4), fp(0.0)),
  }, {
    name: "CVE-2002-0392/all", // 3.3.1
    val:  "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H",
    exp:  cvss.MustParseScores(7.8, fp(6.4), fp(9.2)),
  }, {
    name: "CVE-2003-0818/base", // 3.3.2
    val:  "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    exp:  cvss.MustParseScores(10.0, fp(0.0), fp(0.0)),
  }, {
    name: "CVE-2003-0818/temporal", // 3.3.2
    val:  "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C",
    exp:  cvss.MustParseScores(10.0, fp(8.3), fp(0.0)),
  }, {
    name: "CVE-2003-0818/all", // 3.3.2
    val:  "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L",
    exp:  cvss.MustParseScores(10.0, fp(8.3), fp(9.0)),
  }, {
    name: "CVE-2003-0062/base", // 3.3.3
    val:  "AV:L/AC:H/Au:N/C:C/I:C/A:C",
    exp:  cvss.MustParseScores(6.2, fp(0.0), fp(0.0)),
  }, {
    name: "CVE-2003-0062/temporal", // 3.3.3
    val:  "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
    exp:  cvss.MustParseScores(6.2, fp(4.9), fp(0.0)),
  }, {
    name: "CVE-2003-0062/all", // 3.3.3
    val: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M",
    exp:  cvss.MustParseScores(6.2, fp(4.9), fp(7.5)),
  }, {
    name: "A:N", // from nvd v2 calc
    val: "AV:A/AC:M/Au:M/C:P/I:P/A:N",
    exp:  cvss.MustParseScores(3.4, fp(0.0), fp(0.0)),
  }, {
    name: "Au:S", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P",
    exp:  cvss.MustParseScores(4.9, fp(0.0), fp(0.0)),
  }, {
    name: "E:ND", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:ND",
    exp:  cvss.MustParseScores(4.9, fp(0.0), fp(0.0)),
  }, {
    name: "E:U", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:U/RL:ND/RC:ND",
    exp:  cvss.MustParseScores(4.9, fp(4.2), fp(0.0)),
  }, {
    name: "E:H", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:ND/RC:ND",
    exp:  cvss.MustParseScores(4.9, fp(4.9), fp(0.0)),
  }, {
    name: "RL:TF", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:TF/RC:ND",
    exp:  cvss.MustParseScores(4.9, fp(4.4), fp(0.0)),
  }, {
    name: "RL:W", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(0.0)),
  }, {
    name: "RL:U", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:U/RC:ND",
    exp:  cvss.MustParseScores(4.9, fp(4.9), fp(0.0)),
  }, {
    name: "RC:UC", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:U/RC:UC",
    exp:  cvss.MustParseScores(4.9, fp(4.4), fp(0.0)),
  }, {
    name: "RC:UR", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:U/RC:UR",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(0.0)),
  }, {
    name: "CDP:ND", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:ND/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(2.8)),
  }, {
    name: "CDP:N", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:N/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(2.8)),
  }, {
    name: "CDP:L", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:L/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(3.5)),
  }, {
    name: "CDP:LM", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:LM/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(5.0)),
  }, {
    name: "CDP:MH", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:MH/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(5.7)),
  }, {
    name: "CDP:H", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.4)),
  }, {
    name: "TD:ND", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:ND/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.4)),
  }, {
    name: "TD:N", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:N/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(0.0)),
  }, {
    name: "TD:L", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:L/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(1.6)),
  }, {
    name: "TD:M", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:M/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(4.8)),
  }, {
    name: "TD:H", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.4)),
  }, {
    name: "CR:ND", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:ND/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.8)),
  }, {
    name: "CR:L", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.4)),
  }, {
    name: "CR:M", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:M/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.8)),
  }, {
    name: "CR:H", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:H/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(7.1)),
  }, {
    name: "IR:ND", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:ND/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.8)),
  }, {
    name: "IR:L", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.4)),
  }, {
    name: "IR:M", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:M/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.8)),
  }, {
    name: "IR:H", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:H/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(7.1)),
  }, {
    name: "AR:ND", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:ND",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.8)),
  }, {
    name: "AR:L", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:L",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.4)),
  }, {
    name: "AR:M", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:M",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(6.8)),
  }, {
    name: "AR:H", // from nvd v2 calc
    val: "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:H",
    exp:  cvss.MustParseScores(4.9, fp(4.7), fp(7.1)),
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

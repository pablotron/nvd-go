package parser

import (
  "pmdn.org/nvd-go/cvss"
  "reflect"
  "testing"
)

func TestParseVector(t *testing.T) {
  fp := func(v float64) *float64 { return &v }

  passTests := []struct {
    val string // test vector
    expVersion cvss.Version // expected CVSS version
    expScores cvss.Scores // expected CVSS scores
  } {
    { "AV:N/AC:L/Au:N/C:N/I:N/A:C", cvss.V2, cvss.MustParseScores(7.8, nil, nil) },
    { "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C", cvss.V2, cvss.MustParseScores(7.8, fp(6.4), nil) },
    { "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H", cvss.V2, cvss.MustParseScores(7.8, fp(6.4), fp(9.2)) },
    { "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:C", cvss.V30, cvss.MustParseScores(7.3, fp(7.3), nil) },
    { "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:N/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X", cvss.V30, cvss.MustParseScores(7.3, nil, fp(7.3)) },
    { "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:A/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X", cvss.V30, cvss.MustParseScores(7.3, nil, fp(6.3)) },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:R", cvss.V31, cvss.MustParseScores(7.3, fp(7.1), nil) },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:C", cvss.V31, cvss.MustParseScores(7.3, fp(7.3), nil) },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:X/IR:X/AR:X/MAV:N/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X", cvss.V31, cvss.MustParseScores(7.3, nil, fp(7.3)) },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      // parse vector
      v, err := ParseVector(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // check string
      t.Run("string", func(t *testing.T) {
        got := v.String()
        if got != test.val {
          t.Fatalf("got %s, exp %s", got, test.val)
        }
      })

      // check version
      t.Run("version", func(t *testing.T) {
        got := v.Version()
        if got != test.expVersion {
          t.Fatalf("got %s, exp %s", got, test.expVersion)
        }
      })

      // check scores
      t.Run("scores", func(t *testing.T) {
        got, err := v.Scores()
        if err != nil {
          t.Fatal(err)
        }

        if !reflect.DeepEqual(got, test.expScores) {
          t.Fatalf("got %v, exp %v", got, test.expScores)
        }
      })
    })
  }
}

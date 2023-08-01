package nvd_api

import (
  "github.com/google/uuid"
  "testing"
)

func TestNewClientWithUrl(t *testing.T) {
  // generate random api key
  apiKey, err := uuid.NewRandom()
  if err != nil {
    t.Fatal(err)
  }

  // create mock server
  s, err := NewMockServer(apiKey.String())
  if err != nil {
    t.Fatal(err)
  }
  defer s.Close()

  // test bad api key
  t.Run("invalid key", func(t *testing.T) {
    // create client with valid api key
    client := NewClientWithUrl("unknown key", s.Url)
    if _, err := client.Cves(CveParams{}); err == nil {
      t.Fatal("got success, exp error")
    }
  })

  // test all client methods
  t.Run("methods", func(t *testing.T) {
    // create client with good api key
    client := NewClientWithUrl(apiKey.String(), s.Url)

    t.Run("Cves", func(t *testing.T) {
      if _, err := client.Cves(CveParams{}); err != nil {
        t.Fatal(err)
      }
    })

    t.Run("CveHistory", func(t *testing.T) {
      if _, err := client.CveHistory(CveHistoryParams{}); err != nil {
        t.Fatal(err)
      }
    })

    t.Run("Cpes", func(t *testing.T) {
      if _, err := client.Cpes(CpeParams{}); err != nil {
        t.Fatal(err)
      }
    })

    t.Run("CpeMatches", func(t *testing.T) {
      if _, err := client.CpeMatches(CpeMatchParams{}); err != nil {
        t.Fatal(err)
      }
    })

    t.Run("Sources", func(t *testing.T) {
      if _, err := client.Sources(SourceParams{}); err != nil {
        t.Fatal(err)
      }
    })
  })
}

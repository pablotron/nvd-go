package nvd_api

import (
  "context"
  "github.com/google/uuid"
  "pablotron.org/nvd-go/mock-server"
  "testing"
)

func TestClient(t *testing.T) {
  ctx := context.Background()

  // generate random api key
  apiKey, err := uuid.NewRandom()
  if err != nil {
    t.Fatal(err)
  }

  // create mock server
  s, err := mock_server.New(apiKey.String())
  if err != nil {
    t.Fatal(err)
  }
  defer s.Close()

  // test bad api key
  t.Run("invalid key", func(t *testing.T) {
    // create client with valid api key
    client := NewClientWithUrl("unknown key", s.Url)
    if _, err := client.Cves(ctx, CveParams{}); err == nil {
      t.Fatal("got success, exp error")
    }
  })

  t.Run("user agent", func(t *testing.T) {
    // create client with valid api key and user agent
    client := NewClientWithUrl(apiKey.String(), s.Url)
    client.UserAgent = "foobar"
    if _, err := client.Cves(ctx, CveParams{}); err != nil {
      t.Fatal(err)
    }
  })

  //nolint:staticcheck // allow nil context for test (golangci-lint)
  t.Run("nil context", func(t *testing.T) {
    // create client with valid api key
    client := NewClientWithUrl(apiKey.String(), s.Url)

    // call Cves() with nil context
    // (http.NewRequest() will error out when given a nil context)
    //lint:ignore SA1012 allow nil context for test (staticcheck)
    if _, err := client.Cves(nil, CveParams{}); err == nil {
      t.Fatal("got success, exp error")
    }
  })

  t.Run("cancelled context", func(t *testing.T) {
    // create cancelled context
    ctx, cancel := context.WithCancel(ctx)
    cancel()

    // create client with valid api key
    client := NewClientWithUrl(apiKey.String(), s.Url)

    // call Cves() with nil context
    // (http.NewRequest() will error out when given a nil context)
    if _, err := client.Cves(ctx, CveParams{}); err == nil {
      t.Fatal("got success, exp error")
    }
  })

  t.Run("invalid query string", func(t *testing.T) {
    // create client with valid api key and user agent
    client := NewClientWithUrl(apiKey.String(), s.Url)
    client.UserAgent = "foobar"
    if _, err := client.Cves(ctx, CveParams { ResultsPerPage: 50000 }); err == nil {
      t.Fatal("got success, exp error")
    }
  })

  // test all client methods
  t.Run("methods", func(t *testing.T) {
    // create client with good api key
    client := NewClientWithUrl(apiKey.String(), s.Url)

    t.Run("Cves", func(t *testing.T) {
      if _, err := client.Cves(ctx, CveParams{}); err != nil {
        t.Fatal(err)
      }
    })

    t.Run("CveHistory", func(t *testing.T) {
      if _, err := client.CveHistory(ctx, CveHistoryParams{}); err != nil {
        t.Fatal(err)
      }
    })

    t.Run("Cpes", func(t *testing.T) {
      if _, err := client.Cpes(ctx, CpeParams{}); err != nil {
        t.Fatal(err)
      }
    })

    t.Run("CpeMatches", func(t *testing.T) {
      if _, err := client.CpeMatches(ctx, CpeMatchParams{}); err != nil {
        t.Fatal(err)
      }
    })

    t.Run("Sources", func(t *testing.T) {
      if _, err := client.Sources(ctx, SourceParams{}); err != nil {
        t.Fatal(err)
      }
    })
  })
}

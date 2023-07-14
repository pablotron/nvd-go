package nvd

import (
  "fmt"
  net_url "net/url"
)

type Client struct {
  // API key
  apiKey string

  // API URL.
  apiUrl *net_url.URL
}

// Default NVD API URL.
var DefaultApiUrl = net_url.URL {
  Scheme: "https",
  Host: "services.nvd.nist.gov",
  Path: "/rest/json/cves/2.0",
}

func NewClientWithUrl(apiKey string, apiUrl *net_url.URL) Client {
  return Client { apiKey: apiKey, apiUrl: apiUrl }
}

func NewClient(apiKey string) Client {
  return NewClientWithUrl(apiKey, &DefaultApiUrl)
}

type CveResults struct {
}

func (c Client) Cves(params CveParams) (*CveResults, error) {
  return nil, fmt.Errorf("TODO")
}

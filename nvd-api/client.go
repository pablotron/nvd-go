package nvd_api

import (
  "fmt"
  net_url "net/url"
)

// NVD API client.
type Client struct {
  // API key
  apiKey string

  // API URL.
  apiUrl *net_url.URL
}

// Create new REST API client from given API key and server URL.
func NewClientWithUrl(apiKey string, apiUrl *net_url.URL) Client {
  return Client { apiKey: apiKey, apiUrl: apiUrl }
}

// Create new REST API client from given API key and default API URL.
func NewClient(apiKey string) Client {
  return NewClientWithUrl(apiKey, &DefaultUrl)
}

func (c Client) Cves(params CveParams) (*Response, error) {
  return nil, fmt.Errorf("TODO")
}

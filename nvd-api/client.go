package nvd_api

import (
  "context"
  "encoding/json"
  "fmt"
  "net/http"
  net_url "net/url"
)

// shared http client
var httpClient = &http.Client{}

// NVD API client.
type Client struct {
  // User agent
  UserAgent string

  // HTTP client
  HttpClient *http.Client

  // API key
  apiKey string

  // API URL.
  apiUrl *net_url.URL
}

// Create new REST API client from given API key and server URL.
func NewClientWithUrl(apiKey string, apiUrl *net_url.URL) Client {
  return Client { apiKey: apiKey, apiUrl: apiUrl, HttpClient: httpClient }
}

// Create new REST API client from given API key and default API URL.
func NewClient(apiKey string) Client {
  return NewClientWithUrl(apiKey, &DefaultUrl)
}

// Send API request.
func (c Client) send(ctx context.Context, endpoint string, params QueryStringer, format Format) (*Response, error) {
  // build query string from parameters
  query, err := params.QueryString()
  if err != nil {
    return nil, fmt.Errorf("QueryString(): %w", err)
  }

  // build new URL from API URL with endpoint path and query string
  url := c.apiUrl.JoinPath(endpoint)
  url.RawQuery = query

  // create request
  req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
  if err != nil {
    return nil, fmt.Errorf("NewRequest(): %w", err)
  }

  // add request headers
  req.Header.Add("Accept", "application/json")
  req.Header.Add("apiKey", c.apiKey)
  if c.UserAgent != "" {
    req.Header.Add("User-Agent", c.UserAgent)
  }

  // send request, get response
  resp, err := c.HttpClient.Do(req)
  if err != nil {
    return nil, fmt.Errorf("Do(): %w", err)
  }
  defer resp.Body.Close()

  // read body, decode response
  var r Response
  if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
    return nil, fmt.Errorf("Decode(): %w", err)
  }

  // check format
  if r.Format != format {
    return nil, fmt.Errorf("invalid response format: %s", r.Format)
  }

  // return response
  return &r, nil
}

// Search for CVEs via NVD API.
func (c Client) Cves(ctx context.Context, params CveParams) (*Response, error) {
  // send request, return response
  return c.send(ctx, "cves/2.0", &params, FormatCve)
}

// Search for CVE changes via NVD API.
func (c Client) CveHistory(ctx context.Context, params CveHistoryParams) (*Response, error) {
  // send request, return response
  return c.send(ctx, "cvehistory/2.0", &params, FormatCveHistory)
}

// Search for CPEs via NVD API.
func (c Client) Cpes(ctx context.Context, params CpeParams) (*Response, error) {
  // send request, return response
  return c.send(ctx, "cpes/2.0", &params, FormatCpe)
}

// Search for CPE matches via NVD API.
func (c Client) CpeMatches(ctx context.Context, params CpeMatchParams) (*Response, error) {
  // send request, return response
  return c.send(ctx, "cpematch/2.0", &params, FormatCpeMatch)
}

// Search for sources via NVD API.
func (c Client) Sources(ctx context.Context, params SourceParams) (*Response, error) {
  // send request, return response
  return c.send(ctx, "source/2.0", &params, FormatSource)
}

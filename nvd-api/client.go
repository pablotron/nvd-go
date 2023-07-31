package nvd_api

import (
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
func (c Client) send(endpoint string, params QueryStringer, format Format) (*Response, error) {
  // build query string from parameters
  query, err := params.QueryString()
  if err != nil {
    return nil, fmt.Errorf("QueryString(): %w", err)
  }

  // build full URL path
  path, err := net_url.JoinPath(c.apiUrl.Path, endpoint)
  if err != nil {
    return nil, fmt.Errorf("JoinPath(): %w", err)
  }

  // build request url
  url := *c.apiUrl
  url.Path = path
  url.RawQuery = query

  // create request
  req, err := http.NewRequest("GET", url.String(), nil)
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
func (c Client) Cves(params CveParams) (*Response, error) {
  // send request, return response
  return c.send("cves/2.0", &params, FormatCve)
}

// Search for CVE changes via NVD API.
func (c Client) CveHistory(params CveHistoryParams) (*Response, error) {
  // send request, return response
  return c.send("cvehistory/2.0", &params, FormatCveHistory)
}

// Search for CPEs via NVD API.
func (c Client) Cpes(params CpeParams) (*Response, error) {
  // send request, return response
  return c.send("cpes/2.0", &params, FormatCpe)
}

// Search for CPE matches via NVD API.
func (c Client) CpeMatches(params CpeMatchParams) (*Response, error) {
  // send request, return response
  return c.send("cpematch/2.0", &params, FormatCpeMatch)
}

// Search for sources via NVD API.
func (c Client) Sources(params SourceParams) (*Response, error) {
  // send request, return response
  return c.send("source/2.0", &params, FormatSource)
}

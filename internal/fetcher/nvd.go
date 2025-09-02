/*
Last Updated: 2025-09-01

This module is responsible for:
- Connecting to the NVD API 2.0 via HTTP GET
- Querying CVEs within a specified date range
- Decoding the returned JSON
- Returning a list of CVEs with ID, description, and official NVD URL

Example usage:

    pubStart := "2025-09-01T00:00:00:000 UTC"
    pubEnd := "2025-09-07T00:00:00:000 UTC"
    cves, err := fetcher.FetchNVDCVEs(pubStart, pubEnd, 20)
    if err != nil {
        log.Fatal(err)
    }
    for _, cve := range cves {
        fmt.Println(cve.ID, cve.Description, cve.URL)
    }

Notes:
- This module does not perform relevance filtering; it is recommended to use it together with filter.go
- Returned URLs point to the official NVD pages
- API rate limits should be respected
*/

package fetcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
)

type CVE struct {
	ID          string
	Description string
	URL         string
}

type CVEQuery struct {
	PubStart   string `validate:"required,datetime=2006-01-02T15:04:05Z07:00"`
	PubEnd     string `validate:"required,datetime=2006-01-02T15:04:05Z07:00"`
	MaxResults int    `validate:"gte=1,lte=2000"`
}

type NvdResponse struct {
	Vulnerabilities []struct {
		Cve struct {
			ID           string `json:"id"`
			SourceID     string `json:"sourceIdentifier"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (nvd *NvdResponse) GetScore(i int) float64 {
	if len(nvd.Vulnerabilities[i].Cve.Metrics.CVSSMetricV31) > 0 {
		return nvd.Vulnerabilities[i].Cve.Metrics.CVSSMetricV31[0].CvssData.BaseScore
	}
	return 0.0
}

func FetchNVDCVEs(query CVEQuery) (*NvdResponse, error) {
	v := validator.New()

	if err := v.Struct(query); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	start, _ := time.Parse(time.RFC3339, query.PubStart)
	end, _ := time.Parse(time.RFC3339, query.PubEnd)

	if end.Before(start) {
		return nil, fmt.Errorf("pubEnd cannot be before pubStart")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=%s&pubEndDate=%s&resultsPerPage=20", query.PubStart, query.PubEnd)

	resp, err := client.Get(apiURL)

	if err != nil {
		return nil, fmt.Errorf("error fetching NVD API: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status: %s", resp.Status)
	}

	var data NvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("error decoding NVD JSON data: %w", err)
	}

	return &data, nil
}

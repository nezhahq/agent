package monitor

import (
	"io"
	"testing"
)

func TestGeoIPApi(t *testing.T) {
	for _, ep := range cfList {
		resp, err := httpGetWithUA(httpClientV4, ep)
		if err != nil {
			t.Fatalf("httpGetWithUA(%s) error: %v", ep, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("io.ReadAll(%s) error: %v", ep, err)
		}
		resp.Body.Close()
		ip := string(body)
		t.Logf("%s %s", ep, ip)
		if ip == "" {
			t.Fatalf("httpGetWithUA(%s) error: %v", ep, err)
		}
	}
}

func TestFetchGeoIP(t *testing.T) {
	ip := fetchIP(cfList, false)
	if ip == "" {
		t.Fatalf("fetchGeoIP() error: %v", ip)
	}
}

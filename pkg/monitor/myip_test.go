package monitor

import (
	"io"
	"testing"
)

func TestGeoIPApi(t *testing.T) {
	for i := 0; i < len(cfList); i++ {
		resp, err := httpGetWithUA(httpClientV4, cfList[i])
		if err != nil {
			t.Fatalf("httpGetWithUA(%s) error: %v", cfList[i], err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("io.ReadAll(%s) error: %v", cfList[i], err)
		}
		resp.Body.Close()
		ip := string(body)
		t.Logf("%s %s", cfList[i], ip)
		if ip == "" {
			t.Fatalf("httpGetWithUA(%s) error: %v", cfList[i], err)
		}
	}
}

func TestFetchGeoIP(t *testing.T) {
	ip := fetchIP(cfList, false)
	if ip == "" {
		t.Fatalf("fetchGeoIP() error: %v", ip)
	}
}

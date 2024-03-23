package monitor

import (
	"io"
	"testing"
)

func TestGeoIPApi(t *testing.T) {
	for i := 0; i < len(geoIPApiList); i++ {
		resp, err := httpGetWithUA(httpClientV4, geoIPApiList[i])
		if err != nil {
			t.Fatalf("httpGetWithUA(%s) error: %v", geoIPApiList[i], err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("io.ReadAll(%s) error: %v", geoIPApiList[i], err)
		}
		resp.Body.Close()
		var ip geoIP
		err = ip.Unmarshal(body)
		if err != nil {
			t.Fatalf("ip.Unmarshal(%s) error: %v", geoIPApiList[i], err)
		}
		t.Logf("%s %s %s", geoIPApiList[i], ip.CountryCode, ip.IP)
		if ip.IP == "" || ip.CountryCode == "" {
			t.Fatalf("ip.Unmarshal(%s) error: %v", geoIPApiList[i], err)
		}
	}
}

func TestFetchGeoIP(t *testing.T) {
	ip := fetchGeoIP(geoIPApiList, false)
	if ip.IP == "" || ip.CountryCode == "" {
		t.Fatalf("fetchGeoIP() error: %v", ip)
	}
}

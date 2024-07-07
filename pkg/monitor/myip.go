package monitor

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nezhahq/agent/pkg/util"
)

const MacOSChromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"

type geoIP struct {
	CountryCode  string `json:"country_code,omitempty"`
	CountryCode2 string `json:"countryCode,omitempty"`
	IP           string `json:"ip,omitempty"`
	Query        string `json:"query,omitempty"`
	Location     struct {
		CountryCode string `json:"country_code,omitempty"`
	} `json:"location,omitempty"`
}

func (ip *geoIP) Unmarshal(body []byte) error {
	if err := util.Json.Unmarshal(body, ip); err != nil {
		return err
	}
	if ip.IP == "" && ip.Query != "" {
		ip.IP = ip.Query
	}
	if ip.CountryCode == "" && ip.CountryCode2 != "" {
		ip.CountryCode = ip.CountryCode2
	}
	if ip.CountryCode == "" && ip.Location.CountryCode != "" {
		ip.CountryCode = ip.Location.CountryCode
	}
	return nil
}

var (
	geoIPApiList = []string{
		"http://api.myip.la/en?json",
		"https://api.ip.sb/geoip",
		"https://ipapi.co/json",
		"http://ip-api.com/json/",
		// "https://extreme-ip-lookup.com/json/", // 不精确
		// "https://ip.seeip.org/geoip", // 不精确
		// "https://freegeoip.app/json/", // 需要 Key
	}
	CachedIP, cachedCountry string
	httpClientV4            = util.NewSingleStackHTTPClient(time.Second*20, time.Second*5, time.Second*10, false)
	httpClientV6            = util.NewSingleStackHTTPClient(time.Second*20, time.Second*5, time.Second*10, true)
)

// UpdateIP 按设置时间间隔更新IP地址与国家码的缓存
func UpdateIP(logging bool, period uint32) {
	for {
		util.Println(logging, "NEZHA_AGENT>> 正在更新本地缓存IP信息")
		ipv4 := fetchGeoIP(geoIPApiList, false)
		ipv6 := fetchGeoIP(geoIPApiList, true)
		if ipv4.IP == "" && ipv6.IP == "" {
			if period > 60 {
				time.Sleep(time.Minute)
			} else {
				time.Sleep(time.Second * time.Duration(period))
			}
			continue
		}
		if ipv4.IP == "" || ipv6.IP == "" {
			CachedIP = fmt.Sprintf("%s%s", ipv4.IP, ipv6.IP)
		} else {
			CachedIP = fmt.Sprintf("%s/%s", ipv4.IP, ipv6.IP)
		}
		if ipv4.CountryCode != "" {
			cachedCountry = ipv4.CountryCode
		} else if ipv6.CountryCode != "" {
			cachedCountry = ipv6.CountryCode
		}
		time.Sleep(time.Second * time.Duration(period))
	}
}

func fetchGeoIP(servers []string, isV6 bool) geoIP {
	var ip geoIP
	var resp *http.Response
	var err error

	// 双栈支持参差不齐，不能随机请求，有些 IPv6 取不到 IP
	for i := 0; i < len(servers); i++ {
		if isV6 {
			resp, err = httpGetWithUA(httpClientV6, servers[i])
		} else {
			resp, err = httpGetWithUA(httpClientV4, servers[i])
		}
		if err == nil {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			resp.Body.Close()
			newIP := geoIP{}
			if err := newIP.Unmarshal(body); err != nil {
				continue
			}
			// 没取到 v6 IP
			if isV6 && !strings.Contains(newIP.IP, ":") {
				continue
			}
			// 没取到 v4 IP
			if !isV6 && !strings.Contains(newIP.IP, ".") {
				continue
			}
			// 未获取到国家码
			if newIP.CountryCode == "" {
				continue
			}
			ip = newIP
			return ip
		}
	}
	return ip
}

func httpGetWithUA(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("User-Agent", MacOSChromeUA)
	return client.Do(req)
}

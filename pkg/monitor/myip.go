package monitor

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/logger"
	"github.com/nezhahq/agent/pkg/util"
	pb "github.com/nezhahq/agent/proto"
)

var (
	cfList = []string{
		"https://blog.cloudflare.com/cdn-cgi/trace",
		"https://developers.cloudflare.com/cdn-cgi/trace",
		"https://hostinger.com/cdn-cgi/trace",
		"https://ahrefs.com/cdn-cgi/trace",
	}
	httpClientV4 = util.NewSingleStackHTTPClient(time.Second*20, time.Second*5, time.Second*10, false)
	httpClientV6 = util.NewSingleStackHTTPClient(time.Second*20, time.Second*5, time.Second*10, true)
	fetchIPProbe = fetchIP

	retryTimes      int
	failedStartedAt time.Time
	latestRetryAt   time.Time
	geoQueryIP      string
	countryCode     string
	geoIPChanged    = true
	geoIPFetchLock  sync.Mutex
	geoIPLock       sync.RWMutex
)

// UpdateIP 按设置时间间隔更新IP地址的缓存
func FetchIP(config *model.AgentConfig, useIPv6CountryCode bool) *pb.GeoIP {
	logger.Println("正在更新本地缓存IP信息")
	geoIPFetchLock.Lock()
	defer geoIPFetchLock.Unlock()

	geoIPLock.RLock()
	if retryTimes > 2 && time.Now().Before(latestRetryAt.Add(latestRetryAt.Sub(failedStartedAt)*time.Duration(2))) {
		geoIPLock.RUnlock()
		logger.Println("IP地址获取失败次数过多，fallback到agent连接IP")
		return &pb.GeoIP{
			Use6: false,
			Ip: &pb.IP{
				Ipv4: "",
				Ipv6: "",
			},
		}
	}
	geoIPLock.RUnlock()

	wg := new(sync.WaitGroup)
	wg.Add(2)
	var ipv4, ipv6 string
	endpoints := cfList
	if config != nil && len(config.CustomIPApi) > 0 {
		endpoints = config.CustomIPApi
	}
	go func() {
		defer wg.Done()
		ipv4 = fetchIPProbe(endpoints, false)
	}()
	go func() {
		defer wg.Done()
		ipv6 = fetchIPProbe(endpoints, true)
	}()
	wg.Wait()

	geoIPLock.Lock()
	defer geoIPLock.Unlock()
	if ipv6 != "" && (useIPv6CountryCode || ipv4 == "") {
		geoIPChanged = geoQueryIP != ipv6 || geoIPChanged
		geoQueryIP = ipv6
	} else if ipv4 != "" {
		geoIPChanged = geoQueryIP != ipv4 || geoIPChanged
		geoQueryIP = ipv4
	}

	if geoQueryIP != "" {
		retryTimes = 0
		return &pb.GeoIP{
			Use6: useIPv6CountryCode,
			Ip: &pb.IP{
				Ipv4: ipv4,
				Ipv6: ipv6,
			},
		}
	}

	retryTimes++
	now := time.Now()
	latestRetryAt = now

	if retryTimes == 1 {
		failedStartedAt = now
	}

	return nil
}

func GeoIPChanged() bool {
	geoIPLock.RLock()
	defer geoIPLock.RUnlock()
	return geoIPChanged
}

func MarkGeoIPReported(reportedCountryCode string) {
	geoIPLock.Lock()
	defer geoIPLock.Unlock()
	countryCode = reportedCountryCode
	geoIPChanged = false
}

func CachedCountryCode() string {
	geoIPLock.RLock()
	defer geoIPLock.RUnlock()
	return countryCode
}

func fetchIP(servers []string, isV6 bool) string {
	var ip string
	var resp *http.Response
	var err error

	// 双栈支持参差不齐，不能随机请求，有些 IPv6 取不到 IP
	for _, server := range servers {
		if isV6 {
			resp, err = httpGetWithUA(httpClientV6, server)
		} else {
			resp, err = httpGetWithUA(httpClientV4, server)
		}
		// 遇到单栈机器提前退出
		if err != nil && strings.Contains(err.Error(), "no route to host") {
			return ip
		}
		if err == nil {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			resp.Body.Close()

			bodyStr := string(body)
			var newIP string

			if !strings.Contains(bodyStr, "ip=") {
				newIP = strings.TrimSpace(strings.ReplaceAll(bodyStr, "\n", ""))
			} else {
				lines := strings.Split(bodyStr, "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "ip=") {
						newIP = strings.TrimPrefix(line, "ip=")
						break
					}
				}
			}
			parsedIP := net.ParseIP(newIP)
			// 没取到 v6 IP
			if isV6 && (parsedIP == nil || parsedIP.To4() != nil) {
				continue
			}
			// 没取到 v4 IP
			if !isV6 && (parsedIP == nil || parsedIP.To4() == nil) {
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
	req.Header.Add("User-Agent", util.MacOSChromeUA)
	return client.Do(req)
}

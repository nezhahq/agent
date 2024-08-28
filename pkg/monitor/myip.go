package monitor

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nezhahq/agent/pkg/util"
)

var (
	cfList = []string{
		"https://blog.cloudflare.com/cdn-cgi/trace",
		"https://dash.cloudflare.com/cdn-cgi/trace",
		"https://cf-ns.com/cdn-cgi/trace", // 有国内节点
	}
	CachedIP, GeoQueryIP, CachedCountryCode string
	httpClientV4                            = util.NewSingleStackHTTPClient(time.Second*20, time.Second*5, time.Second*10, false)
	httpClientV6                            = util.NewSingleStackHTTPClient(time.Second*20, time.Second*5, time.Second*10, true)
)

// UpdateIP 按设置时间间隔更新IP地址的缓存
func UpdateIP(useIPv6CountryCode bool, period uint32) {
	for {
		util.Println(agentConfig.Debug, "正在更新本地缓存IP信息")
		wg := new(sync.WaitGroup)
		wg.Add(2)
		var ipv4, ipv6 string
		go func() {
			defer wg.Done()
			ipv4 = fetchIP(cfList, false)
		}()
		go func() {
			defer wg.Done()
			ipv6 = fetchIP(cfList, true)
		}()
		wg.Wait()

		if ipv4 == "" && ipv6 == "" {
			if period > 60 {
				time.Sleep(time.Minute)
			} else {
				time.Sleep(time.Second * time.Duration(period))
			}
			continue
		}

		if ipv4 == "" || ipv6 == "" {
			CachedIP = fmt.Sprintf("%s%s", ipv4, ipv6)
		} else {
			CachedIP = fmt.Sprintf("%s/%s", ipv4, ipv6)
		}

		if ipv6 != "" && (useIPv6CountryCode || ipv4 == "") {
			GeoQueryIP = ipv6
		} else {
			GeoQueryIP = ipv4
		}

		time.Sleep(time.Second * time.Duration(period))
	}
}

func fetchIP(servers []string, isV6 bool) string {
	var ip string
	var resp *http.Response
	var err error

	// 双栈支持参差不齐，不能随机请求，有些 IPv6 取不到 IP
	for i := 0; i < len(servers); i++ {
		if isV6 {
			resp, err = httpGetWithUA(httpClientV6, servers[i])
		} else {
			resp, err = httpGetWithUA(httpClientV4, servers[i])
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
			lines := strings.Split(string(body), "\n")
			var newIP string
			for _, line := range lines {
				if strings.HasPrefix(line, "ip=") {
					newIP = strings.TrimPrefix(line, "ip=")
					break
				}
			}
			// 没取到 v6 IP
			if isV6 && !strings.Contains(newIP, ":") {
				continue
			}
			// 没取到 v4 IP
			if !isV6 && !strings.Contains(newIP, ".") {
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

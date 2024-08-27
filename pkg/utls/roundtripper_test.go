package utls_test

import (
	"net/http"
	"testing"

	utls "github.com/refraction-networking/utls"

	utlsx "github.com/nezhahq/agent/pkg/utls"
)

const url = "https://www.patreon.com/login"

func TestCloudflareDetectionDefaultClient(t *testing.T) {
	client := http.DefaultClient

	resp, err := doRequest(client, url)
	if err != nil {
		t.Errorf("Get %s failed: %v", url, err)
	}

	if resp.StatusCode != 200 {
		t.Log("Default client is detected, switch to utls transport")
		client.Transport = utlsx.NewUTLSHTTPRoundTripperWithProxy(
			utls.HelloChrome_Auto, new(utls.Config), client.Transport, true, nil,
		)
		resp, err = doRequest(client, url)
		if err != nil {
			t.Errorf("Get %s failed: %v", url, err)
		}
		if resp.StatusCode != 200 {
			t.Fail()
		} else {
			t.Log("Client with utls transport passed Cloudflare detection")
		}
	} else {
		t.Log("Default client passed Cloudflare detection")
	}
}

func doRequest(client *http.Client, url string) (*http.Response, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp, nil
}

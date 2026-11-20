package main

import (
	"fmt"
	"net"
	"os"
	"testing"
)

func TestLookupIP(t *testing.T) {
	// 必须用 t.Skip 而不是直接 return：直接返回会让这个依赖外网 DNS 的用例
	// 在 CI 上显示为“通过”，看起来像是被覆盖了。
	if ci := os.Getenv("CI"); ci != "" {
		t.Skip("requires public DNS, which CI runners do not guarantee")
	}

	ip, err := lookupIP("www.google.com")
	fmt.Printf("ip: %v, err: %v\n", ip, err)
	if err != nil {
		t.Errorf("lookupIP failed: %v", err)
	}
	_, err = net.ResolveIPAddr("ip", "www.google.com")
	if err != nil {
		t.Errorf("ResolveIPAddr failed: %v", err)
	}

	ip, err = lookupIP("ipv6.google.com")
	fmt.Printf("ip: %v, err: %v\n", ip, err)
	if err != nil {
		t.Errorf("lookupIP failed: %v", err)
	}
	_, err = net.ResolveIPAddr("ip", "ipv6.google.com")
	if err != nil {
		t.Errorf("ResolveIPAddr failed: %v", err)
	}
}

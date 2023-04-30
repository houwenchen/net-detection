package arp

import (
	"fmt"
	"net"
	"testing"
)

func TestArp(t *testing.T) {
	Arp()
}

func TestGetIpsViaIPNet(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.0.103/23")
	ipList := GetIpsViaIPNet(ipNet)
	fmt.Println(len(ipList))
}

func TestNextIP(t *testing.T) {
	// nextIP := NextIP("192.168.0.255")
	// fmt.Println(nextIP)

	tests := []struct {
		// case name
		name string

		// para
		s string

		expect string
	}{
		{
			s:      "192.168.0.255",
			expect: "192.168.1.0",
		},
		{
			s:      "192.168.255.255",
			expect: "192.169.0.0",
		},
		{
			s:      "192.255.255.255",
			expect: "193.0.0.0",
		},
		{
			s:      "192.0.255.0",
			expect: "192.0.255.1",
		},
		{
			s:      "192.255.255.0",
			expect: "192.255.255.1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := NextIP(net.ParseIP(test.s))

			if actual.String() != test.expect {
				t.Errorf("%s: actual result: %s, expect result: %s", test.name, actual.String(), test.expect)
			}
		})
	}
}

func TestGetIps(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.0.103/23")
	ipList := GetIps(ipNet)
	fmt.Println(ipList)
	fmt.Println(len(ipList))
}

package arp

import (
	"fmt"
	"log"
	"net"
)

func Arp() {
	ifaceList, err := net.Interfaces()
	if err != nil {
		log.Fatalf("get host interfaces failed, err: %v\n", err)
	}

	for _, iface := range ifaceList {
		// 排除 down 的网卡
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 排除 Loopback 网卡
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 排除没有 mac 地址的网卡
		if iface.HardwareAddr == nil {
			continue
		}

		// 排除没有 ipv4 地址的网卡，因为 arp 只服务于 ipv4
		addrList, err := iface.Addrs()
		if err != nil {
			log.Printf("get addrs failed, err: %v", err)
			continue
		}
		if len(addrList) == 0 {
			continue
		}
		// fmt.Printf("网卡名: %s, ips: %v\n", iface.Name, addrList)
		for _, addrObj := range addrList {
			if ip, ok := addrObj.(*net.IPNet); ok {
				if ip.IP.To4() != nil {
					fmt.Printf("网卡名: %s, ips: %v\n", iface.Name, addrObj)
				}
			}
		}

		// fmt.Println(iface.Name)
	}
}

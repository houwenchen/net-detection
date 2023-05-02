package arp

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	manuf "github.com/timest/gomanuf"
)

// 定义一个 map 存放网卡与同一网段 ip 的映射关系
type InterfaceIps map[string]IpSubnets

// 定义一个 map 存放子网与属于此子网的所有 ip
type IpSubnets map[string][]net.IP

func Arp() {
	ifaceList, err := net.Interfaces()
	if err != nil {
		log.Fatalf("get host interfaces failed, err: %v\n", err)
	}

	interfaceIps := make(InterfaceIps)
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

		// 排除没有 ip 的网卡
		addrList, err := iface.Addrs()
		if err != nil {
			log.Printf("get addrs failed, err: %v", err)
			continue
		}
		// fmt.Println(addrList)
		// fmt.Println(len(addrList))
		if len(addrList) == 0 {
			continue
		}
		// fmt.Printf("网卡名: %s, ips: %v\n", iface.Name, addrList)

		// 排除没有 ipv4 地址的网卡，因为 arp 只服务于 ipv4
		ips := make(IpSubnets)
		for _, addrObj := range addrList {
			if ip, ok := addrObj.(*net.IPNet); ok {
				if ip.IP.To4() != nil {
					log.Printf("网卡名: %s, ips: %v\n", iface.Name, addrObj)
					ipList := GetIps(ip)
					ips[addrObj.String()] = ipList
				}
			}
		}
		if len(ips) != 0 {
			interfaceIps[iface.Name] = ips
		}
	}
	fmt.Println(interfaceIps)
}

// TODO: 看看这里能否复用，因为网卡上接收的包有很多类型，能否根据包的类型进行不同的处理逻辑
// 对不同的网卡开启 pcap 监听并对接收的ARP包进行处理
func listenARPPacket(ctx context.Context, iface net.Interface) {
	// 对不同的网卡开启 pcap 监听
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("pcap open fail, err:", err)
	}
	defer handle.Close()

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			arpLayer := p.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if arpLayer == nil {
					continue
				}
				if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
					// This is a packet I sent.
					continue
				}
				if arp.Operation == layers.ARPReply {
					mac := net.HardwareAddr(arp.SourceHwAddress)
					m := manuf.Search(mac.String())
					if _, ok := infoSet[net.IP(arp.SourceProtAddress).String()]; !ok {
						ch <- true
						infoSet[net.IP(arp.SourceProtAddress).String()] = info{mac, m}
						ch <- false
					}
				}
			}
		}
	}
}

// 发送 ARP 包
func sendARPPacket() {

}

// 废弃，实现的比较冗余
// 获取同子网的所有 ip , 因为 ARP 协议作用范围在局域网中
func GetIpsViaIPNet(ipNet *net.IPNet) []net.IP {
	ipBegin := ipNet.IP.Mask((ipNet.Mask))
	ones, bits := ipNet.Mask.Size()
	ipLenth := bits - ones
	var ipList []net.IP

	if ipLenth > 24 {
		ipList = getIpsForFourLayers(ipNet, ipBegin, ipLenth)
	} else if ipLenth > 16 {
		ipList = getIpsForThreeLayers(ipNet, ipBegin, ipLenth)
	} else if ipLenth > 8 {
		ipList = getIpsForTwoLayers(ipNet, ipBegin, ipLenth)
	} else {
		ipList = getIpsForOneLayers(ipNet, ipBegin, ipLenth)
	}

	fmt.Println(ipList)

	return ipList
}

// 获取同子网的所有 ip , 因为 ARP 协议作用范围在局域网中
func GetIps(ipNet *net.IPNet) []net.IP {
	var ipList []net.IP

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); NextIP(ip) {
		ipNext := make([]byte, len(ip))
		copy(ipNext, ip)
		ipList = append(ipList, ipNext)
	}

	return ipList
}

func getIpsForFourLayers(ipNet *net.IPNet, ipBegin net.IP, ipLenth int) []net.IP {
	ipList := []net.IP{}

	for n := 0; n < (1 << (ipLenth - 24)); n++ {
		for m := 0; m < (1 << 8); m++ {
			for j := 0; j < (1 << 8); j++ {
				for i := 0; i < (1 << 8); i++ {
					ipBegin[3]++
					ipNext := make([]byte, len(ipBegin))
					copy(ipNext, ipBegin)
					if ipNet.Contains(ipNext) {
						ipList = append(ipList, ipNext)
					} else {
						break
					}
				}
				ipBegin[2]++
			}
			ipBegin[1]++
		}
		ipBegin[0]++
	}

	return ipList
}

func getIpsForThreeLayers(ipNet *net.IPNet, ipBegin net.IP, ipLenth int) []net.IP {
	ipList := []net.IP{}

	for m := 0; m < (1 << (ipLenth - 16)); m++ {
		for j := 0; j < (1 << 8); j++ {
			for i := 0; i < (1 << 8); i++ {
				ipBegin[3]++
				ipNext := make([]byte, len(ipBegin))
				copy(ipNext, ipBegin)
				if ipNet.Contains(ipNext) {
					ipList = append(ipList, ipNext)
				} else {
					break
				}
			}
			ipBegin[2]++
		}
		ipBegin[1]++
	}

	return ipList
}

func getIpsForTwoLayers(ipNet *net.IPNet, ipBegin net.IP, ipLenth int) []net.IP {
	ipList := []net.IP{}

	for j := 0; j < (1 << (ipLenth - 8)); j++ {
		for i := 0; i < (1 << 8); i++ {
			ipBegin[3]++
			ipNext := make([]byte, len(ipBegin))
			copy(ipNext, ipBegin)
			if ipNet.Contains(ipNext) {
				ipList = append(ipList, ipNext)
			} else {
				break
			}
		}
		ipBegin[2]++
	}

	return ipList
}

func getIpsForOneLayers(ipNet *net.IPNet, ipBegin net.IP, ipLenth int) []net.IP {
	ipList := []net.IP{}

	for i := 0; i < (1 << (ipLenth - 8)); i++ {
		ipBegin[3]++
		ipNext := make([]byte, len(ipBegin))
		copy(ipNext, ipBegin)
		if ipNet.Contains(ipNext) {
			ipList = append(ipList, ipNext)
		} else {
			break
		}
	}

	return ipList
}

func NextIP(ip net.IP) net.IP {
	// ip := net.ParseIP(s).To4()
	ip = ip.To4()

	if ip[3] == 0xff {
		if ip[2] == 0xff {
			if ip[1] == 0xff {
				if ip[0] == 0xff {
					fmt.Println("没有下一位")
					return nil
				}
				ip[3] = 0
				ip[2] = 0
				ip[1] = 0
				ip[0]++
				return ip
			}
			ip[3] = 0
			ip[2] = 0
			ip[1]++

			return ip
		}
		ip[3] = 0
		ip[2]++

		return ip
	}

	ip[3]++
	return ip
}

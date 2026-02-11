package main

import (
	"flag"
	"log"
	"net"
	"runtime"

	"github.com/enigma522/netcut-cli/networkScan"
)

func getDefaultInterface() string {
	if runtime.GOOS == "windows" {
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Fatal(err)
		}
		for _, i := range ifaces {
			if (i.Flags&net.FlagUp) != 0 && (i.Flags&net.FlagLoopback) == 0 {
				return i.Name
			}
		}
		log.Fatal("No active network interface found")
	}
	return "wlp49s0"
}

func main() {

	scanFlag := flag.Bool("scan", false, "Scan the network")
	CIDR := flag.String("cidr", "", "CIDR for the network scan")
	cutFlag := flag.Bool("cut", false, "Cut off a device")
	ipAddr := flag.String("ip", "", "IP address of the device to cut off")
	mac := flag.String("mac", "", "MAC address of the device to cut off")
	gateway := flag.String("g", "", "Gateway IP address")
	ifaceName := flag.String("i", "", "Interface name")
	flag.Parse()

	if *ifaceName == "" {
		*ifaceName = getDefaultInterface()
	}

	log.Printf("Using interface: %s\n", *ifaceName)

	scanner := networkscan.NewNetworkScanner(*ifaceName)
	defer scanner.Close()

	if *scanFlag {
		scanner.NetScan(*CIDR)
	}

	if *cutFlag {
		if *ipAddr == "" {
			log.Fatal("IP address is required when using the cut option.")
		}

		var deviceToCut *networkscan.Device

		if *mac == "" {
			devices := scanner.NetScan(*ipAddr + "/32")
			for _, device := range devices {
				if device.IP.String() == *ipAddr {
					deviceToCut = &device
					break
				}
			}
		} else {
			macAddr, err := net.ParseMAC(*mac)
			if err != nil {
				log.Fatalf("Error parsing MAC address: %v", err)
			}
			deviceToCut = &networkscan.Device{
				IP:  net.ParseIP(*ipAddr),
				MAC: macAddr,
			}
		}

		if deviceToCut != nil {
			log.Printf("Cut off device: IP: %s, MAC: %s\n",
				deviceToCut.IP, deviceToCut.MAC)
			scanner.CutOffDevice(*deviceToCut, *gateway)
		} else {
			log.Printf("Device with IP: %s not found\n", *ipAddr)
		}
	}
}

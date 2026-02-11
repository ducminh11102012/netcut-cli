package networkscan

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func IncrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func SendARPRequest(handle *pcap.Handle, dstMAC net.HardwareAddr,
	srcMAC net.HardwareAddr, srcIP, dstIP net.IP) {

	srcIP = srcIP.To4()
	dstIP = dstIP.To4()

	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, ethLayer, arpLayer); err != nil {
		log.Println("Error serializing ARP request:", err)
		return
	}

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Println("Error sending ARP request:", err)
	}
}

func SendARPReply(handle *pcap.Handle,
	targetMAC net.HardwareAddr,
	targetIP net.IP,
	localMAC net.HardwareAddr,
	localIP net.IP) {

	targetIP = targetIP.To4()
	localIP = localIP.To4()

	ethLayer := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       targetMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(localMAC),
		SourceProtAddress: []byte(localIP),
		DstHwAddress:      []byte(targetMAC),
		DstProtAddress:    []byte(targetIP),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, ethLayer, arpLayer); err != nil {
		log.Println("Error serializing ARP reply:", err)
		return
	}

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Println("Error sending ARP reply:", err)
	}
}

func HandleARPPacket(packet gopacket.Packet) Device {

	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)

		if arp.Operation == layers.ARPReply {

			ip := net.IP(arp.SourceProtAddress).To4()
			mac := net.HardwareAddr(arp.SourceHwAddress)

			host, _ := net.LookupAddr(ip.String())

			return Device{
				IP:       ip,
				MAC:      mac,
				HOSTNAME: host,
			}
		}
	}

	return Device{}
}

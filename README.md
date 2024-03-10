This program is a command-line tool written in Go, designed to generate and send TCP SYN packets to a specified target host and port.
It uses randomly generated source IP addresses for each packet, allowing users to simulate a SYN flood attack for testing purposes.

## WARNING

This tool is intended for educational and testing purposes only. Using this tool to perform a SYN flood attack or any form of
denial-of-service attack against any host, server, or network without explicit permission is illegal and unethical.
Users are responsible for adhering to all applicable laws and regulations in their jurisdiction.
Misuse of this tool can result in significant legal consequences.

## Requirements

- Go programming language
- Linux operating system with raw socket support

## Usage

To use the tool, compile the Go source file and run it with the following arguments:

```
go run main.go <host> <port> <packets>
```

Where:

- `<host>` is the target IP address or hostname.
- `<port>` is the target port number.
- `<packets>` is the number of packets to send.

Example:

```
./tcp_syn_flooder example.com 80 1000
```

This will attempt to send 1000 TCP SYN packets to `example.com` on port 80.

## Implementation Details

The tool performs the following steps:

1. Parses command-line arguments to determine the target host, port, and number of packets.
2. Generates a random public IP address for the source IP of each packet.
3. Constructs a TCP SYN packet with the random source IP and specified destination IP and port.
4. Sends the packet using a raw socket.

## Legal Advice

- Users must ensure they have explicit permission from the target host/network owners before using this tool.
- Engaging in unauthorized testing or attacks constitutes a criminal offense in many countries.
- Always conduct ethical testing within legal boundaries and obtain necessary permissions.

## Disclaimer

The authors of this tool disclaim any liability for misuse or damages caused by this tool.
Users assume all responsibility and risk associated with the use of this tool.

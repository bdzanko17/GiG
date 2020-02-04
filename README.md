# GIG
Install the prerequisites. You will need go, libpcap and the gopacket package. Since gopacket is built on top of libpcap, I highly recommend you understand how that library works. You can learn how to use libpcap in C for a deeper understanding. These examples should work in Linux/Mac using libpcap and on Windows with WinPcap. You may need to set GOARCH=386 if you get an error like cc1.exe: sorry, unimplemented: 64-bit mode not compiled in.

INSTALLATION

Clone this repository and make sure you have installed Go. 

Get the gopacket package from GitHub
go get github.com/google/gopacket

Pcap dev headers might be necessary
sudo apt-get install libpcap-dev

# EXAMPLE 1
Run with : sudo go run filename.go 
This will start sniffing packet on default port and interface 

# EXAMPLE 2
Insert options from CMD, -i -> for interface name, -maxp for max number of packets and -maxt for maximum capture time

Run with: sudo go run filename.go -i="ethex" -p="80,8080"

This will start sniffing packets on ethex interface and on 80,8080 ports

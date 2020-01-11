package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"

	"time"
)

var (
	device       string = "wlp6s0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 1 * time.Second
	handle       *pcap.Handle
	TSval        uint32 = 0
	TSerc        uint32 = 0
	source_ip    net.IP
	dest_ip      net.IP
	source_port  string
	dest_port    string
	srcstr       string
	dststr       string
)

type Flowrecord struct {
	last_time int64
	flowname  string
	tsval     uint32
	tsecr     uint32
}

func main() {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	fmt.Println("ADRESA: ", localAddr.IP)

	fmt.Println("First packet at: ", time.Now())
	//Flows := make(map[string]bool)
	//TimeFlow := make(map[string]int64)
	//var vrijeme int64
	var br_paketa int
	var br_flow int
	Flov := make(map[string]Flowrecord)

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "tcp and port 80"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		br_paketa++

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			source_ip = ip.SrcIP
			dest_ip = ip.DstIP
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			if len(tcp.Options) >= 3 &&
				binary.BigEndian.Uint32(tcp.Options[2].OptionData[:4]) > 0 ||
				binary.BigEndian.Uint32(tcp.Options[2].OptionData[4:8]) > 0 {

				TSval = binary.BigEndian.Uint32(tcp.Options[2].OptionData[:4])
				TSerc = binary.BigEndian.Uint32(tcp.Options[2].OptionData[4:8])
			}

			source_port = tcp.SrcPort.String()
			dest_port = tcp.DstPort.String()

		}
		srcstr = source_ip.String() + ":" + source_port
		dststr = dest_ip.String() + ":" + dest_port
		var fstr string
		fstr = srcstr + dststr
		fmt.Println(fstr)

		var captm int64
		captm = time.Now().UnixNano()
		var RTT int64
		RTT = 0
		var x Flowrecord
		x.flowname = fstr

		_, ok := Flov[dststr+srcstr]
		if ok && TSerc == Flov[dststr+srcstr].tsval && source_ip.String() != localAddr.String() {

			RTT = captm - Flov[dststr+srcstr].last_time
			println("RTT: ", RTT/1000)
			delete(Flov, fstr)
			delete(Flov, dststr+srcstr)
			br_flow++
		} else {
			x.last_time = time.Now().UnixNano()
			x.tsval = TSval
			x.tsecr = TSerc
			Flov[fstr] = x
		}

	}

}

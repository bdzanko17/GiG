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

func main() {

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
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			source_ip = ip.SrcIP
			dest_ip = ip.DstIP
			fmt.Println(source_ip)
			fmt.Println(dest_ip)
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if len(tcp.Options) >= 3 {

				TSval = binary.BigEndian.Uint32(tcp.Options[2].OptionData[:4])
				TSerc = binary.BigEndian.Uint32(tcp.Options[2].OptionData[4:8])
				fmt.Println(TSval)
				fmt.Println(TSerc)

			}
			source_port = tcp.SrcPort.String()
			dest_port = tcp.DstPort.String()
			fmt.Println(source_port)
			fmt.Println(dest_port)
		}
		srcstr = source_ip.String() + ":" + source_port
		dststr = dest_ip.String() + ":" + dest_port
		fmt.Println(srcstr)
		fmt.Println(dststr)

		vrijeme_sat := time.Now().Hour()
		vrijeme_min := time.Now().Minute()
		vrijeme_sec := time.Now().Second()
		vrijeme_nano := float64(time.Now().Nanosecond())
		vrijeme_string := time.Now().String()
		vrijeme := vrijeme_sat*3600 + vrijeme_min*60 + vrijeme_sec + int(vrijeme_nano/1e6)
		fmt.Println("vrijeme:", vrijeme_string)
		fmt.Println("vrijeme:", vrijeme)

	}
	fmt.Print("e")

}

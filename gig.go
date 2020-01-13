package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

var (
	device       string = "wlp6s0" //default
	max_pkt      int    = -1       // default
	max_age      int    = -1       //default
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = -1 * time.Millisecond
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
	last_time time.Time
	flowname  string
	tsval     uint32
	tsecr     uint32
}

func ProcessPacket(handle *pcap.Handle, localAddr string) {

	var start = time.Now()
	var counter int = 0

	Flow := make(map[string]Flowrecord)
	RTT_sumary := make(map[string]string)

	fmt.Println("First packet at: ", time.Now())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		counter++
		if (counter > max_pkt && max_pkt != -1) || (int(time.Since(start)) > max_age && max_age != -1) {
			return
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			source_ip = ip.SrcIP
			dest_ip = ip.DstIP
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		//Verify if a packet has TCP layer
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Taking Timestamps from TCP options(if included)(Tsval and Tsecr)
			if len(tcp.Options) >= 3 && len(tcp.Options[2].OptionData) > 0 &&
				(binary.BigEndian.Uint32(tcp.Options[2].OptionData[:4]) > 0 ||
					binary.BigEndian.Uint32(tcp.Options[2].OptionData[4:8]) > 0) {

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

		//Creating structure about Flows and TCP connections
		x := Flowrecord{
			last_time: time.Now(),
			flowname:  "",
			tsval:     0,
			tsecr:     0,
		}

		x.flowname = fstr
		//Checking for bidirectional flow(if yes calculate RTT)
		_, ok := Flow[dststr+srcstr]
		if ok && TSerc == Flow[dststr+srcstr].tsval && source_ip.String() != localAddr {
			var RTT = time.Since(Flow[dststr+srcstr].last_time).String()
			h, m, s := time.Now().Clock()
			RTT_sumary[time.Now().String()] = RTT
			print(h, ":", m, ":", s, "  For flow: ", dststr+" : "+srcstr, " calculated RTT: ")
			println(RTT)
			delete(Flow, dststr+srcstr)

			//IF no insert, Flow in Flowrecords
		} else {
			x.last_time = time.Now()
			x.tsval = TSval
			x.tsecr = TSerc
			Flow[fstr] = x
		}
		//Back on listening

	}
}

func main() {

	x := flag.String("i", "wlp6s0", "a string")
	y := flag.Int("maxp", -1, "an int")
	z := flag.Int("maxt", -1, "an int")
	flag.Parse()

	device = *x
	max_pkt = *y
	max_age = *z

	fmt.Println("ISPISI STRING: ", max_pkt)
	fmt.Println("ISPISI STRING: ", max_age)
	fmt.Println("ISPISI STRING: ", device)

	//Getting the IP address of device
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// Open device to start listening
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
	ProcessPacket(handle, localAddr.IP.String()) // Use the handle as a packet source to process all packets

}

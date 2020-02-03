/*
 *    goDASH, golang client emulator for DASH video streaming
 *    Copyright (c) 2020, Benjamin Džanko, Edin Ibragić, Almedina Kerla, Merjema Šetić, Haris Tarahija, Faculty of Electrical Engineering Sarajevo
 *                                            [bdzako1,eibragic1,akerla2,msetic1,htarahija1]@etf.unsa.ba)
 *                      Telecommunications Software Engineering, University of Sarajevo
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License
 *    as published by the Free Software Foundation; either version 2
 *    of the License, or (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *    02110-1301, USA.
 */

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
	"strings"
	"time"
)

var (
	id           int    = 0
	br_paketa    int    = 0
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
	ports        []string
	fstr         string
	start        time.Time
)

type Flowrecord struct {
	last_time time.Time
	flowname  string
	tsval     uint32
	tsecr     uint32
}

func ProcessPacket(handle *pcap.Handle, localAddr string) {

	var counter int = 0

	Flow := make(map[int]Flowrecord)
	RTT_sumary := make(map[string]string)

	fmt.Println("Started sniffing at: ", time.Now())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		start = time.Now()
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
				br_paketa++

				TSval = binary.BigEndian.Uint32(tcp.Options[2].OptionData[:4])
				TSerc = binary.BigEndian.Uint32(tcp.Options[2].OptionData[4:8])

			} else {
				continue
				fmt.Println("XD")
			}

			source_port = tcp.SrcPort.String()
			dest_port = tcp.DstPort.String()

		}
		srcstr = source_ip.String() + ":" + source_port
		dststr = dest_ip.String() + ":" + dest_port

		fstr = srcstr + dststr

		//Creating structure about Flows and TCP connections
		x := Flowrecord{
			last_time: time.Now(),
			flowname:  "",
			tsval:     0,
			tsecr:     0,
		}

		//Checking for bidirectional flow(if yes calculate RTT)

		x.flowname = fstr
		x.last_time = time.Now()
		x.tsval = TSval
		x.tsecr = TSerc
		Flow[id] = x
		id++

		for k, v := range Flow {
			if v.flowname == dststr+srcstr && TSerc == v.tsval && source_ip.String() != localAddr {
				fmt.Println(br_paketa)
				var RTT = time.Since(v.last_time).String()
				h, m, s := time.Now().Clock()
				RTT_sumary[time.Now().String()] = RTT
				print(h, ":", m, ":", s, "  For flow: ", dststr+" : "+srcstr, " calculated RTT: ")
				println(RTT)
				delete(Flow, k)
				delete(Flow, id)
				id -= 2
				continue
			}
		}
		//Back on listening

	}
}

func main() {

	//Insert options from CMD, -i -> for interface name, -maxp for max number of packets and -maxt for maximum capture time
	x := flag.String("i", "wlp6s0", "Interface name")
	y := flag.Int("maxp", -1, "Max number of packets to capture")
	z := flag.Int("maxt", -1, "Capture time")
	p := flag.String("p", "80,443", "Sniffing port/ports")
	flag.Parse()

	device = *x
	max_pkt = *y
	max_age = *z

	//Getting the IP address of device
	//conn, err := net.Dial("udp", "8.8.8.8:80")
	//if err != nil {
	//	log.Fatal(err)
	//}

	//	defer conn.Close()

	//localAddr := conn.LocalAddr().(*net.UDPAddr)

	// Open device to start listening
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ports = strings.Split(*p, ",")
	var filter string = "tcp and port "

	for indeks, element := range ports {

		if indeks < len(ports)-1 {
			filter += element + " or "
		} else {
			filter += element
		}
	}
	fmt.Println(filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	// Use the handle as a packet source to process all packets and Local IP address for flow detection
	ProcessPacket(handle, "192.168.1.2")

}

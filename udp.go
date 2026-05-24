package main

import (
	"net"
	"log"
	"fmt"
)

func startUDPServer(port string){
	address , err := net.ResolveUDPAddr("udp",port);
	if err != nil {
		log.Fatal(err)
	}
	conn , err := net.ListenUDP("udp",address);
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Started the udp server on port ",port)
	defer conn.Close()
	buffer := make([]byte,512)
	for {
		n  , addr , err := conn.ReadFrom(buffer)

		if err != nil {
			fmt.Printf("ERROR: %v\n",err);
			continue;
		}
		packetdata := buffer[:n];
		p := parser{data:packetdata};
		p.parsePacket();
		DNSPacket := p.dnspacket 
		processDNSPacket(DNSPacket,addr,conn);

	}
}


func sendDNSPacketToServer(p DNSPacket , ip string) DNSPacket{
	conn, err := net.DialUDP(
    "udp",
    nil,
    &net.UDPAddr{
        IP:   net.ParseIP(ip),
        Port: 53,
    },
	)
	if err != nil {
			panic(err)
	} 
	defer conn.Close();
	_ , err = conn.Write(unParsePacket(p));
	if err != nil {
		fmt.Println("write error:",err);
		return DNSPacket{};
	}

	response := make([]byte,4096);
	n , err := conn.Read(response)
	if err != nil {
		fmt.Println("read error:",err)
		return DNSPacket{};
	}
	response = response[:n];

	var DNSPacketResponse DNSPacket;
	parser := parser{data:response};
	parser.parsePacket();
	DNSPacketResponse = parser.dnspacket;
	return DNSPacketResponse;
}

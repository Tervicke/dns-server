package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

func sendDNSPacket(p DNSPacket){
	conn, err := net.DialUDP(
    "udp",
    nil,
    &net.UDPAddr{
        IP:   net.ParseIP("198.41.0.4"),
        Port: 53,
    },
	)
	if err != nil {
			panic(err)
	}
	p.header.RD = false;
	defer conn.Close()
	log.Println("Sent the query to the root server");
	
	buf := make([]byte,512)
	n , err := conn.Read(buf);
	if err != nil {
		panic(err)

	}
	response := buf[:n]
	DNSPacket := parsePacket(response);
	fmt.Println(DNSPacket);
}

func processPacket(packet []byte) {
	DNSPacket := parsePacket(packet);
	fmt.Printf("%+v",DNSPacket);
	fmt.Println("-----------------------------------");
	fmt.Println(DNSPacket.header.Isquery)
	if(DNSPacket.header.Isquery){
		// sendPacket(packet);
	}
}
func startUDPServer(){
	log.Println("Starting the udp server on port 8080")
	address , err := net.ResolveUDPAddr("udp",":8080");
	if err != nil {
		log.Fatal(err)
	}
	conn , err := net.ListenUDP("udp",address);

	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	buffer := make([]byte,512)
	for {

		_  , _ , err := conn.ReadFrom(buffer)

		if err != nil {
			fmt.Printf("ERROR: %v\n",err);
			continue;
		}
		fmt.Println(buffer);
	}
}

func main(){
	question , err := hex.DecodeString("00d10120000100000000000106676f6f676c6503636f6d000001000100002904d000000000000c000a00080509ecacd04299f5");
	if err != nil {
		panic(err)
	}
	fmt.Println(question);
	unParsePacket( parsePacket(question) );
}

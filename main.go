package main

import (
	// "bytes"
	"bytes"
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
	 // testQuestion();
	 testAnswer();
}
func testQuestion(){
	question , err := hex.DecodeString("00d10120000100000000000106676f6f676c6503636f6d000001000100002904d000000000000c000a00080509ecacd04299f5");
	if err != nil {
		panic(err)
	}
	fmt.Println(question);
	p := parsePacket(question);
	packet := unParsePacket( p );
	fmt.Printf("%+v",p);
	fmt.Println(bytes.Equal(packet,question));
}
func testAnswer(){
	answer , err := hex.DecodeString("dda2810000010000000d001b06676f6f676c6503636f6d0000010001c013000200010002a3000014016c0c67746c642d73657276657273036e657400c013000200010002a3000004016ac02ac013000200010002a30000040168c02ac013000200010002a30000040164c02ac013000200010002a30000040162c02ac013000200010002a30000040166c02ac013000200010002a3000004016bc02ac013000200010002a3000004016dc02ac013000200010002a30000040169c02ac013000200010002a30000040167c02ac013000200010002a30000040161c02ac013000200010002a30000040163c02ac013000200010002a30000040165c02ac028000100010002a3000004c029a21ec028001c00010002a300001020010500d93700000000000000000030c048000100010002a3000004c0304f1ec048001c00010002a300001020010502709400000000000000000030c058000100010002a3000004c036701ec058001c00010002a30000102001050208cc00000000000000000030c068000100010002a3000004c01f501ec068001c00010002a300001020010500856e00000000000000000030c078000100010002a3000004c0210e1ec078001c00010002a300001020010503231d00000000000000020030c088000100010002a3000004c023331ec088001c00010002a300001020010503d41400000000000000000030c098000100010002a3000004c034b21ec098001c00010002a3000010200105030d2d00000000000000000030c0a8000100010002a3000004c037531ec0a8001c00010002a300001020010501b1f900000000000000000030c0b8000100010002a3000004c02bac1ec0b8001c00010002a30000102001050339c100000000000000000030c0c8000100010002a3000004c02a5d1ec0c8001c00010002a300001020010503eea300000000000000000030c0d8000100010002a3000004c005061ec0d8001c00010002a300001020010503a83e00000000000000020030c0e8000100010002a3000004c01a5c1ec0e8001c00010002a30000102001050383eb00000000000000000030c0f8000100010002a3000004c00c5e1ec0f8001c00010002a3000010200105021ca1000000000000000000300000291000000000000000");
	if err != nil {
		panic(err)
	}
	fmt.Println(answer);
	p := parsePacket(answer);
	 // fmt.Printf("%+v\n",p);
	 packet := unParsePacket( p );
	 fmt.Println(bytes.Equal(packet,answer));
}

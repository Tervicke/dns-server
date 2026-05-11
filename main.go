package main

import (
	"fmt"
	"encoding/hex"
)


func processPacket(packet []byte) {
	DNSPacket := parsePacket(packet);
	fmt.Printf("%+v",DNSPacket);
}

func main(){
	 answer_packet , err := hex.DecodeString("3a17818000010004000000000973797377726169746803636f6d0000010001c00c00010001000038400004b9c76c99c00c00010001000038400004b9c76e99c00c00010001000038400004b9c76f99c00c00010001000038400004b9c76d99");
	if err != nil {
		fmt.Println("error decoding packet")
		return
	}
	/*
	//question_packet , err := hex.DecodeString("25b7010000010000000000000973797377726169746803636f6d0000010001");
	question_packet , err := hex.DecodeString("3a17010000010000000000000973797377726169746803636f6d0000010001");
	if err != nil{
		fmt.Println("error decoding packet")
		return
	}
	print_header(question_packet)
	fmt.Println("------");
// 	print_header(answer_packet);

	 question_section(question_packet , extract_header(question_packet));
	 question_section(answer_packet, extract_header(answer_packet));
*/


	// start the udp server
	/*
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

		processPacket(buffer);
	}
	*/
	processPacket(answer_packet)
}

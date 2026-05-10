package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

)

//pos is 0 indexed
func iszero(num uint16 , pos int) bool { 
	if( num & (1 << pos) == 0){
		return true;
	}
	return false;
}

type header struct{
	Id uint16;

	Isquery bool; 
	Opcode uint16;
	AA bool; //authoritative answer
	TC bool;  //truncated
	RD bool; //recursion desired
	RA bool; // recursion availiable
	Z uint16; //future use
	Rcode uint16; //response code
	
	QDCOUNT uint16;
	ANCOUNT uint16;
	NSCOUNT uint16;
	ARCOUNT uint16;
};

type question struct{
	Name string;
	Type uint16;
	Class uint16;
}

func extract_header(packet []byte) header{
	//extract the ID
	header := header{};
	header.Id = binary.BigEndian.Uint16(packet[0:2]);
	

	//extract the flags
	flag := binary.BigEndian.Uint16(packet[2:4]);  

	// IS QUERY
	if( iszero(flag,15) ){ 
		header.Isquery = true;
	}else{
		header.Isquery = false;
	}

	//OPCODE
	header.Opcode = (flag >> 11) & 0xF;
	
	//AA
	if(iszero(flag,10)){
		header.AA = false;
	}else{
		header.AA = true;
	}
	
	//TC
	if(iszero(flag,9)){
		header.TC = false;
	}else{
		header.TC = true;
	}
	
	//RD
	if(iszero(flag,8)){
		header.RD = false;
	}else{
		header.RD = true;
	}

	if(iszero(flag,7)){
		header.RA = false;
	}else{
		header.RA = true;
	}

	header.Z = (flag >> 4) & 7;

	header.Rcode = (flag & 15);


	header.QDCOUNT = binary.BigEndian.Uint16(packet[4:6]);
	
	header.ANCOUNT = binary.BigEndian.Uint16(packet[6:8]);

	header.NSCOUNT = binary.BigEndian.Uint16(packet[8:10]);

	header.ARCOUNT = binary.BigEndian.Uint16(packet[10:12]);

	//return the header
	return header;
}
func question_section(packet[] byte , header header){
	// var questions []string;
	var cur uint16 = 12;
	 for i := 0 ; i < int(header.QDCOUNT) ; i++ {
		 q := question{};
		 label := "";
		 //QNAME 
		 for true{

			 label_size := uint16(packet[cur]);

			 cur++;
			 //hit the delimeter
			 if label_size == 0 {
				 break;
			 }


			 for j := cur ; j < cur + label_size ; j++{
				 label += string(rune(packet[j]));
			 }
			 cur += label_size;
			 label += ".";
		 }
		 q.Name= label[0:len(label)-1];

		 //QTYPE
		 q.Type = binary.BigEndian.Uint16(packet[cur:cur+2]);
		
		 cur+=2;

		//QCLASS
		 q.Class = binary.BigEndian.Uint16(packet[cur:cur+2]);
		 fmt.Println(q);
		
		 cur += 2;

	}
}

func print_header(packet []byte){
	header := extract_header(packet)
	fmt.Println("packet ID = " , header.Id);
	fmt.Println("Is query = ",header.Isquery);
	fmt.Println("Opcode = ",header.Opcode);
	fmt.Println("AA = ",header.AA);
	fmt.Println("RD = ",header.RD);
	fmt.Println("RA = ",header.RA);
	fmt.Println("Z = ",header.Z);
	fmt.Println("Rcode = ",header.Rcode);
	fmt.Println("QDCOUNT = ",header.QDCOUNT);
	fmt.Println("ANCOUNT = ",header.ANCOUNT);
	fmt.Println("NSCOUNT = ",header.NSCOUNT);
	fmt.Println("ARCOUNT = ",header.ARCOUNT);

}

func main(){
	 answer_packet , err := hex.DecodeString("3a17818000010004000000000973797377726169746803636f6d0000010001c00c00010001000038400004b9c76c99c00c00010001000038400004b9c76e99c00c00010001000038400004b9c76f99c00c00010001000038400004b9c76d99");
	if err != nil {
		fmt.Println("error decoding packet")
		return
	}
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


}

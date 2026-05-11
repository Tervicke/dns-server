package main

import (
	"encoding/binary"
	"fmt"
)
func parsePacket(packet []byte) DNSPacket{
	DNSPacket := DNSPacket{};

	header := readHeader(packet);
	DNSPacket.header = header;
	
	question , offset  := readQuestions(packet , int(header.QDCOUNT));
	DNSPacket.question = question;

	offset = readAnswer(packet , offset , int(header.ANCOUNT))

	return DNSPacket;
}

//extract header
func readHeader(packet []byte) header{
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

//returns the label as string for eg google.com + the offset at which the termination exists
func readName(packet []byte ,offset int) (string , int){
	 //QNAME 
	label := "";
	 for true{

		 label_size := int(packet[offset]);

		 //pointer detected ( 192 = 1100 0000 )
		 if((label_size & 192) == 192){
			 //get the temp 2 bytes
			 temp := binary.BigEndian.Uint16(packet[offset:offset+2]);
			 fmt.Printf("%016b\n",temp);
			 pointerOffset := (temp  & 16383); //1683 = 0011 1111 1111 1111
			 fmt.Printf("%016b\n",pointerOffset);
			 name , _ := readName(packet , int(pointerOffset));
			 offset++;
			 return name,offset;
		 }
		
		 //normally parse the labels
		 offset++;
		 //hit the delimeter
		 if label_size == 0 {
			 break;
		 }


		 for j := offset ; j < offset + label_size ; j++{
			 label += string(rune(packet[j]));
		 }
		 offset += label_size;
		 label += ".";
	 }
	 return label[0:len(label)-1],offset;
}

func readQuestions(packet[] byte , QDCOUNT int) ( []question , int){
 	var questions []question;
	var offset int = 12; //start with 12 because the header is exactly 12 bytes (i.e ends at 11th index)
	 for i := 0 ; i < QDCOUNT ; i++ {
		 q := question{};
		 q.Name , offset = readName(packet,offset);

		 //QTYPE
		 q.Type = binary.BigEndian.Uint16(packet[offset:offset+2]);
		
		 offset+=2;

		//QCLASS
		 q.Class = binary.BigEndian.Uint16(packet[offset:offset+2]);
		 questions = append(questions, q);
		
		 offset += 2;

	}
	return questions , offset;
}

//pos is 0 indexed
func iszero(num uint16 , pos int) bool { 
	if( num & (1 << pos) == 0){
		return true;
	}
	return false;
}

func print_header(packet []byte){
	header := readHeader(packet)
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
func readAnswer(packet []byte , offset int , ANCOUNT int) (int){
	//start reading the resource record 

	name , offset := readName(packet , offset);
	fmt.Println(name);

	return offset;
}

func readResourceRecord(packet []byte , offset int , ANCOUNT int) {

}

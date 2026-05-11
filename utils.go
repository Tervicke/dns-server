package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)
func parsePacket(packet []byte) DNSPacket{
	DNSPacket := DNSPacket{};

	header := readHeader(packet);
	DNSPacket.header = header;
	
	question , offset  := readQuestions(packet , int(header.QDCOUNT));
	DNSPacket.question = question;

	answers , offset := readAnswer(packet , offset , int(header.ANCOUNT))
	DNSPacket.answers = answers;

	authority , offset := readAuthority(packet,offset,int(header.NSCOUNT))
	DNSPacket.authority= authority;

	additional , offset := readAdditional(packet , offset , int(header.ARCOUNT));
	DNSPacket.additional = additional;

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

//returns the label as string for eg google.com + the next offset 
func readName(packet []byte ,offset int) (string , int){
	 //QNAME 
	label := "";
	 for true{

		 label_size := int(packet[offset]);

		 //pointer detected ( 192 = 1100 0000 )
		 if((label_size & 192) == 192){
			 //get the temp 2 bytes
			 temp := binary.BigEndian.Uint16(packet[offset:offset+2]);
			 pointerOffset := (temp  & 16383); //1683 = 0011 1111 1111 1111
			 name , _ := readName(packet , int(pointerOffset));
			 offset+=2;
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
	 if(len(label) == 0){
		 return "",offset;
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
	if( (num & (1 << pos)) == 0){
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

func readResourceRecord(packet []byte ,offset int) (resourceRecord , int){
	record := resourceRecord{};

	name , offset := readName(packet , offset);
	record.Name = name;
	
	rrtype := binary.BigEndian.Uint16(packet[offset:offset+2]);
	record.RRtype = rrtype;
	offset+=2;

	class := binary.BigEndian.Uint16(packet[offset:offset+2]);
	record.Class = class;
	offset += 2;

	TTL := binary.BigEndian.Uint32(packet[offset:offset+4]);
	record.TTL = TTL;
	offset += 4;
	
	rdlen := binary.BigEndian.Uint16(packet[offset:offset+2]);
	record.Len = rdlen;
	offset += 2;
	//A OR AAAA TYPE
	if (rrtype == 1 || rrtype == 28){
		addr , ok := netip.AddrFromSlice(packet[offset:offset+int(rdlen)]);
		if !ok { fmt.Println("could not parse net ip addr"); }
		record.Addr = addr;
	} else if( rrtype == 2){
		name , _ := readName(packet , offset);
		record.Host = name;
	}else{
		fmt.Printf("not recgonized rrtype = %d , SKIPPING THE PAYLOAD",rrtype);
	}

	offset+=int(rdlen);
	return record,offset;
}

func readAnswer(packet []byte , offset int , ANCOUNT int) ([]resourceRecord,int){
	var answer []resourceRecord;
	for i := 0 ; i < ANCOUNT ; i++ {
		record , newOffset := readResourceRecord(packet,offset);
		offset = newOffset;
		answer = append(answer, record);
	}
	return answer,offset;
}

func readAuthority(packet []byte , offset int , NSCOUNT int) ([]resourceRecord,int){
	var authority []resourceRecord;
	for i := 0 ; i < NSCOUNT; i++ {
		record , newOffset := readResourceRecord(packet,offset);
		offset = newOffset;
		authority = append(authority, record);
	}
	return authority,offset;
}


func readAdditional(packet []byte , offset int , ARCOUNT int) ([]resourceRecord,int){
	var add []resourceRecord;
	for i := 0 ; i < ARCOUNT; i++ {
		record , newOffset := readResourceRecord(packet,offset);
		offset = newOffset;
		add = append(add, record);
	}
	return add,offset;
}

package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
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
	var sb strings.Builder;
	 for true{

		 label_size := int(packet[offset]);

		 //pointer detected ( 192 = 1100 0000 )
		 if((label_size & 192) == 192){
			 //get the temp 2 bytes
			 temp := binary.BigEndian.Uint16(packet[offset:offset+2]);
			 pointerOffset := (temp  & 16383); //1683 = 0011 1111 1111 1111
			 name , _ := readName(packet , int(pointerOffset));
			 sb.WriteString(name);
			 offset += 2;
			 break;
		 }else{
			 //normally parse the labels
			 offset++;
			 //hit the delimeter
			 if label_size == 0 {
				 break;
			 }

			 for j := offset ; j < offset + label_size ; j++{
				 sb.WriteString(string(rune(packet[j])));
			 }
			 offset += label_size;
			 sb.WriteString(".");
		 }
	 }
	 label := sb.String();
	 if(len(label) == 0){
		 return "",offset;
	 }
	 if(label[len(label)-1] == '.'){
		return label[0:len(label)-1],offset;
	}else{
		return label,offset;
	}
}

func readQuestions(packet[] byte , QDCOUNT int) ( []question , int){
 	var questions []question;
	var offset int = 12; //start with 12 because the header is exactly 12 bytes (i.e ends at 11th index)
	 for range QDCOUNT {
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
	switch(rrtype){
	case 1,28:
		addr , ok := netip.AddrFromSlice(packet[offset:offset+int(rdlen)]);
		if !ok { fmt.Println("could not parse net ip addr"); }
		record.Addr = addr;
	case 2:
		name , _ := readName(packet , offset);
		record.Host = name;
	default:
		// fmt.Printf("not recgonized rrtype = %d , SKIPPING THE PAYLOAD\n",rrtype);
	}
	record.Data = append([]byte(nil), packet[offset:offset+int(rdlen)]...)
	offset+=int(rdlen);
	return record,offset;
}

func readAnswer(packet []byte , offset int , ANCOUNT int) ([]resourceRecord,int){
	var answer []resourceRecord;
	for range ANCOUNT{
		record , newOffset := readResourceRecord(packet,offset);
		offset = newOffset;
		answer = append(answer, record);
	}
	return answer,offset;
}

func readAuthority(packet []byte , offset int , NSCOUNT int) ([]resourceRecord,int){
	var authority []resourceRecord;
	for range NSCOUNT{
		record , newOffset := readResourceRecord(packet,offset);
		offset = newOffset;
		authority = append(authority, record);
	}
	return authority,offset;
}


func readAdditional(packet []byte , offset int , ARCOUNT int) ([]resourceRecord,int){
	var add []resourceRecord;
	for range ARCOUNT {
		record , newOffset := readResourceRecord(packet,offset);
		offset = newOffset;
		add = append(add, record);
	}
	return add,offset;
}

func unParsePacket(DNSPacket DNSPacket) []byte { 
	var packet []byte;
	packet = unParseHeader( DNSPacket ,packet);
	packet = unParseQuestion(DNSPacket,packet);
	packet = unParseAdditional(DNSPacket , packet);
	fmt.Println(packet);
	return packet;
}
func unParseHeader(DNSPacket DNSPacket , packet []byte) []byte {
	//unparse the ID 
	var tmp [2]byte; //tmp storage of byte to append it to the packet later on
	binary.BigEndian.PutUint16(tmp[:],DNSPacket.header.Id);
	packet = append(packet, tmp[:]...);
	
	//the flag bytes
	var flag uint16 = 0;

	if(DNSPacket.header.Isquery){
	}else{
		var mask uint16 = (uint16(1) << 15);
		flag = flag | mask;
	}

	
	opcodeMask := DNSPacket.header.Opcode << 11;
	flag = flag | opcodeMask;

	if(DNSPacket.header.AA){
		var mask uint16 = (uint16(1) << 10);
		flag = flag | mask;
	}else{
	}


	if(DNSPacket.header.TC){
		var mask uint16 = (uint16(1) << 9);
		flag = flag | mask;
	}else{
	}


	if(DNSPacket.header.RD){
		var mask uint16 = (uint16(1) << 8);
		flag = flag | mask;
	}else{
	}


	if(DNSPacket.header.RA){
		var mask uint16 = (uint16(1) << 7);
		flag = flag | mask;
	}else{
	}

	//no need to update Z
	zMask := DNSPacket.header.Z << 4;
	flag = flag | zMask;

	rcode := DNSPacket.header.Rcode;
	flag = flag | rcode;

	binary.BigEndian.PutUint16(tmp[:],flag);
	packet = append(packet, tmp[:]...);
	
	binary.BigEndian.PutUint16(tmp[:],DNSPacket.header.QDCOUNT);
	packet = append(packet, tmp[:]...);

	binary.BigEndian.PutUint16(tmp[:],DNSPacket.header.ANCOUNT);
	packet = append(packet, tmp[:]...);

	binary.BigEndian.PutUint16(tmp[:],DNSPacket.header.NSCOUNT);
	packet = append(packet, tmp[:]...);

	binary.BigEndian.PutUint16(tmp[:],DNSPacket.header.ARCOUNT);
	packet = append(packet, tmp[:]...);

	return packet;
}
func unParseQuestion(DNSPacket DNSPacket ,packet []byte) []byte {
	// offset := 12;
	for _ , q := range DNSPacket.question{
		packet = appendLabel(q.Name,packet);
		packet = binary.BigEndian.AppendUint16(packet,q.Type);
		packet = binary.BigEndian.AppendUint16(packet,q.Class);
	}
	return packet;
}

func appendLabel(name string, packet []byte) []byte {
	if name == "" || name == "."{
		return append(packet,0);
	}

	for n := range strings.SplitSeq(name,"."){
		if n == ""{
			continue
		}

		packet = append(packet,byte(len(n)));
		packet = append(packet,[]byte(n)...);
	} 
	packet = append(packet,0);
	return packet;
}
func unParseAdditional(DNSPacket DNSPacket , packet []byte) []byte {
	for i := range DNSPacket.header.ARCOUNT{
		packet = unParseRecord(DNSPacket.additional[i],packet);
	} 
	return packet;
}

func unParseAnswer(DNSPacket DNSPacket , packet []byte) []byte {
	for i := range DNSPacket.header.ANCOUNT{
		packet = unParseRecord(DNSPacket.answers[i],packet);
	} 
	return packet;
}

func unParseAuthority(DNSPacket DNSPacket , packet []byte) []byte {
	for i := range DNSPacket.header.NSCOUNT{
		packet = unParseRecord(DNSPacket.authority[i],packet);
	} 
	return packet;
}

func unParseRecord(record resourceRecord , packet []byte) []byte{
	packet = appendLabel(record.Name,packet);
	packet = binary.BigEndian.AppendUint16(packet,record.RRtype);
	packet = binary.BigEndian.AppendUint16(packet,record.Class);
	packet = binary. BigEndian.AppendUint32(packet,record.TTL);

	var rdata []byte

	switch record.RRtype {
	case 1, 28:
		rdata = record.Addr.AsSlice()
	case 2:
		rdata = appendLabel("", nil)
		rdata = appendLabel(record.Host, nil)
	default:
		rdata = record.Data
	}

	packet = binary.BigEndian.AppendUint16(packet, uint16(len(rdata)))
	packet = append(packet, rdata...)
	return packet;
}

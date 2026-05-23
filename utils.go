package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

func(p *parser) parsePacket(){
	p.readHeader();
	if len(p.err) > 0 {return};
	p.readQuestions();
	p.readAnswer();
	p.readAuthority();
	p.readAdditional();
}

func(p *parser) readHeader() {
	packet := p.data;
	if(len(packet) < 12){ //check if header availiable
		p.err = append(p.err, errors.New("header not complete"))
		return;
	}
	p.dnspacket.header.Id = binary.BigEndian.Uint16(packet[0:2]);
	flag := binary.BigEndian.Uint16(packet[2:4]);  
	p.dnspacket.header.Isquery = !isZero(flag,15) 
	p.dnspacket.header.Opcode = (flag >> 11) & 0xF;
	p.dnspacket.header.AA = isZero(flag,10);
	p.dnspacket.header.TC = isZero(flag,9);
	p.dnspacket.header.RD = isZero(flag,8);
	p.dnspacket.header.RA= isZero(flag,7);
	p.dnspacket.header.Z = (flag >> 4) & 7;
	p.dnspacket.header.Rcode = (flag & 15);
	p.dnspacket.header.QDCOUNT = binary.BigEndian.Uint16(packet[4:6]);
	p.dnspacket.header.ANCOUNT = binary.BigEndian.Uint16(packet[6:8]);
	p.dnspacket.header.NSCOUNT = binary.BigEndian.Uint16(packet[8:10]);
	p.dnspacket.header.ARCOUNT = binary.BigEndian.Uint16(packet[10:12]);
}

func readName(packet []byte ,offset int) (string , int , error){
	 //QNAME 
	var sb strings.Builder;
	 for true{
		 if ( len(packet) <= offset ) {
			 return "",-1,errors.New("label size not defined");
		 }
		 label_size := int(packet[offset]);

		 //pointer detected ( 192 = 1100 0000 )
		 if((label_size & 192) == 192){
			 //get the temp 2 bytes
			 temp := binary.BigEndian.Uint16(packet[offset:offset+2]);
			 pointerOffset := (temp  & 16383); //1683 = 0011 1111 1111 1111
			 name , _ , err := readName(packet , int(pointerOffset));
			 if err != nil {
				 return "",-1,err;
			 }
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
		 return "",offset,nil;
	 }
	 if(label[len(label)-1] == '.'){
		return label[0:len(label)-1],offset,nil;
	}else{
		return label,offset,nil;
	}
}

func(p *parser) readQuestions(){
	if p.dnspacket.header.QDCOUNT != 1{
		p.err = append(p.err, errors.New("qdcount not 1"))
		return;
	}
	var offset int = 12; // header ends at 11th index)
	 for range p.dnspacket.header.QDCOUNT {
		 q := question{};
		 name , newOffset , err := readName(p.data,offset);
		 if err != nil {
			 p.err = append(p.err, err);
			 return;
		 }
		 q.Name = name;
		 offset = newOffset;
		 if offset+4 > len(p.data) {
			 p.err = append(p.err, errors.New("question incomplete"))
			 return
		 }
		 q.Type = binary.BigEndian.Uint16(p.data[offset:offset+2]); //QTYPE
		 offset+=2;
		 q.Class = binary.BigEndian.Uint16(p.data[offset:offset+2]); //QCLASS
		 p.dnspacket.question = append(p.dnspacket.question, q);
		 offset += 2;
	}
	p.offset = offset;
}

//pos is 0 indexed
func isZero(num uint16 , pos int) bool{ 
	if( num & (1 << pos) == 0 ){
		return false;
	}
	return true;
}

func readResourceRecord(packet []byte ,offset int) (resourceRecord , int){
	record := resourceRecord{};

	name , offset,_ := readName(packet , offset);
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
		name , _ , _:= readName(packet , offset);
		record.Host = name;
	default:
		// fmt.Printf("not recgonized rrtype = %d , SKIPPING THE PAYLOAD\n",rrtype);
	}
	record.Data = append([]byte(nil), packet[offset:offset+int(rdlen)]...)
	offset+=int(rdlen);
	return record,offset;
}
func(p *parser) readAnswer(){
	for range p.dnspacket.header.ANCOUNT{
		record , newOffset := readResourceRecord(p.data,p.offset);
		p.offset = newOffset;
		p.dnspacket.answers = append(p.dnspacket.answers, record);
	}
}

func readAnswer(packet []byte , offset int , ANCOUNT int) ([]resourceRecord,int){
	panic("rewrite in progress")
}

func(p *parser) readAuthority(){
	for range p.dnspacket.header.NSCOUNT{
		record , newOffset := readResourceRecord(p.data,p.offset);
		p.offset = newOffset;
		p.dnspacket.authority = append(p.dnspacket.authority, record);
	}
}
func(p *parser) readAdditional(){
	var add []resourceRecord;
	for range  p.dnspacket.header.ARCOUNT{
		record , newOffset := readResourceRecord(p.data,p.offset);
		p.offset = newOffset;
		add = append(add, record);
	}
	p.dnspacket.additional = add;
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
	packet = unParseAnswer(DNSPacket,packet);
	packet = unParseAuthority(DNSPacket,packet);
	packet = unParseAdditional(DNSPacket , packet);
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
		fmt.Println(
			record.Name,
			record.RRtype,
			record.Addr,
			len(record.Addr.AsSlice()),
		)
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

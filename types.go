package main

import "net/netip"

type DNSPacket struct{
	header header;
	question []question;
	answers []resourceRecord;
	authority []resourceRecord;
	additional []resourceRecord;
}

type resourceRecord struct{
	Name string;
	RRtype uint16;
	Class uint16;
	TTL uint32;
	Len uint16;

	Addr netip.Addr;
	Host string; 
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

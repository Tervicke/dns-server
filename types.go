package main

type DNSPacket struct{
	header header;
	question []question;
	answers any;
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

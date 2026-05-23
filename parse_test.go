package main

import (
	"encoding/hex"
	"testing"
)

func TestReadHeader(t *testing.T){ 
	valid_query , err := hex.DecodeString("f562010000010000000000000667697468756203636f6d0000010001");
	if err != nil {
		t.Fatalf("failed to decode query : %v\n",err)
	}

	t.Run("Valid DNS query", func(t *testing.T) {
		p := parser{data:valid_query}
		p.parsePacket();
		header := p.dnspacket.header; 
		tests := []struct{
			name string
			got any
			want any
		}{
			{"Id" , header.Id , uint16(0xf562)},
			{"QDCOUNT",header.QDCOUNT,uint16(1)},
			{"ANCOUNT",header.ANCOUNT,uint16(0)},
			{"NSCOUNT",header.NSCOUNT,uint16(0)},
			{"ARCOUNT",header.ARCOUNT,uint16(0)},
			{"Query?",header.Isquery,bool(true)},
			{"AA?",header.AA,bool(false)},
			{"TC",header.TC,bool(false)},
			{"RD",header.RD,bool(true)},
			{"RA",header.RA,bool(false)},
			{"Z",header.Z,uint16(0)},
			{"Rcode",header.Rcode,uint16(0)},
		};
	
		for _ , tt := range tests{
			if tt.want != tt.got{
				t.Errorf("%s = %v , want = %v",tt.name,tt.got,tt.want);
			}
		}
	})

	incomplete_query , err := hex.DecodeString("012342123123");
	if err != nil {
		t.Fatalf("could not decode incomplete query")
	}

	t.Run("Incomplete query",func(t *testing.T) {
		p := parser{data:incomplete_query}
		p.parsePacket()
		if len(p.err) <= 0 {
			t.Errorf("did not return error with incomplete query");
		}
		if p.err[0].Error() != "header not complete"{
			t.Errorf("mismatched error msg");
		}
	})
}

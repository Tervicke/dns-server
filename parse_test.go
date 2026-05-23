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

func TestReadQuestions(t *testing.T){
	valid_query , err := hex.DecodeString("f562010000010000000000000667697468756203636f6d0000010001");
	if err != nil {
		t.Fatalf("could not decode valid query")
	}

	//valid query
	t.Run("valid query",func(t *testing.T) {
		p := parser{data:valid_query};
		p.parsePacket();
		if len(p.err) != 0 {
			t.Errorf("expected 0 errors got %d",len(p.err));
		}
		if len(p.dnspacket.question) != 1{
			t.Fatalf("no question read");
		}

		tests := []struct{
			name string
			want any
			got any
		}{
			{"Name",string("github.com"),string(p.dnspacket.question[0].Name)},
			{"class",uint16(1),p.dnspacket.question[0].Class},
			{"Type",uint16(1),p.dnspacket.question[0].Type},
			{"offset",int(28),p.offset},
		};
		for _ , tt := range tests{
			if(tt.want != tt.got){
				t.Errorf("%s , want = %v got = %v",tt.name,tt.want,tt.got);
			}
		}

	})

	incompleteHeader := valid_query[0:12];
	t.Run("incomplete question section",func(t *testing.T) {
		p := parser{data:incompleteHeader};
		p.parsePacket();

		if len(p.err ) != 1 {
			t.Errorf("expected error 1 got %d",len(p.err));
		}
		want := "label size not defined";
		got := p.err[0].Error();
		if(want != got){
			t.Errorf("error string mismatch want = %s got = %s",want,got);
		}

	})

	incompleteHeader2 := valid_query[0:25];
	t.Run("incomplete question section 2",func(t *testing.T) {
		p := parser{data:incompleteHeader2};
		p.parsePacket();

		if len(p.err ) != 1 {
			t.Errorf("expected error 1 got %d",len(p.err));
		}
		want := "question incomplete";
		got := p.err[0].Error();
		if(want != got){
			t.Errorf("error string mismatch want = %s got = %s",want,got);
		}

	})
}
func TestReadAnswer(t *testing.T) {
	answerQuery, err := hex.DecodeString(
		"1a34818000010001000000010667697468756203636f6d0000010001c00c000100010000003c000414cf4952000029ffd6000000000000",
	)

	if err != nil {
		t.Fatal("could not decode answer query")
	}

	t.Run("valid A record answer", func(t *testing.T) {
		p := parser{data: answerQuery}
		p.parsePacket()

		if len(p.err) != 0 {
			t.Fatalf("expected 0 errors got %d", len(p.err))
		}

		if len(p.dnspacket.answers) != 1 {
			t.Fatalf(
				"expected 1 answer got %d",
				len(p.dnspacket.answers),
			)
		}

		answer := p.dnspacket.answers[0]

		tests := []struct {
			name string
			got  any
			want any
		}{
			{"Name", answer.Name, "github.com"},
			{"RRtype", answer.RRtype, uint16(1)},
			{"Class", answer.Class, uint16(1)},
			{"TTL", answer.TTL, uint32(60)},
			{"Len", answer.Len, uint16(4)},
			{"Addr", answer.Addr.String(), "20.207.73.82"},
		}

		for _, tt := range tests {
			if tt.got != tt.want {
				t.Errorf(
					"%s = %v, want %v",
					tt.name,
					tt.got,
					tt.want,
				)
			}
		}
	})
}
func TestReadAuthority(t *testing.T) {
	authorityQuery, err := hex.DecodeString(
		"ccde810000010000000300010977696b697065646961036e65740000010001c00c000200010002a3000013036e73300977696b696d65646961036f726700c00c000200010002a3000006036e7331c02fc00c000200010002a3000006036e7332c02f0000291000000000000000",
	)

	if err != nil {
		t.Fatal("could not decode authority query")
	}

	t.Run("valid NS authority record", func(t *testing.T) {
		p := parser{data: authorityQuery}
		p.parsePacket()

		if len(p.err) != 0 {
			t.Fatalf("expected 0 errors got %d", len(p.err))
		}

		if len(p.dnspacket.authority) != 3 {
			t.Fatalf(
				"expected 3 authority records got %d",
				len(p.dnspacket.authority),
			)
		}

		tests := []struct {
			index int
			name  string
			got   any
			want  any
		}{
			// ns0.wikimedia.org.
			{0, "Name", p.dnspacket.authority[0].Name, "wikipedia.net"},
			{0, "RRtype", p.dnspacket.authority[0].RRtype, uint16(2)},
			{0, "Class", p.dnspacket.authority[0].Class, uint16(1)},
			{0, "TTL", p.dnspacket.authority[0].TTL, uint32(172800)},
			{0, "Len", p.dnspacket.authority[0].Len, uint16(19)},
			{0, "Host", p.dnspacket.authority[0].Host, "ns0.wikimedia.org"},

			// ns1.wikimedia.org.
			{1, "Name", p.dnspacket.authority[1].Name, "wikipedia.net"},
			{1, "RRtype", p.dnspacket.authority[1].RRtype, uint16(2)},
			{1, "Class", p.dnspacket.authority[1].Class, uint16(1)},
			{1, "TTL", p.dnspacket.authority[1].TTL, uint32(172800)},
			{1, "Len", p.dnspacket.authority[1].Len, uint16(6)},
			{1, "Host", p.dnspacket.authority[1].Host, "ns1.wikimedia.org"},

			// ns2.wikimedia.org.
			{2, "Name", p.dnspacket.authority[2].Name, "wikipedia.net"},
			{2, "RRtype", p.dnspacket.authority[2].RRtype, uint16(2)},
			{2, "Class", p.dnspacket.authority[2].Class, uint16(1)},
			{2, "TTL", p.dnspacket.authority[2].TTL, uint32(172800)},
			{2, "Len", p.dnspacket.authority[2].Len, uint16(6)},
			{2, "Host", p.dnspacket.authority[2].Host, "ns2.wikimedia.org"},
		}

		for _, tt := range tests {
			if tt.got != tt.want {
				t.Errorf(
					"record[%d] %s = %v, want %v",
					tt.index,
					tt.name,
					tt.got,
					tt.want,
				)
			}
		}
	})
}
func TestReadAdditional(t *testing.T) {
	additionalQuery, err := hex.DecodeString(
		"f32c810000010000000400090a63616c6c6f66636f646502696e0000010001c017000200010002a3000012046e733130077472732d646e73036f726700c017000200010002a3000012046e733031077472732d646e7303636f6d00c017000200010002a3000013046e733130077472732d646e7304696e666f00c017000200010002a3000012046e733031077472732d646e73036e657400c02b000100010002a3000004404ecd01c02b001c00010002a300001026200171081315340008000000000001c049000100010002a300000440600101c049001c00010002a300001026200057400100000000000000000001c067000100010002a3000004404ecc01c067001c00010002a300001026200171081215340008000000000001c086000100010002a300000440600201c086001c00010002a3000010262000574002000000000000000000010000291000000000000000",
	)

	if err != nil {
		t.Fatal("could not decode additional query")
	}

	t.Run("valid glue records", func(t *testing.T) {
		p := parser{data: additionalQuery}
		p.parsePacket()

		if len(p.err) != 0 {
			t.Fatalf("expected 0 errors got %d", len(p.err))
		}

		if len(p.dnspacket.additional) != 9 {
			t.Fatalf(
				"expected 9 additional records got %d",
				len(p.dnspacket.additional),
			)
		}

		// only deeply validate first glue record
		add := p.dnspacket.additional[0]

		tests := []struct {
			name string
			got  any
			want any
		}{
			{"Name", add.Name, "ns10.trs-dns.org"},
			{"RRtype", add.RRtype, uint16(1)},
			{"Class", add.Class, uint16(1)},
			{"TTL", add.TTL, uint32(172800)},
			{"Len", add.Len, uint16(4)},
			{"Addr", add.Addr.String(), "64.78.205.1"},
		}

		for _, tt := range tests {
			if tt.got != tt.want {
				t.Errorf(
					"%s = %v, want %v",
					tt.name,
					tt.got,
					tt.want,
				)
			}
		}
	})
}

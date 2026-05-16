package main

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)
var c *cache.Cache = cache.New(cache.NoExpiration,cache.DefaultExpiration);  

func sendDNSPacketToServer(p DNSPacket , ip string) DNSPacket{
	conn, err := net.DialUDP(
    "udp",
    nil,
    &net.UDPAddr{
        IP:   net.ParseIP(ip),
        Port: 53,
    },
	)
	if err != nil {
			panic(err)
	} 
	defer conn.Close();
	_ , err = conn.Write(unParsePacket(p));
	if err != nil {
		fmt.Println("write error:",err);
		return DNSPacket{};
	}

	response := make([]byte,4096);
	n , err := conn.Read(response)
	if err != nil {
		fmt.Println("read error:",err)
		return DNSPacket{};
	}
	response = response[:n];

	var DNSPacketResponse DNSPacket;
	DNSPacketResponse = parsePacket(response);
	return DNSPacketResponse;
}

func getRecords(expiryTime time.Time , query RRSet , ans []string) []resourceRecord{
	var answer []resourceRecord;
	TTL := max(0, uint32(time.Until(expiryTime).Seconds()))
	if(query.Type == 1){ //A record

		for i := 0 ; i < len(ans) ; i++{

			Addr , err := netip.ParseAddr(ans[i]); 
			if err != nil {
				continue;
			}
			answer = append(answer, 
				resourceRecord{
					Name: query.Name,
					RRtype: query.Type,
					Class: 1,
					TTL:TTL,
					Addr: Addr,
				},
			);

		}
	}else if(query.Type == 28){ // AAAA record
 
		for i := 0 ; i < len(ans) ; i++{

			Addr , err := netip.ParseAddr(ans[i]); 
			if err != nil {
				continue
			} 
			answer = append(answer, 
				resourceRecord{
					Name: query.Name,
					RRtype: query.Type,
					Class: 1,
					TTL:TTL,
					Addr: Addr,
				},
			);

		}
	}else if(query.Type == 2){ //NS type

		for i := 0 ; i < len(ans) ; i++{

			answer = append(answer, 
				resourceRecord{
					Name: query.Name,
					RRtype: query.Type,
					Class: 1,
					TTL:TTL,
					Host: ans[i],
				},
			);

		}

	}
	return answer;
}

//this will accept the DNSPacket and send the respone with the answer of the first DNS packet
func startResolving(p DNSPacket, currentServer string) DNSPacket {
	depth := 0

	for {
		indent := strings.Repeat("│  ", depth)

		fmt.Printf("%s→ Querying server: %s\n", indent, currentServer)

		response := sendDNSPacketToServer(p, currentServer)

		if response.header.ANCOUNT > 0 {
			fmt.Printf("%s✓ Final answer received\n", indent)
			return response
		}

		// Cache authority NS records
		for _, r := range response.authority {
			if r.RRtype != 2 {
				continue
			}

			key := RRSet{r.Name, 2}.getString()

			var values []string
			if old, found := c.Get(key); found {
				values = old.([]string)
			}

			values = append(values, r.Host)
			c.Set(key, values, time.Duration(r.TTL)*time.Second)
		}

		// Cache glue records
		for _, r := range response.additional {
			if r.RRtype != 1 && r.RRtype != 28 {
				continue
			}

			key := RRSet{r.Name, r.RRtype}.getString()

			var values []string
			if old, found := c.Get(key); found {
				values = old.([]string)
			}

			values = append(values, r.Addr.String())
			c.Set(key, values, time.Duration(r.TTL)*time.Second)
		}

		var nextNS string

		for _, r := range response.authority {
			if r.RRtype == 2 {
				nextNS = r.Host
				break
			}
		}

		if nextNS == "" {
			panic("did not find NS")
		}

		fmt.Printf("%s→ Next NS: %s\n", indent, nextNS)

		currentServer = resolveHostNameToIP(nextNS)

		fmt.Printf(
			"%s→ Resolved %s -> %s\n\n",
			indent,
			nextNS,
			currentServer,
		)

		depth++
	}

	return DNSPacket{}
}
func resolveHostNameToIP(host string) string {

	// normalize
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	// first try cache directly
	query := RRSet{
		Name: host,
		Type: 1, // A record
	}

	ans, found := c.Get(query.getString())
	if found {
		ips := ans.([]string)

		if len(ips) > 0 {
			return ips[0]
		}
	}

	// build DNS query packet
	packet := DNSPacket{
		header: header{
			Id:      uint16(rand.Intn(65535)),
			RD:      true,
			QDCOUNT: 1,
			Isquery: true,
		},

		question: []question{
			{
				Name:  host,
				Type:  1,
				Class: 1,
			},
		},
	}

	// get best starting point
	startingServer := returnClosestDelegation(query)

	// fully resolve
	response := startResolving(packet, startingServer)

	// answer section contains final A records
	for _, r := range response.answers{

		if r.RRtype == 1 {
			return r.Addr.String()
		}
	}

	panic("could not resolve hostname to ip")
}

//the only jov of this function is to give me the closestDelegation
func returnClosestDelegation(query RRSet) string {
	// var answerRecord []resourceRecord;
	var closestDelegation string =  "198.41.0.4"; //always the root

	ans , found := c.Get(query.getString());
	if found{
		return ans.([]string)[0]; //can be hostname or the ip also
	} 

	if(query.Type == 1){ //Try with NS server
		//check for the (NS,A)
		NSquery := RRSet{query.Name , 2}; //for the NS record 
		ans , valid := c.Get(NSquery.getString());
		if valid {
			//get the first hostname (for now)
			hostName := (ans.([]string))[0]; 
			//get the server ip
			closestDelegation = returnClosestDelegation(RRSet{hostName,1}) //serverip which will provide me the record 
			return closestDelegation;
		}
	}

	name := query.Name;
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	zone := parts[len(parts)-1]
	//check for the (ZONE,NS)
	zoneNSQuery := RRSet{zone,2}; //depending upon whether
	ans , found = c.Get(zoneNSQuery.getString());
	if found {
			//get the first hostname (for now)
			hostName := (ans.([]string))[0]; 
			//get the server ip
			closestDelegation = returnClosestDelegation(RRSet{hostName,1})
			return closestDelegation
	}

	return closestDelegation;
}

func processDNSPacket(DNSPacket DNSPacket , upstream net.Addr , conn *net.UDPConn) {
	//set the default value in solovedQuestion
	q := DNSPacket.question[0] //only process the first question
		query := RRSet{q.Name,q.Type};
		//see if u the exact query in the cache
		ans , expiryTime , found := c.GetWithExpiration(query.getString());
		if found{
			answer := getRecords(expiryTime,query,ans.([]string));

			ansPacket := DNSPacket;
			ansPacket.answers = answer;
			ansPacket.header.ANCOUNT = uint16(len(answer));
			ansPacket.header.RA = true;
			ansPacket.header.Isquery = false;

			respBytes := unParsePacket(ansPacket); 
			conn.WriteTo(respBytes,upstream);
		}else{
			closestDelegationIP := returnClosestDelegation(query);//get the server from where u can start resolving
			answer := startResolving(DNSPacket , closestDelegationIP)
			//cache the answer
			var IPs []string;
			var TTL uint32 = math.MaxUint32;
			for _ , ans := range answer.answers{
				IPs = append(IPs, ans.Addr.String())
				TTL = min(TTL,ans.TTL);
			}
			c.Add(query.getString(),IPs,time.Duration(TTL)*time.Second);
			answer.header.RA = true;
			respBytes := unParsePacket(answer); 
			conn.WriteTo(respBytes,upstream);
		}
}

func startUDPServer(){
	address , err := net.ResolveUDPAddr("udp",":8080");
	if err != nil {
		log.Fatal(err)
	}
	conn , err := net.ListenUDP("udp",address);
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Started the udp server on port 8080")
	defer conn.Close()
	buffer := make([]byte,512)
	for {
		n  , addr , err := conn.ReadFrom(buffer)

		if err != nil {
			fmt.Printf("ERROR: %v\n",err);
			continue;
		}
		packetdata := buffer[:n];
		DNSPacket := parsePacket(packetdata);
		processDNSPacket(DNSPacket,addr,conn);

	}
}

func main(){
	// insertCacheRecord();
	startUDPServer();
}

func insertCacheRecord() {
	q := RRSet{"syswraith.com", 1}
	
	addr, _ := netip.ParseAddr("185.199.110.153")

	c.Add(
		q.getString(),
		[]string{addr.String()},
		cache.DefaultExpiration,
	)
}

package main

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)
var c *cache.Cache = cache.New(cache.NoExpiration,cache.DefaultExpiration);  

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

func startResolving(p DNSPacket , currentServer string) (DNSPacket , error ){
	fmt.Println("resolving with the server",currentServer)
	response := sendDNSPacketToServer(p,currentServer);
	
	//error check
	if response.header.Rcode == 3{
		return DNSPacket{},errors.New("NXDOMAIN");
	}
	if response.header.Rcode == 2{
		return DNSPacket{},errors.New("SERVFAIL");
	}


	//answer found from the authoritative server 
	if response.header.ANCOUNT > 0 || response.header.AA{
		return response , nil;
	}

	//cache the NS records	
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

	for _, r := range response.authority { //go over all the NS records
		if r.RRtype == 2{ //indicating a NS record
			nextNS := r.Host;
			currentServer , err := resolveHostNameToIP(nextNS);
			if err != nil{
				return DNSPacket{},nil;
			}
			answer , err := startResolving(p,currentServer);
			if err == nil {
				return answer,nil;
			}
			if err.Error() == "NXDOMAIN"{
				return DNSPacket{},err;
			}
			if err.Error() == "SERVFAIL"{
				return DNSPacket{},err;
			}
		}
	}

	return DNSPacket{},errors.New("SERVFAIL")
}

func resolveHostNameToIP(host string) (string , error) {

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
			return ips[0],nil
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
	response,err := startResolving(packet, startingServer)
	if err != nil {
		return "",err 
	}

	// answer section contains final A records
	for _, r := range response.answers{

		if r.RRtype == 1 {
			return r.Addr.String(),nil
		}
	}

	return "",errors.New("SERVFAIL")
}

//the only job of this function is to give me the closestDelegation
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
	logDNS(DNSPacket);
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
			answer , err := startResolving(DNSPacket , closestDelegationIP)
			if err != nil { 
				if err.Error() == "NXDOMAIN"{
					fmt.Println("NXDOMAIN - fail")
					DNSPacket.header.Rcode = 3;
					answer = DNSPacket;
				}else if err.Error() == "SERVFAIL"{
					fmt.Println("NXDOMAIN - fail")
					DNSPacket.header.Rcode = 2;
					answer = DNSPacket;
				}else{
					panic("unexpected error")
				}
			}
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
			logDNS(answer);
		}
}


func main(){
	startUDPServer(":8080");
}

func logDNS(p DNSPacket){
	var mp map[uint16]string = make(map[uint16]string);
	mp[1] = "A"
	mp[28] = "AAAA";
	mp[65] = "HTTPS";
	fmt.Printf("Q: %s %s\n",p.question[0].Name,mp[p.question[0].Type]);

	for _ , ans := range p.answers{
		fmt.Printf("A: %s %s\n",ans.Name,ans.Addr.String())
	}
}

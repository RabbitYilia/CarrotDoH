package main

import (
	"bufio"
	"github.com/babolivier/go-doh-client"
	"github.com/jpillora/go-tld"
	"github.com/miekg/dns"
	"github.com/seiflotfy/cuckoofilter"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type Config struct {
	Listen string `yaml:"listen"`
	Normal string `yaml:"normal"`
	Speed  string `yaml:"speed"`
}

var NormalResolver doh.Resolver
var SpeedResolver doh.Resolver
var filter *cuckoo.Filter

func main() {
	conf := new(Config)
	yamlFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(yamlFile, conf)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Listen on:" + conf.Listen)
	filter = cuckoo.NewFilter(1000000)
	LoadListToFilter("List.txt")
	NormalResolver = doh.Resolver{
		Host:  conf.Normal, // Change this with your favourite DoH-compliant resolver.
		Class: doh.IN,
	}
	SpeedResolver = doh.Resolver{
		Host:  conf.Speed, // Change this with your favourite DoH-compliant resolver.
		Class: doh.IN,
	}
	dns.HandleFunc(".", handleRequest)
	go func() {
		srv := &dns.Server{Addr: conf.Listen, Net: "udp"}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatal("Failed to set udp listener %s\n", err.Error())
		}
	}()
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case s := <-sig:
			log.Fatalf("Signal (%d) received, stopping\n", s)
		}
	}
}

func LoadListToFilter(FileName string) {
	fi, err := os.Open(FileName)
	if err != nil {
		log.Fatal(err)
	}
	br := bufio.NewReader(fi)
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		filter.InsertUnique(line)
	}
	fi.Close()
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	log.Println("===============")
	domain := strings.TrimRight(r.Question[0].Name, ".")
	ip, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	log.Println("Request From :" + ip)
	var m *dns.Msg
	if DeterminePath(domain) {
		log.Println("Query:" + domain + " Go Speed")
		m = ProcessReq(SpeedResolver, r)
	} else {
		log.Println("Query:" + domain + " Go Normal")
		m = ProcessReq(NormalResolver, r)
	}
	log.Println(m.Answer)
	w.WriteMsg(m)
}

func DeterminePath(domain string) bool {
	if strings.Contains(domain, ".cn") {
		return true
	}
	if filter.Lookup([]byte(domain)) {
		return true
	}
	ParsedDomain, err := tld.Parse("http://" + domain)
	if err != nil {
		return false
	}
	if filter.Lookup([]byte(ParsedDomain.Domain + "." + ParsedDomain.TLD)) {
		return true
	}
	return false
}

func ProcessReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	var m *dns.Msg
	switch r.Question[0].Qtype {
	case dns.TypePTR:
		log.Println("Quest Type: PTR")
		m = ProcessPTRReq(Resolver, r)
	case dns.TypeA:
		log.Println("Quest Type: A")
		m = ProcessAReq(Resolver, r)
	case dns.TypeAAAA:
		log.Println("Quest Type: AAAA")
		m = ProcessAAAAReq(Resolver, r)
	case dns.TypeCNAME:
		log.Println("Quest Type: CNAME")
		m = ProcessCNAMEReq(Resolver, r)
	case dns.TypeMX:
		log.Println("Quest Type: MX")
		m = ProcessMXReq(Resolver, r)
	case dns.TypeNS:
		log.Println("Quest Type: NS")
		m = ProcessNSReq(Resolver, r)
	case dns.TypeSRV:
		log.Println("Quest Type: SRV")
		m = ProcessSRVReq(Resolver, r)
	case dns.TypeSOA:
		log.Println("Quest Type: SOV")
		m = ProcessSOAReq(Resolver, r)
	case dns.TypeTXT:
		log.Println("Quest Type: TXT")
		m = ProcessTXTReq(Resolver, r)
	default:
		log.Println("Quest Type: Unknown")
		m = ReturnEmpty(Resolver, r)
	}
	return m
}

func ReturnEmpty(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	m.Rcode = dns.RcodeNameError
	return m
}

func ProcessSRVReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	domain := strings.TrimRight(r.Question[0].Name, ".")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	SRVResult, SRVTTL, err := Resolver.LookupSRV(domain)
	if err == nil {
		for ID, SRVRecord := range SRVResult {
			Response := new(dns.SRV)
			Response.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: SRVTTL[ID]}
			Response.Target = ProcessValue(SRVRecord.Target)
			Response.Port = SRVRecord.Port
			Response.Priority = SRVRecord.Priority
			Response.Weight = SRVRecord.Weight
			m.Answer = append(m.Answer, Response)
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	return m
}

//tested
func ProcessSOAReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	domain := strings.TrimRight(r.Question[0].Name, ".")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	SOAResult, SOATTL, err := Resolver.LookupSOA(domain)
	if err == nil {
		for ID, SOARecord := range SOAResult {
			Response := new(dns.SOA)
			Response.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: SOATTL[ID]}
			Response.Ns = ProcessValue(SOARecord.PrimaryNS)
			Response.Expire = uint32(SOARecord.Expire)
			Response.Minttl = SOARecord.Minimum
			Response.Refresh = uint32(SOARecord.Refresh)
			Response.Mbox = ProcessValue(SOARecord.RespMailbox)
			Response.Retry = uint32(SOARecord.Retry)
			Response.Serial = SOARecord.Serial
			m.Answer = append(m.Answer, Response)
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	return m
}

//tested
func ProcessTXTReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	domain := strings.TrimRight(r.Question[0].Name, ".")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	TXTResult, TXTTTL, err := Resolver.LookupTXT(domain)
	if err == nil {
		for ID, NSRecord := range TXTResult {
			Response := new(dns.TXT)
			Response.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: TXTTTL[ID]}
			Response.Txt = append(Response.Txt, NSRecord.TXT)
			m.Answer = append(m.Answer, Response)
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	return m
}

//tested
func ProcessNSReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	domain := strings.TrimRight(r.Question[0].Name, ".")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	NSResult, NSTTL, err := Resolver.LookupNS(domain)
	if err == nil {
		for ID, NSRecord := range NSResult {
			Response := new(dns.NS)
			Response.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: NSTTL[ID]}
			Response.Ns = ProcessValue(NSRecord.Host)
			m.Answer = append(m.Answer, Response)
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	return m
}

//tested
func ProcessMXReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	domain := strings.TrimRight(r.Question[0].Name, ".")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	MXResult, MXTTL, err := Resolver.LookupMX(domain)
	if err == nil {
		for ID, MXRecord := range MXResult {
			Response := new(dns.MX)
			Response.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: MXTTL[ID]}
			Response.Mx = ProcessValue(MXRecord.Host)
			Response.Preference = MXRecord.Pref
			m.Answer = append(m.Answer, Response)
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	return m
}

//tested
func ProcessCNAMEReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	domain := strings.TrimRight(r.Question[0].Name, ".")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	CNAMEResult, CNAMETTL, err := Resolver.LookupCNAME(domain)
	if err == nil {
		for ID, CNAMERecord := range CNAMEResult {
			Response := new(dns.CNAME)
			Response.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: CNAMETTL[ID]}
			Response.Target = ProcessValue(CNAMERecord.CNAME)
			m.Answer = append(m.Answer, Response)
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	return m
}

//tested
func ProcessPTRReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	domain := strings.TrimRight(r.Question[0].Name, ".")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	PTRResult, PTRTTL, err := Resolver.LookupPTR(domain)
	if err == nil {
		for ID, PTRRecord := range PTRResult {
			Response := new(dns.PTR)
			Response.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: PTRTTL[ID]}
			Response.Ptr = ProcessValue(PTRRecord.PTR)
			m.Answer = append(m.Answer, Response)
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	return m
}

//tested
func ProcessAReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	domain := strings.TrimRight(r.Question[0].Name, ".")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	AResult, ATTL, err := Resolver.LookupA(domain)
	if err == nil {
		for ID, ARecord := range AResult {
			Response := new(dns.A)
			Response.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ATTL[ID]}
			Response.A = net.ParseIP(ARecord.IP4)
			m.Answer = append(m.Answer, Response)
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	return m
}

//tested
func ProcessAAAAReq(Resolver doh.Resolver, r *dns.Msg) *dns.Msg {
	domain := strings.TrimRight(r.Question[0].Name, ".")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.RecursionAvailable = true
	m.RecursionDesired = true
	m.Answer = []dns.RR{}
	AAAAResult, AAAATTL, err := Resolver.LookupAAAA(domain)
	if err == nil {
		for ID, AAAARecord := range AAAAResult {
			Response := new(dns.AAAA)
			Response.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: AAAATTL[ID]}
			Response.AAAA = net.ParseIP(AAAARecord.IP6)
			m.Answer = append(m.Answer, Response)
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	return m
}

//tested
func ProcessValue(Value string) string {
	IP := net.ParseIP(Value)
	if IP == nil {
		return strings.Trim(Value, ".") + "."
	} else {
		return IP.String()
	}
}

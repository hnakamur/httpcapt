package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type addrPortPair struct {
	src netip.AddrPort
	dst netip.AddrPort
}

var errUnexpectedEndpointType = errors.New("unexpected endpoint type")
var errUnexpectedIPAddressLen = errors.New("unexpected IP Address bytes length")

func ipAddrPortFromEndpoints(ip, tcp gopacket.Endpoint) (netip.AddrPort, error) {
	ipAddr, err := ipAddrFromEndpoint(ip)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := tcpPortFromEndpoint(tcp)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ipAddr, port), nil
}

func ipAddrFromEndpoint(ep gopacket.Endpoint) (netip.Addr, error) {
	switch ep.EndpointType() {
	case layers.EndpointIPv4, layers.EndpointIPv6:
		addr, ok := netip.AddrFromSlice(ep.Raw())
		if !ok {
			return netip.Addr{}, errUnexpectedIPAddressLen
		}
		return addr, nil
	default:
		return netip.Addr{}, errUnexpectedEndpointType
	}
}

func tcpPortFromEndpoint(ep gopacket.Endpoint) (uint16, error) {
	if ep.EndpointType() != layers.EndpointTCPPort {
		return 0, errUnexpectedEndpointType
	}
	return binary.BigEndian.Uint16(ep.Raw()), nil
}

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	requests map[addrPortPair]*http.Request
	mu       sync.Mutex
}

func newHttpStreamFactory() *httpStreamFactory {
	return &httpStreamFactory{
		requests: make(map[addrPortPair]*http.Request),
	}
}

func (f *httpStreamFactory) putRequest(pair addrPortPair, req *http.Request) {
	log.Printf("putRequest req=%p", req)
	f.mu.Lock()
	f.requests[pair] = req
	f.mu.Unlock()
}

func (f *httpStreamFactory) takeRequest(pair addrPortPair) *http.Request {
	f.mu.Lock()
	req := f.requests[pair]
	delete(f.requests, pair)
	f.mu.Unlock()
	log.Printf("takeRequest req=%p", req)
	return req
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	factory        *httpStreamFactory
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (f *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		factory:   f,
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

const responsePrefix = "HTTP/"

func (s *httpStream) run() {
	buf := bufio.NewReader(&s.r)
	for {
		prefix, err := buf.Peek(len(responsePrefix))
		if err == io.EOF {
			return
		} else if err != nil {
			log.Printf("buf.Peek err=%v", err)
		}

		if string(prefix) == responsePrefix {
			src, err := ipAddrPortFromEndpoints(s.net.Src(), s.transport.Src())
			if err != nil {
				log.Printf("bad source address: %s", err)
				return
			}
			dst, err := ipAddrPortFromEndpoints(s.net.Dst(), s.transport.Dst())
			if err != nil {
				log.Printf("bad source address: %s", err)
				return
			}
			pair := addrPortPair{src: dst, dst: src}
			req := s.factory.takeRequest(pair)

			resp, err := http.ReadResponse(buf, req)
			if err != nil {
				log.Println("Error reading stream", s.net, s.transport, ":", err)
			} else {
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Printf("error reading response body, %s", err)
					return
				}
				resp.Body.Close()
				log.Println("Received response from stream", s.net, s.transport, ":", resp, "body:", string(bodyBytes), "with", len(bodyBytes), "bytes in response body")
			}
			continue
		}

		req, err := http.ReadRequest(buf)
		if err != nil {
			log.Println("Error reading stream", s.net, s.transport, ":", err)
		} else {
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				log.Printf("error reading request body, %s", err)
				return
			}
			req.Body.Close()
			log.Println("Received request from stream", s.net, s.transport, ":", req, "body:", string(bodyBytes), "with", len(bodyBytes), "bytes in request body")

			src, err := ipAddrPortFromEndpoints(s.net.Src(), s.transport.Src())
			if err != nil {
				log.Printf("bad source address: %s", err)
				return
			}
			dst, err := ipAddrPortFromEndpoints(s.net.Dst(), s.transport.Dst())
			if err != nil {
				log.Printf("bad source address: %s", err)
				return
			}
			pair := addrPortPair{src: src, dst: dst}
			s.factory.putRequest(pair, req)
		}
	}
}

func main() {
	dev := flag.String("i", "any", "device name")
	filter := flag.String("f", "tcp and port 80", "filter")
	snaplen := flag.Int("snaplen", 1500, "maximum size to read for each packet")
	promisc := flag.Bool("promisc", true, "whether to put the interface in promiscuous mode")
	timeout := flag.Duration("timeout", 0, "timeout (0=forever)")
	flag.Parse()

	if *timeout == 0 {
		*timeout = pcap.BlockForever
	}
	handle, err := pcap.OpenLive(*dev, int32(*snaplen), *promisc, *timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Filtering capture targets
	if err = handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := newHttpStreamFactory()
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// Get decoded packets through chann
	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			log.Println("Unusable packet")
			continue
		}
		tcp := packet.TransportLayer().(*layers.TCP)
		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
	}
}

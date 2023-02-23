package httpcapt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type CaptureResult struct {
	RequestTime time.Time
	Time        time.Time
	Client      netip.AddrPort
	Server      netip.AddrPort
	Response    *http.Response
	Error       error
}

var errUnexpectedEndpointType = errors.New("unexpected endpoint type")
var errUnexpectedIPAddressLen = errors.New("unexpected IP Address length")

type timedHTTPRequest struct {
	time time.Time
	req  *http.Request
}

type HTTPStreamFactory struct {
	packetSource *gopacket.PacketSource
	resultC      chan<- CaptureResult
	requests     map[addrPortPair]timedHTTPRequest
	mu           sync.Mutex
}

func NewHTTPStreamFactory(packetSource *gopacket.PacketSource, resultC chan<- CaptureResult) *HTTPStreamFactory {
	return &HTTPStreamFactory{
		packetSource: packetSource,
		resultC:      resultC,
		requests:     make(map[addrPortPair]timedHTTPRequest),
	}
}

// HTTPStreamFactory implements tcpassembly.StreamFactory
var _ tcpassembly.StreamFactory = (*HTTPStreamFactory)(nil)

func (f *HTTPStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		factory:   f,
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run()
	return &hstream.r
}

func (f *HTTPStreamFactory) Run(ctx context.Context) error {
	streamPool := tcpassembly.NewStreamPool(f)
	assembler := tcpassembly.NewAssembler(streamPool)
	for {
		select {
		case packet, ok := <-f.packetSource.Packets():
			if !ok {
				return nil
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (f *HTTPStreamFactory) putRequest(pair addrPortPair, req timedHTTPRequest) {
	f.mu.Lock()
	f.requests[pair] = req
	f.mu.Unlock()
}

func (f *HTTPStreamFactory) takeRequest(pair addrPortPair) (timedHTTPRequest, bool) {
	f.mu.Lock()
	req, ok := f.requests[pair]
	if ok {
		delete(f.requests, pair)
	}
	f.mu.Unlock()
	return req, ok
}

type httpStream struct {
	factory        *HTTPStreamFactory
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

const responsePrefix = "HTTP/"

func (s *httpStream) run() {
	buf := bufio.NewReader(&s.r)
	for {
		prefix, err := buf.Peek(len(responsePrefix))
		if err == io.EOF {
			return
		}

		now := time.Now()
		if err != nil {
			s.sendErr(now, fmt.Errorf("peek packet: %s", err))
			return
		}
		src, err := ipAddrPortFromEndpoints(s.net.Src(), s.transport.Src())
		if err != nil {
			s.sendErr(now, fmt.Errorf("bad source address: %s", err))
			return
		}
		dst, err := ipAddrPortFromEndpoints(s.net.Dst(), s.transport.Dst())
		if err != nil {
			s.sendErr(now, fmt.Errorf("bad destination address: %s", err))
			return
		}

		if string(prefix) == responsePrefix {
			pair := addrPortPair{src: dst, dst: src}
			req, _ := s.factory.takeRequest(pair)

			resp, err := http.ReadResponse(buf, req.req)
			if err != nil {
				s.sendErr(now, fmt.Errorf("read response: src=%s, dst=%s, err=%s", src, dst, err))
				return
			}
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				s.sendErr(now, fmt.Errorf("read response body: src=%s, dst=%s, err=%s", src, dst, err))
				return
			}
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			s.sendResponse(now, dst, src, resp, req.time)
		} else {
			req, err := http.ReadRequest(buf)
			if err != nil {
				s.sendErr(now, fmt.Errorf("read request: src=%s, dst=%s, err=%s", src, dst, err))
				return
			}
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				s.sendErr(now, fmt.Errorf("read requset body: src=%s, dst=%s, err=%s", src, dst, err))
				return
			}
			req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			pair := addrPortPair{src: src, dst: dst}
			s.factory.putRequest(pair, timedHTTPRequest{time: now, req: req})
		}
	}
}

func (s *httpStream) sendErr(now time.Time, err error) {
	s.factory.resultC <- CaptureResult{
		Time:  now,
		Error: err,
	}
}

func (s *httpStream) sendResponse(now time.Time, client, server netip.AddrPort, resp *http.Response, reqTime time.Time) {
	s.factory.resultC <- CaptureResult{
		RequestTime: reqTime,
		Time:        now,
		Client:      client,
		Server:      server,
		Response:    resp,
	}
}

type addrPortPair struct {
	src netip.AddrPort
	dst netip.AddrPort
}

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

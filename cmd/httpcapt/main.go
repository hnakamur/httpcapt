package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/hnakamur/httpcapt"
)

func main() {
	dev := flag.String("i", "any", "device name")
	filter := flag.String("f", "tcp and port 80", "filter")
	snaplen := flag.Int("snaplen", 1500, "maximum size to read for each packet")
	promisc := flag.Bool("promisc", false, "whether to put the interface in promiscuous mode")
	timeout := flag.Duration("timeout", time.Second, "timeout (0=forever)")
	flag.Parse()

	if *timeout == 0 {
		*timeout = pcap.BlockForever
	}
	ctx := context.Background()
	if err := run(ctx, *dev, *filter, int32(*snaplen), *promisc, *timeout); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, dev, filter string, snaplen int32, promisc bool, timeout time.Duration) error {
	notifyCtx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	handle, err := pcap.OpenLive(dev, snaplen, promisc, timeout)
	if err != nil {
		return fmt.Errorf("open device to capture: %s", err)
	}
	defer handle.Close()

	if err = handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("set bpf filter: %s", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	resultC := make(chan httpcapt.CaptureResult)
	streamFactory := httpcapt.NewHTTPStreamFactory(packetSource, resultC)
	go streamFactory.Run(notifyCtx)
	for {
		select {
		case result := <-resultC:
			if result.Error != nil {
				return fmt.Errorf("capture: %s", result.Error)
			}
			resp := result.Response
			req := resp.Request
			reqBodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return fmt.Errorf("read body from request: %s", result.Error)
			}
			respBodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("read body from response: %s", result.Error)
			}
			log.Printf("result: reqTime=%s, respTime=%s, client=%s, server=%s, request=%+v, requestBody=%s, response=%+v, responseBody=%s",
				result.RequestTime, result.Time, result.Client, result.Server, req, string(reqBodyBytes), resp, string(respBodyBytes))
		case <-notifyCtx.Done():
			return notifyCtx.Err()
		}
	}
}

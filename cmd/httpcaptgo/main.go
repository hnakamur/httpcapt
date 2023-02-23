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
	"github.com/google/gopacket/layers"
	"github.com/hnakamur/httpcapt"
	"github.com/packetcap/go-pcap"
)

func main() {
	dev := flag.String("i", "any", "device name")
	filter := flag.String("f", "tcp and port 80", "filter")
	snaplen := flag.Int("snaplen", 1500, "maximum size to read for each packet")
	promisc := flag.Bool("promisc", true, "whether to put the interface in promiscuous mode")
	timeout := flag.Duration("timeout", time.Second, "timeout (0=forever)")
	syscalls := flag.Bool("syscall", false, "use system calls")
	flag.Parse()

	ctx := context.Background()
	if err := run(ctx, *dev, *filter, int32(*snaplen), *promisc, *timeout, *syscalls); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, dev, filter string, snaplen int32, promisc bool, timeout time.Duration, syscalls bool) error {
	notifyCtx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	handle, err := pcap.OpenLive(dev, snaplen, promisc, timeout, syscalls)
	if err != nil {
		return fmt.Errorf("open device to capture: %s", err)
	}
	defer handle.Close()

	if err = handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("set bpf filter: %s", err)
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
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

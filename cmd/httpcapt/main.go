package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/hnakamur/httpcapt"
)

func main() {
	dev := flag.String("i", "any", "device name or \"any\" for all devices")
	filter := flag.String("f", "tcp and port 80", "filter")
	flag.Parse()

	ctx := context.Background()
	if err := run(ctx, *dev, *filter); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, dev, filter string) error {
	notifyCtx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	resultC := make(chan httpcapt.CaptureResult)

	capturer, err := httpcapt.NewEthernetCapturer(dev)
	if err != nil {
		return fmt.Errorf("open device to capture: %s", err)
	}
	if err = capturer.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("set bpf filter: %s", err)
	}
	go capturer.Capture(notifyCtx, resultC)

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

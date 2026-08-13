package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kilo666mj/rilldns/internal/controlclient"
	"github.com/kilo666mj/rilldns/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	apiURL := flag.String("api-url", "http://127.0.0.1:8053", "RillDNS management API URL")
	dnsAddress := flag.String("dns-address", "127.0.0.1:53", "RillDNS DNS listener used for resolution tests")
	flag.Parse()

	api, err := controlclient.New(*apiURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := mcpserver.New(api, *dnsAddress).Run(ctx, &mcp.StdioTransport{}); err != nil && !normalClose(err) {
		log.Printf("RillDNS MCP server stopped: %v", err)
		os.Exit(1)
	}
}

func normalClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || strings.HasSuffix(err.Error(), ": EOF")
}

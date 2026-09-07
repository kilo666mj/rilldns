package main

import (
	"flag"
	"log"

	"github.com/kilo666mj/rilldns/internal/cachezones"
)

func main() {
	zoneDir := flag.String("zone-dir", "/var/lib/rilldns/zones", "directory containing authoritative .zone files")
	output := flag.String("output", "/var/lib/rilldns/cache-zones.conf", "generated CoreDNS fragment")
	flag.Parse()
	content, err := cachezones.Render(*zoneDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := cachezones.WriteAtomic(*output, content); err != nil {
		log.Fatal(err)
	}
}

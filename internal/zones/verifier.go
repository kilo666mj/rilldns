package zones

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSVerifier struct {
	Address        string
	NotifyAddress  string
	ReplicaAddress string
	Interval       time.Duration
	TSIGName       string
	TSIGSecret     string
}

func (v DNSVerifier) Notify(ctx context.Context, zone string) error {
	if v.NotifyAddress == "" {
		return nil
	}
	message := new(dns.Msg)
	message.SetNotify(dns.Fqdn(zone))
	if v.TSIGName == "" || v.TSIGSecret == "" {
		return fmt.Errorf("NOTIFY requires a TSIG name and secret")
	}
	name := dns.Fqdn(strings.ToLower(v.TSIGName))
	message.SetTsig(name, dns.HmacSHA256, 300, time.Now().Unix())
	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second, TsigSecret: map[string]string{name: v.TSIGSecret}}
	response, _, err := client.ExchangeContext(ctx, message, v.NotifyAddress)
	if err != nil {
		return err
	}
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("NOTIFY returned %s", dns.RcodeToString[response.Rcode])
	}
	return nil
}

func (v DNSVerifier) WaitForSerial(ctx context.Context, zone string, serial uint32) error {
	return v.wait(ctx, v.Address, zone, func(response *dns.Msg) bool {
		for _, rr := range response.Answer {
			if soa, ok := rr.(*dns.SOA); ok && soa.Serial == serial {
				return true
			}
		}
		return false
	}, fmt.Sprintf("serial %d", serial))
}

func (v DNSVerifier) WaitForAbsence(ctx context.Context, zone string) error {
	return v.wait(ctx, v.Address, zone, func(response *dns.Msg) bool {
		return response.Authoritative && response.Rcode == dns.RcodeNameError
	}, "authoritative NXDOMAIN")
}

func (v DNSVerifier) WaitForReplicaSerial(ctx context.Context, zone string, serial uint32) error {
	if v.ReplicaAddress == "" {
		return nil
	}
	return v.wait(ctx, v.ReplicaAddress, zone, func(response *dns.Msg) bool {
		for _, rr := range response.Answer {
			if soa, ok := rr.(*dns.SOA); ok && soa.Serial == serial {
				return true
			}
		}
		return false
	}, fmt.Sprintf("replica serial %d", serial))
}

func (v DNSVerifier) WaitForReplicaAbsence(ctx context.Context, zone string) error {
	if v.ReplicaAddress == "" {
		return nil
	}
	return v.wait(ctx, v.ReplicaAddress, zone, func(response *dns.Msg) bool {
		return response.Authoritative && response.Rcode == dns.RcodeNameError
	}, "authoritative replica NXDOMAIN")
}

func (v DNSVerifier) wait(ctx context.Context, address, zone string, accepted func(*dns.Msg) bool, wanted string) error {
	interval := v.Interval
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	client := &dns.Client{Net: "udp", Timeout: time.Second}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var last string
	for {
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
		response, _, err := client.ExchangeContext(ctx, message, address)
		if err == nil {
			if accepted(response) {
				return nil
			}
			last = fmt.Sprintf("rcode %s, authoritative %t", dns.RcodeToString[response.Rcode], response.Authoritative)
			for _, rr := range response.Answer {
				if soa, ok := rr.(*dns.SOA); ok {
					last = fmt.Sprintf("served serial %d", soa.Serial)
				}
			}
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("verification timeout waiting for %s (%s): %w", wanted, last, ctx.Err())
		case <-ticker.C:
		}
	}
}

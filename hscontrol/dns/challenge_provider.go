package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	cloudflare "github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"github.com/rs/zerolog/log"
)

var (
	ErrDNSChallengeProviderDisabled = errors.New("dns challenge provider disabled")
	ErrDNSPropagationTimeout        = errors.New("dns propagation timeout")
	ErrInvalidDNSChallengeName      = errors.New("invalid dns challenge fqdn")
)

const (
	defaultTXTTTLSeconds           = 120
	defaultPropagationTimeout      = 120 * time.Second
	defaultPropagationPollInterval = 5 * time.Second
	dnsLookupTimeout               = 10 * time.Second
)

var propagationResolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

type lookupTXTFunc func(context.Context, string, string) ([]string, error)

type cloudflareDNSClient interface {
	GetRecords(context.Context, string) ([]libdns.Record, error)
	DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error)
	SetRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error)
}

// ChallengeProvider creates and updates ACME DNS-01 TXT records.
type ChallengeProvider interface {
	UpsertTXT(ctx context.Context, fqdn, value string) error
}

// NewChallengeProvider creates a DNS challenge provider from configuration.
func NewChallengeProvider(cfg types.DNSChallengeConfig) (ChallengeProvider, error) {
	if !cfg.Cloudflare.Enabled() {
		return nil, ErrDNSChallengeProviderDisabled
	}

	return &cloudflareProvider{
		provider: &cloudflare.Provider{
			APIToken: cfg.Cloudflare.APIToken,
		},
		zone:                    normalizeZone(cfg.Cloudflare.Zone),
		lookupTXT:               lookupTXTAt,
		propagationResolvers:    propagationResolvers,
		propagationTimeout:      defaultPropagationTimeout,
		propagationPollInterval: defaultPropagationPollInterval,
	}, nil
}

type cloudflareProvider struct {
	provider cloudflareDNSClient
	zone     string

	lookupTXT               lookupTXTFunc
	propagationResolvers    []string
	propagationTimeout      time.Duration
	propagationPollInterval time.Duration
}

func (p *cloudflareProvider) UpsertTXT(ctx context.Context, fqdn, value string) error {
	recordName, err := relativeRecordName(fqdn, p.zone)
	if err != nil {
		return err
	}

	records, err := p.provider.GetRecords(ctx, p.zone)
	if err != nil {
		return fmt.Errorf("listing cloudflare records: %w", err)
	}

	absFQDN := ensureTrailingDot(strings.ToLower(strings.TrimSpace(fqdn)))
	value = strings.TrimSpace(value)

	var found bool
	for _, rec := range records {
		if !isTXTRecordForName(rec, p.zone, absFQDN) {
			continue
		}

		if strings.TrimSpace(rec.RR().Data) == value {
			found = true
			continue
		}

		_, err := p.provider.DeleteRecords(ctx, p.zone, []libdns.Record{rec})
		if err != nil {
			return fmt.Errorf("deleting stale cloudflare record: %w", err)
		}
	}

	if !found {
		_, err = p.provider.SetRecords(ctx, p.zone, []libdns.Record{libdns.TXT{
			Name: recordName,
			Text: value,
			TTL:  defaultTXTTTLSeconds * time.Second,
		}})
		if err != nil {
			return fmt.Errorf("setting cloudflare TXT record: %w", err)
		}

		log.Info().
			Str("fqdn", strings.TrimSuffix(absFQDN, ".")).
			Msg("created ACME challenge TXT record")
	}

	return p.waitForPropagation(ctx, absFQDN, value)
}

func (p *cloudflareProvider) waitForPropagation(ctx context.Context, fqdn, value string) error {
	log.Info().
		Str("fqdn", strings.TrimSuffix(fqdn, ".")).
		Dur("timeout", p.propagationTimeout).
		Msg("waiting for DNS propagation of ACME challenge TXT record")

	deadline := time.Now().Add(p.propagationTimeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		for _, server := range p.propagationResolvers {
			found, err := p.lookupTXT(ctx, fqdn, server)
			if err != nil {
				continue
			}

			if slices.Contains(found, value) {
				log.Info().
					Str("fqdn", strings.TrimSuffix(fqdn, ".")).
					Str("resolver", server).
					Msg("DNS propagation confirmed")

				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(p.propagationPollInterval):
		}
	}

	return fmt.Errorf(
		"%w: TXT record %q not visible via public DNS after %s",
		ErrDNSPropagationTimeout,
		strings.TrimSuffix(fqdn, "."),
		p.propagationTimeout,
	)
}

func isTXTRecordForName(rec libdns.Record, zone, fqdn string) bool {
	rr := rec.RR()
	if rr.Type != "TXT" {
		return false
	}

	return ensureTrailingDot(strings.ToLower(libdns.AbsoluteName(rr.Name, zone))) == fqdn
}

func relativeRecordName(fqdn, zone string) (string, error) {
	fqdn = ensureTrailingDot(strings.ToLower(strings.TrimSpace(fqdn)))
	zone = ensureTrailingDot(normalizeZone(zone))

	if fqdn == zone {
		return "@", nil
	}

	suffix := "." + zone
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("%w: %q is not within zone %q", ErrInvalidDNSChallengeName, fqdn, zone)
	}

	return strings.TrimSuffix(strings.TrimSuffix(fqdn, suffix), "."), nil
}

func normalizeZone(zone string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(zone)), ".")
}

func ensureTrailingDot(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}

	return name + "."
}

func lookupTXTAt(ctx context.Context, fqdn, nameserver string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dnsLookupTimeout}

			return d.DialContext(ctx, "udp", nameserver)
		},
	}

	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()

	return resolver.LookupTXT(lookupCtx, strings.TrimSuffix(fqdn, "."))
}

package dns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCloudflareClient struct {
	records  []libdns.Record
	deleted  []libdns.Record
	setCalls []libdns.Record
}

func (f *fakeCloudflareClient) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	out := make([]libdns.Record, len(f.records))
	copy(out, f.records)

	return out, nil
}

func (f *fakeCloudflareClient) DeleteRecords(_ context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	f.deleted = append(f.deleted, records...)

	return records, nil
}

func (f *fakeCloudflareClient) SetRecords(_ context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	f.setCalls = append(f.setCalls, records...)

	return records, nil
}

func TestCloudflareProviderUpsertTXTDeletesStaleRecords(t *testing.T) {
	client := &fakeCloudflareClient{
		records: []libdns.Record{
			libdns.TXT{Name: "_acme-challenge.node", Text: "stale"},
			libdns.TXT{Name: "_acme-challenge.node", Text: "wanted"},
			libdns.TXT{Name: "_acme-challenge.other", Text: "keep"},
		},
	}

	provider := &cloudflareProvider{
		provider:                client,
		zone:                    "example.com",
		lookupTXT:               func(context.Context, string, string) ([]string, error) { return []string{"wanted"}, nil },
		propagationResolvers:    []string{"1.1.1.1:53"},
		propagationTimeout:      time.Second,
		propagationPollInterval: time.Millisecond,
	}

	err := provider.UpsertTXT(context.Background(), "_acme-challenge.node.example.com", "wanted")
	require.NoError(t, err)

	require.Len(t, client.deleted, 1)
	assert.Equal(t, "_acme-challenge.node", client.deleted[0].RR().Name)
	assert.Equal(t, "stale", client.deleted[0].RR().Data)
	assert.Empty(t, client.setCalls)
}

func TestCloudflareProviderUpsertTXTCreatesRecordWhenMissing(t *testing.T) {
	client := &fakeCloudflareClient{}

	provider := &cloudflareProvider{
		provider:                client,
		zone:                    "example.com",
		lookupTXT:               func(context.Context, string, string) ([]string, error) { return []string{"wanted"}, nil },
		propagationResolvers:    []string{"1.1.1.1:53"},
		propagationTimeout:      time.Second,
		propagationPollInterval: time.Millisecond,
	}

	err := provider.UpsertTXT(context.Background(), "_acme-challenge.node.example.com.", "wanted")
	require.NoError(t, err)

	require.Len(t, client.setCalls, 1)
	assert.Equal(t, "TXT", client.setCalls[0].RR().Type)
	assert.Equal(t, "_acme-challenge.node", client.setCalls[0].RR().Name)
	assert.Equal(t, "wanted", client.setCalls[0].RR().Data)
	assert.Equal(t, 120*time.Second, client.setCalls[0].RR().TTL)
}

func TestCloudflareProviderWaitForPropagationTimeout(t *testing.T) {
	provider := &cloudflareProvider{
		provider:                &fakeCloudflareClient{},
		zone:                    "example.com",
		lookupTXT:               func(context.Context, string, string) ([]string, error) { return nil, errors.New("not found") },
		propagationResolvers:    []string{"1.1.1.1:53"},
		propagationTimeout:      5 * time.Millisecond,
		propagationPollInterval: time.Millisecond,
	}

	err := provider.waitForPropagation(context.Background(), "_acme-challenge.node.example.com.", "wanted")
	require.ErrorIs(t, err, ErrDNSPropagationTimeout)
}

func TestRelativeRecordName(t *testing.T) {
	name, err := relativeRecordName("_acme-challenge.node.example.com.", "example.com")
	require.NoError(t, err)
	assert.Equal(t, "_acme-challenge.node", name)

	_, err = relativeRecordName("_acme-challenge.node.other.com.", "example.com")
	require.ErrorIs(t, err, ErrInvalidDNSChallengeName)
}

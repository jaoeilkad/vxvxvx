package rdns_test

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghalg"
	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/rdns"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rDNSExchanger is a mock dnsforward.RDNSExchanger implementation for tests.
type rDNSExchanger struct {
	ex         upstream.Upstream
	usePrivate bool
}

// Exchange implements dnsforward.RDNSExchanger interface for *RDNSExchanger.
func (e *rDNSExchanger) Exchange(ip net.IP) (host string, err error) {
	rev, err := netutil.IPToReversedAddr(ip)
	if err != nil {
		return "", fmt.Errorf("reversing ip: %w", err)
	}

	req := &dns.Msg{
		Question: []dns.Question{{
			Name:   dns.Fqdn(rev),
			Qclass: dns.ClassINET,
			Qtype:  dns.TypePTR,
		}},
	}

	resp, err := e.ex.Exchange(req)
	if err != nil {
		return "", err
	}

	if len(resp.Answer) == 0 {
		return "", errors.Error("no ptr data")
	}

	ptr, ok := resp.Answer[0].(*dns.PTR)
	if !ok {
		return "", fmt.Errorf("bad type %T", resp.Answer[0])
	}

	return ptr.Ptr, nil
}

// Exchange implements dnsforward.RDNSExchanger interface for *RDNSExchanger.
func (e *rDNSExchanger) ResolvesPrivatePTR() (ok bool) {
	return e.usePrivate
}

func TestDefault_Process(t *testing.T) {
	const (
		domain1 = "ip1234.domain"
		domain2 = "ip4321.domain"
	)

	ip1 := netip.MustParseAddr("1.2.3.4")
	revAddr1, err := netutil.IPToReversedAddr(ip1.AsSlice())
	require.NoError(t, err)

	ip2 := netip.MustParseAddr("4.3.2.1")
	revAddr2, err := netutil.IPToReversedAddr(ip2.AsSlice())
	require.NoError(t, err)

	testCases := []struct {
		name string
		addr netip.Addr
		want string
	}{{
		name: "first",
		addr: ip1,
		want: domain1,
	}, {
		name: "second",
		addr: ip2,
		want: domain2,
	}, {
		name: "empty",
		addr: netip.MustParseAddr("0.0.0.0"),
		want: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hit := 0

			upstream := &aghtest.UpstreamMock{
				OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
					hit++

					return aghalg.Coalesce(
						aghtest.MatchedResponse(req, dns.TypePTR, revAddr1, domain1),
						aghtest.MatchedResponse(req, dns.TypePTR, revAddr2, domain2),
						new(dns.Msg).SetRcode(req, dns.RcodeNameError),
					), nil
				},
			}

			r := rdns.New(&rdns.Config{
				Exchanger: &rDNSExchanger{
					ex: upstream,
				},
				CacheSize: 100,
				CacheTTL:  time.Hour,
			})

			got, changed := r.Process(tc.addr)
			require.True(t, changed)

			assert.Equal(t, tc.want, got)
			assert.Equal(t, 1, hit)

			// From cache.
			got, changed = r.Process(tc.addr)
			require.False(t, changed)

			assert.Equal(t, tc.want, got)
			assert.Equal(t, 1, hit)
		})
	}
}

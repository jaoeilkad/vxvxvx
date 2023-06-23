package rdns_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/rdns"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRDNSExchanger is a mock [rdns.Exchanger] implementation for tests.
type fakeRDNSExchanger struct {
	OnExchange    func(ip netip.Addr) (host string, err error)
	OnIsPrivateIP func(ip netip.Addr) (ok bool)
}

// type check
var _ rdns.Exchanger = (*fakeRDNSExchanger)(nil)

// Exchange implements [rdns.Exchanger] interface for *fakeRDNSExchanger.
func (e *fakeRDNSExchanger) Exchange(ip netip.Addr) (host string, err error) {
	return e.OnExchange(ip)
}

// IsPrivateIP implements [rdns.Exchanger] interface for *fakeRDNSExchanger.
func (e *fakeRDNSExchanger) IsPrivateIP(ip netip.Addr) (ok bool) {
	return e.OnIsPrivateIP(ip)
}

func TestDefault_Process(t *testing.T) {
	ip1 := netip.MustParseAddr("1.2.3.4")
	revAddr1, err := netutil.IPToReversedAddr(ip1.AsSlice())
	require.NoError(t, err)

	ip2 := netip.MustParseAddr("4.3.2.1")
	revAddr2, err := netutil.IPToReversedAddr(ip2.AsSlice())
	require.NoError(t, err)

	testCases := []struct {
		name    string
		addr    netip.Addr
		private bool
		want    string
	}{{
		name:    "first",
		addr:    ip1,
		private: false,
		want:    revAddr1,
	}, {
		name:    "second",
		addr:    ip2,
		private: false,
		want:    revAddr2,
	}, {
		name:    "empty",
		addr:    netip.MustParseAddr("0.0.0.0"),
		private: false,
		want:    "",
	}, {
		name:    "private",
		addr:    netip.MustParseAddr("0.0.0.0"),
		private: true,
		want:    "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hit := 0

			r := rdns.New(&rdns.Config{
				Exchanger: &fakeRDNSExchanger{
					OnExchange: func(ip netip.Addr) (host string, err error) {
						hit++

						switch ip {
						case ip1:
							return revAddr1, nil
						case ip2:
							return revAddr2, nil
						default:
							return "", nil
						}
					},
					OnIsPrivateIP: func(ip netip.Addr) (ok bool) {
						return tc.private
					},
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

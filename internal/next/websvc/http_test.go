package websvc_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/next/websvc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_HandlePatchSettingsHTTP(t *testing.T) {
	wantWeb := &websvc.HTTPAPIHTTPSettings{
		Addresses:       []netip.AddrPort{netip.MustParseAddrPort("127.0.1.1:80")},
		SecureAddresses: []netip.AddrPort{netip.MustParseAddrPort("127.0.1.1:443")},
		Timeout:         websvc.JSONDuration(10 * time.Second),
		ForceHTTPS:      false,
	}

	confMgr := newConfigManager()
	confMgr.onWeb = func() (c *websvc.Service) {
		return websvc.New(&websvc.Config{
			TLS: &tls.Config{
				Certificates: []tls.Certificate{{}},
			},
			Addresses:       []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:80")},
			SecureAddresses: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:443")},
			Timeout:         5 * time.Second,
			ForceHTTPS:      true,
		})
	}
	confMgr.onUpdateWeb = func(ctx context.Context, c *websvc.Config) (err error) {
		return nil
	}

	_, addr := newTestServer(t, confMgr)
	u := &url.URL{
		Scheme: "http",
		Host:   addr.String(),
		Path:   websvc.PathV1SettingsHTTP,
	}

	req := jobj{
		"addresses":        wantWeb.Addresses,
		"secure_addresses": wantWeb.SecureAddresses,
		"timeout":          wantWeb.Timeout,
		"ForceHTTPS":       wantWeb.ForceHTTPS,
	}

	respBody := httpPatch(t, u, req, http.StatusOK)
	resp := &websvc.HTTPAPIHTTPSettings{}
	err := json.Unmarshal(respBody, resp)
	require.NoError(t, err)

	assert.Equal(t, wantWeb, resp)
}
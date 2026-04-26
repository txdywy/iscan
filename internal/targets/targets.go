package targets

import (
	"encoding/json"
	"os"
	"strings"

	"iscan/internal/model"
)

var customResolvers []model.Resolver

// AddCustomResolvers appends user-specified resolvers to the custom resolver list.
// These are included in BuiltinResolvers() results.
func AddCustomResolvers(resolvers []model.Resolver) {
	customResolvers = append(customResolvers, resolvers...)
}

// DetectTransport detects the DNS transport protocol from a server address.
// Returns "https" for https:// prefix, "tcp-tls" for tls:// prefix, or "udp" otherwise.
func DetectTransport(server string) string {
	if strings.HasPrefix(server, "https://") {
		return "https"
	}
	if strings.HasPrefix(server, "tls://") {
		return "tcp-tls"
	}
	return "udp"
}

// TargetSource provides a list of targets to scan.
type TargetSource interface {
	Load() ([]model.Target, error)
}

// BuiltinSource returns the built-in default target set.
type BuiltinSource struct{}

func (BuiltinSource) Load() ([]model.Target, error) {
	return BuiltinTargets(), nil
}

// FileSource reads targets from a JSON file at the given path.
type FileSource struct {
	Path string
}

func (fs FileSource) Load() ([]model.Target, error) {
	data, err := os.ReadFile(fs.Path)
	if err != nil {
		return nil, err
	}
	var targets []model.Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, err
	}
	for _, t := range targets {
		if err := t.Validate(); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

// SelectSource returns the appropriate TargetSource based on the targetSet string.
// An empty string or "builtin" returns BuiltinSource. Anything else is treated
// as a file path for FileSource.
func SelectSource(targetSet string) TargetSource {
	if targetSet == "" || targetSet == "builtin" {
		return BuiltinSource{}
	}
	return FileSource{Path: targetSet}
}

func BuiltinTargets() []model.Target {
	return []model.Target{
		{
			Name:     "example-control",
			Domain:   "example.com",
			Scheme:   "https",
			Ports:    []int{443},
			Control:  true,
			HTTPPath: "/",
			QUICPort: 443,
		},
		{
			Name:     "cloudflare-control",
			Domain:   "cloudflare.com",
			Scheme:   "https",
			Ports:    []int{443},
			Control:  true,
			HTTPPath: "/",
			QUICPort: 443,
		},
		{
			Name:       "google-diagnostic",
			Domain:     "www.google.com",
			Scheme:     "https",
			Ports:      []int{443},
			HTTPPath:   "/",
			CompareSNI: []string{"example.com"},
			QUICPort:   443,
		},
		{
			Name:     "no-quic-control",
			Domain:   "example.net",
			Scheme:   "https",
			Ports:    []int{443},
			Control:  true,
			HTTPPath: "/",
			QUICPort: 0, // explicitly disabled QUIC for control comparison
		},
	}
}

func BuiltinResolvers() []model.Resolver {
	base := []model.Resolver{
		{Name: "system", System: true, Transport: "system"},
		{Name: "cloudflare", Server: "1.1.1.1:53", Transport: "udp"},
		{Name: "google", Server: "8.8.8.8:53", Transport: "udp"},
		{Name: "quad9", Server: "9.9.9.9:53", Transport: "udp"},
		{Name: "cloudflare-ipv6", Server: "[2606:4700:4700::1111]:53", Transport: "udp"},
		{Name: "google-ipv6", Server: "[2001:4860:4860::8888]:53", Transport: "udp"},
		{Name: "quad9-ipv6", Server: "[2620:fe::fe]:53", Transport: "udp"},
		{Name: "cloudflare-doh", Server: "1.1.1.1", Transport: "https"},
		{Name: "google-doh", Server: "dns.google", Transport: "https"},
		{Name: "cloudflare-dot", Server: "1.1.1.1", Transport: "tcp-tls"},
		{Name: "google-dot", Server: "dns.google", Transport: "tcp-tls"},
	}
	return append(base, customResolvers...)
}

package model

import "time"

type Layer string

const (
	LayerDNS   Layer = "dns"
	LayerTCP   Layer = "tcp"
	LayerTLS   Layer = "tls"
	LayerHTTP  Layer = "http"
	LayerQUIC  Layer = "quic"
	LayerTrace Layer = "trace"
	LayerPing  Layer = "ping"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type FindingType string

const (
	FindingDNSInconsistent     FindingType = "dns_inconsistent"
	FindingDNSSuspiciousAnswer FindingType = "dns_suspicious_answer"
	FindingTCPConnectFailure   FindingType = "tcp_connect_failure"
	FindingTLSHandshakeFailure FindingType = "tls_handshake_failure"
	FindingSNICorrelated       FindingType = "sni_correlated_failure"
	FindingHTTPFailure         FindingType = "http_application_failure"
	FindingQUICFailure         FindingType = "quic_handshake_failure"
	FindingPathQuality         FindingType = "path_quality_degraded"
	FindingLocalNetworkIssue   FindingType = "local_network_issue"
	FindingDNSNXDOMAIN        FindingType = "dns_nxdomain"
	FindingDNSSERVFAIL        FindingType = "dns_servfail"
	FindingDNSREFUSED         FindingType = "dns_refused"
	FindingDNSOtherRCODE      FindingType = "dns_other_rcode"
	FindingDNSTransparentProxy FindingType = "dns_transparent_proxy"
)

type Target struct {
	Name       string   `json:"name"`
	Domain     string   `json:"domain"`
	Scheme     string   `json:"scheme"`
	Ports      []int    `json:"ports"`
	Control    bool     `json:"control"`
	HTTPPath   string   `json:"http_path"`
	CompareSNI []string `json:"compare_sni,omitempty"`
	QUICPort   int      `json:"quic_port,omitempty"`
	AddressFamily  string   `json:"address_family,omitempty"`
}

func (t Target) Validate() error {
	if t.Name == "" {
		return ErrTargetNameRequired
	}
	if t.Domain == "" {
		return ErrTargetDomainRequired
	}
	if t.Scheme != "http" && t.Scheme != "https" {
		return ErrTargetSchemeInvalid
	}
	if len(t.Ports) == 0 {
		return ErrTargetPortsRequired
	}
	return nil
}

type Resolver struct {
	Name      string `json:"name"`
	Server    string `json:"server"`
	System    bool   `json:"system"`
	Transport string `json:"transport,omitempty"`
}

type ScanOptions struct {
	Timeout     time.Duration `json:"timeout"`
	Retries     int           `json:"retries"`
	Trace       bool          `json:"trace"`
	QUIC        bool          `json:"quic"`
	Parallelism int           `json:"parallelism"`
	ICMPPing    bool          `json:"icmp_ping,omitempty"`
	TargetSet      string        `json:"target_set,omitempty"`
	DNSRateLimit   int           `json:"dns_rate_limit,omitempty"`
	CustomResolvers []Resolver   `json:"custom_resolvers,omitempty"`
}

type ScanReport struct {
	StartedAt time.Time      `json:"started_at"`
	Duration  time.Duration  `json:"duration"`
	Options   ScanOptions    `json:"options"`
	Targets   []TargetResult `json:"targets"`
	Findings  []Finding      `json:"findings"`
	Warnings  []string       `json:"warnings,omitempty"`
}

type ProbeResult struct {
	Layer Layer `json:"layer"`
	Data  any   `json:"data"`
}

type TargetResult struct {
	Target   Target        `json:"target"`
	Error    string        `json:"error,omitempty"`
	Results  []ProbeResult `json:"results"`
	Findings []Finding     `json:"findings"`
}

type DNSObservation struct {
	Resolver string        `json:"resolver"`
	Query    string        `json:"query"`
	Type     string        `json:"type"`
	Answers  []string      `json:"answers"`
	CNAMEs   []string      `json:"cnames,omitempty"`
	RCode    string        `json:"rcode"`
	Latency  time.Duration `json:"latency"`
	Success  bool          `json:"success"`
	Error    string        `json:"error,omitempty"`
}

type TCPObservation struct {
	Address   string        `json:"address"`
	Host      string        `json:"host"`
	Port      int           `json:"port"`
	Latency   time.Duration `json:"latency"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
	ErrorKind string        `json:"error_kind,omitempty"`
}

type TLSObservation struct {
	Address    string        `json:"address"`
	SNI        string        `json:"sni"`
	Version    string        `json:"version,omitempty"`
	ALPN       string        `json:"alpn,omitempty"`
	CertSHA256 string        `json:"cert_sha256,omitempty"`
	Latency    time.Duration `json:"latency"`
	Success    bool          `json:"success"`
	Error      string        `json:"error,omitempty"`
}

type HTTPObservation struct {
	URL                 string        `json:"url"`
	DialAddress         string        `json:"dial_address,omitempty"`
	StatusCode          int           `json:"status_code,omitempty"`
	Latency             time.Duration `json:"latency"`
	DNSStartLatency     time.Duration `json:"dns_start_latency,omitempty"`
	ConnectLatency      time.Duration `json:"connect_latency,omitempty"`
	TLSHandshakeLatency time.Duration `json:"tls_handshake_latency,omitempty"`
	FirstByteLatency    time.Duration `json:"first_byte_latency,omitempty"`
	Success             bool          `json:"success"`
	Error               string        `json:"error,omitempty"`
}

type QUICObservation struct {
	Address    string        `json:"address"`
	SNI        string        `json:"sni"`
	Version    string        `json:"version,omitempty"`
	ALPN       string        `json:"alpn,omitempty"`
	CertSHA256 string        `json:"cert_sha256,omitempty"`
	Latency    time.Duration `json:"latency"`
	Success    bool          `json:"success"`
	Error      string        `json:"error,omitempty"`
}

type TraceObservation struct {
	Target  string        `json:"target"`
	Hops    []TraceHop    `json:"hops,omitempty"`
	Latency time.Duration `json:"latency"`
	Success bool          `json:"success"`
	Error   string        `json:"error,omitempty"`
}

type TraceHop struct {
	TTL      int           `json:"ttl"`
	Address  string        `json:"address,omitempty"`
	RTT      time.Duration `json:"rtt,omitempty"`
	Mismatch bool          `json:"mismatch"`
	Error    string        `json:"error,omitempty"`
}

type PingObservation struct {
	Target  string        `json:"target"`
	Address string        `json:"address,omitempty"`
	RTT     time.Duration `json:"rtt,omitempty"`
	TTL     int           `json:"ttl,omitempty"`
	Latency time.Duration `json:"latency"`
	Success bool          `json:"success"`
	Error   string        `json:"error,omitempty"`
}

type Finding struct {
	Type       FindingType `json:"type"`
	Layer      Layer       `json:"layer"`
	Confidence Confidence  `json:"confidence"`
	Evidence   []string    `json:"evidence"`
	ObservedAt time.Time   `json:"observed_at"`
}

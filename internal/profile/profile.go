package profile

import (
	"sort"
	"time"

	"iscan/internal/model"
)

type QualityTier string

const (
	QualityExcellent QualityTier = "excellent"
	QualityGood      QualityTier = "good"
	QualityFair      QualityTier = "fair"
	QualityPoor      QualityTier = "poor"
)

type Profile struct {
	ISP              ISPInfo    `json:"isp"`
	DNSHealth        DNSHealth  `json:"dns_health"`
	TCPHealth        TCPHealth  `json:"tcp_health"`
	TLSHealth        TLSHealth  `json:"tls_health"`
	QUICHealth       QUICHealth `json:"quic_health"`
	PathHealth       PathHealth `json:"path_health"`
	OverallStability float64    `json:"overall_stability"`
}

type ISPInfo struct {
	Name     string `json:"name"`
	FirstHop string `json:"first_hop"`
}

type DNSHealth struct {
	MultiResolver     bool          `json:"multi_resolver"`
	Agreement         bool          `json:"agreement"`
	SuspiciousAnswers int           `json:"suspicious_answers"`
	AvgLatency        time.Duration `json:"avg_latency"`
	Tier              QualityTier   `json:"tier"`
}

type TCPHealth struct {
	SuccessRate float64        `json:"success_rate"`
	AvgLatency  time.Duration  `json:"avg_latency"`
	ErrorModes  map[string]int `json:"error_modes"`
	Tier        QualityTier    `json:"tier"`
}

type TLSHealth struct {
	SuccessRate     float64     `json:"success_rate"`
	HasSNIFiltering bool        `json:"has_sni_filtering"`
	Versions        []string    `json:"versions"`
	Tier            QualityTier `json:"tier"`
}

type PathHealth struct {
	HopCount       int           `json:"hop_count"`
	AvgRTT         time.Duration `json:"avg_rtt"`
	Jitter         time.Duration `json:"jitter"`
	Reachable      bool          `json:"reachable"`
	TraceAvailable bool          `json:"trace_available"`
	Tier           QualityTier   `json:"tier"`
}

type QUICHealth struct {
	SuccessRate float64     `json:"success_rate"`
	Tier        QualityTier `json:"tier"`
}

func BuildProfile(report model.ScanReport) Profile {
	p := Profile{
		ISP:        extractISP(report),
		DNSHealth:  profileDNS(report),
		TCPHealth:  profileTCP(report),
		TLSHealth:  profileTLS(report),
		QUICHealth: profileQUIC(report),
		PathHealth: profilePath(report),
	}
	p.OverallStability = ((StabilityScore(p.DNSHealth.Tier) +
		StabilityScore(p.TCPHealth.Tier) +
		StabilityScore(p.TLSHealth.Tier) +
		StabilityScore(p.QUICHealth.Tier) +
		StabilityScore(p.PathHealth.Tier)) / 5.0)
	return p
}

// StabilityScore maps a quality tier to a numeric stability score.
func StabilityScore(tier QualityTier) float64 {
	switch tier {
	case QualityExcellent:
		return 1.0
	case QualityGood:
		return 0.75
	case QualityFair:
		return 0.45
	case QualityPoor:
		return 0.15
	default:
		return 0
	}
}

func qualityTier(score float64) QualityTier {
	switch {
	case score >= 0.85:
		return QualityExcellent
	case score >= 0.60:
		return QualityGood
	case score >= 0.30:
		return QualityFair
	default:
		return QualityPoor
	}
}

func extractISP(report model.ScanReport) ISPInfo {
	info := ISPInfo{}
	for _, target := range report.Targets {
		if target.Trace == nil || len(target.Trace.Hops) == 0 {
			continue
		}
		if info.FirstHop == "" {
			hop := target.Trace.Hops[0]
			info.FirstHop = hop.Address
		}
	}
	return info
}

func profileDNS(report model.ScanReport) DNSHealth {
	h := DNSHealth{}
	resolvers := map[string]struct{}{}
	var totalLatency time.Duration
	var latencyCount int

	for _, target := range report.Targets {
		for _, obs := range target.DNS {
			resolvers[obs.Resolver] = struct{}{}
			if obs.Latency > 0 {
				totalLatency += obs.Latency
				latencyCount++
			}
		}
	}
	h.MultiResolver = len(resolvers) > 1
	h.Agreement = !hasFinding(report, model.FindingDNSInconsistent)
	h.SuspiciousAnswers = countFindings(report, model.FindingDNSSuspiciousAnswer)
	if latencyCount > 0 {
		h.AvgLatency = totalLatency / time.Duration(latencyCount)
	}
	score := 1.0
	if !h.Agreement {
		score -= 0.3
	}
	if h.SuspiciousAnswers > 0 {
		score -= 0.4
	}
	if h.AvgLatency > 200*time.Millisecond {
		score -= 0.15
	}
	if score < 0 {
		score = 0
	}
	h.Tier = qualityTier(score)
	return h
}

func profileTCP(report model.ScanReport) TCPHealth {
	h := TCPHealth{ErrorModes: map[string]int{}}
	var successes, total int
	var totalLatency time.Duration
	var latencyCount int

	for _, target := range report.Targets {
		for _, obs := range target.TCP {
			total++
			if obs.Latency > 0 {
				totalLatency += obs.Latency
				latencyCount++
			}
			if obs.Success {
				successes++
			} else if obs.ErrorKind != "" {
				h.ErrorModes[obs.ErrorKind]++
			}
		}
	}
	if total > 0 {
		h.SuccessRate = float64(successes) / float64(total)
	}
	if latencyCount > 0 {
		h.AvgLatency = totalLatency / time.Duration(latencyCount)
	}
	h.Tier = qualityTier(h.SuccessRate)
	return h
}

func profileTLS(report model.ScanReport) TLSHealth {
	h := TLSHealth{HasSNIFiltering: hasFinding(report, model.FindingSNICorrelated)}
	versions := map[string]struct{}{}
	var successes, total int
	for _, target := range report.Targets {
		for _, obs := range target.TLS {
			total++
			if obs.Success {
				successes++
				if obs.Version != "" {
					versions[obs.Version] = struct{}{}
				}
			}
		}
	}
	if total > 0 {
		h.SuccessRate = float64(successes) / float64(total)
	}
	for v := range versions {
		h.Versions = append(h.Versions, v)
	}
	sort.Strings(h.Versions)
	score := h.SuccessRate
	if h.HasSNIFiltering {
		score *= 0.6
	}
	h.Tier = qualityTier(score)
	return h
}

func profilePath(report model.ScanReport) PathHealth {
	h := PathHealth{}
	var rtts []float64
	for _, target := range report.Targets {
		if target.Trace == nil {
			continue
		}
		h.TraceAvailable = true
		if model.IsLocalPermissionError(target.Trace.Error) {
			h.TraceAvailable = false
			continue
		}
		if target.Trace.Success {
			h.Reachable = true
		}
		for _, hop := range target.Trace.Hops {
			if hop.RTT > 0 {
				rtts = append(rtts, float64(hop.RTT))
			}
		}
		hops := len(target.Trace.Hops)
		if hops > h.HopCount {
			h.HopCount = hops
		}
	}
	if len(rtts) > 0 {
		var sum float64
		for _, r := range rtts {
			sum += r
		}
		mean := sum / float64(len(rtts))
		h.AvgRTT = time.Duration(mean)
		// Use median absolute deviation (MAD) for jitter instead of
		// standard deviation to be robust against outlier hops.
		devs := make([]float64, len(rtts))
		for i, r := range rtts {
			d := r - mean
			if d < 0 {
				d = -d
			}
			devs[i] = d
		}
		sort.Float64s(devs)
		medianDev := devs[len(devs)/2]
		h.Jitter = time.Duration(medianDev)
	}
	if !h.TraceAvailable {
		h.Tier = QualityFair
		return h
	}
	score := 1.0
	if !h.Reachable {
		score -= 0.4
	}
	if h.Jitter > 100*time.Millisecond {
		score -= 0.3
	}
	if h.HopCount > 25 {
		score -= 0.2
	}
	if score < 0 {
		score = 0
	}
	h.Tier = qualityTier(score)
	return h
}

func profileQUIC(report model.ScanReport) QUICHealth {
	h := QUICHealth{}
	var successes, total int
	for _, target := range report.Targets {
		for _, obs := range target.QUIC {
			total++
			if obs.Success {
				successes++
			}
		}
	}
	if total == 0 {
		// QUIC not probed — treat as neutral (no information = no problem).
		h.Tier = QualityExcellent
		return h
	}
	h.SuccessRate = float64(successes) / float64(total)
	h.Tier = qualityTier(h.SuccessRate)
	return h
}

func hasFinding(report model.ScanReport, typ model.FindingType) bool {
	for _, f := range report.Findings {
		if f.Type == typ {
			return true
		}
	}
	return false
}

func countFindings(report model.ScanReport, typ model.FindingType) int {
	n := 0
	for _, f := range report.Findings {
		if f.Type == typ {
			n++
		}
	}
	return n
}

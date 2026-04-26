package recommend

import (
	"fmt"
	"math"
	"sort"
	"time"

	"iscan/internal/model"
	"iscan/internal/profile"
)

// Weight constants for each recommendation category.
const (
	weightLongTCP     = 0.30
	weightLongTLS     = 0.25
	weightLongPath    = 0.25
	weightLongSNIFree = 0.20

	weightUDPDNS     = 0.25
	weightUDPPath    = 0.35
	weightUDPJitter  = 0.25
	weightUDPSNIFree = 0.15

	weightConservativeTCP       = 0.30
	weightConservativeTLSSNIPen = 0.30
	weightConservativePath      = 0.20
	weightConservativeStability = 0.20

	weightRedundantConnectivity = 0.45
	weightRedundantInstability  = 0.30
	weightRedundantPath         = 0.25
)

type Recommendation struct {
	Rankings []Ranking       `json:"rankings"`
	Profile  profile.Profile `json:"profile"`
}

type Ranking struct {
	Category   string   `json:"category"`
	Score      float64  `json:"score"`
	Reasons    []string `json:"reasons"`
	IsFallback bool     `json:"is_fallback"`
}

func Rank(report model.ScanReport, prof profile.Profile) Recommendation {
	r := Recommendation{Profile: prof}

	tcp := prof.TCPHealth
	tls := prof.TLSHealth
	dns := prof.DNSHealth
	path := prof.PathHealth

	long := Ranking{
		Category: "长连接型 (long-lived TCP)",
		Score: weighted(
			[][2]float64{
				{weightLongTCP, tcp.SuccessRate},
				{weightLongTLS, profile.StabilityScore(tls.Tier)},
				{weightLongPath, profile.StabilityScore(path.Tier)},
				{weightLongSNIFree, invertBool(tls.HasSNIFiltering)},
			}),
		Reasons: reasonsLong(tcp, tls, path),
	}

	udp := Ranking{
		Category: "UDP友好型 (UDP-friendly)",
		Score: weighted(
			[][2]float64{
				{weightUDPDNS, dnsGood(dns)},
				{weightUDPPath, profile.StabilityScore(path.Tier)},
				{weightUDPJitter, lowJitterScore(path.Jitter)},
				{weightUDPSNIFree, invertBool(tls.HasSNIFiltering)},
			}),
		Reasons: reasonsUDP(dns, path),
	}

	conservative := Ranking{
		Category: "保守TCP/TLS型 (conservative TCP/TLS)",
		Score: weighted(
			[][2]float64{
				{weightConservativeTCP, tcp.SuccessRate},
				{weightConservativeTLSSNIPen, profile.StabilityScore(tls.Tier) * (1 - sniPenalty(tls))},
				{weightConservativePath, profile.StabilityScore(path.Tier)},
				{weightConservativeStability, prof.OverallStability},
			}),
		Reasons: reasonsConservative(tcp, tls, prof),
	}

	redundant := Ranking{
		IsFallback: true,
		Category:   "高重试鲁棒型 (high-redundancy retry)",
		Score: weighted(
			[][2]float64{
				{weightRedundantConnectivity, anyConnectivity(tcp, tls)},
				{weightRedundantInstability, 1.0 - prof.OverallStability},
				{weightRedundantPath, profile.StabilityScore(path.Tier)},
			}),
		Reasons: reasonsRedundant(tcp, tls, path),
	}

	// Primary rankings sorted by descending score.
	primary := []Ranking{long, udp, conservative}
	sort.Slice(primary, func(i, j int) bool {
		return primary[i].Score > primary[j].Score
	})
	// Redundant is always appended as a fallback strategy regardless of score.
	r.Rankings = append(primary, redundant)
	return r
}

func weighted(pairs [][2]float64) float64 {
	var sum float64
	for _, p := range pairs {
		sum += p[0] * p[1]
	}
	return math.Round(sum*100) / 100
}

func invertBool(b bool) float64 {
	if b {
		return 0
	}
	return 1.0
}

func sniPenalty(tls profile.TLSHealth) float64 {
	if tls.HasSNIFiltering {
		return 0.3
	}
	return 0
}

func dnsGood(dns profile.DNSHealth) float64 {
	score := 1.0
	if !dns.Agreement {
		score -= 0.3
	}
	if dns.SuspiciousAnswers > 0 {
		score -= 0.5
	}
	if dns.AvgLatency > 500*time.Millisecond {
		score -= 0.3
	}
	if score < 0 {
		score = 0
	}
	return score
}

func lowJitterScore(jitter time.Duration) float64 {
	switch {
	case jitter < 20*time.Millisecond:
		return 1.0
	case jitter < 50*time.Millisecond:
		return 0.8
	case jitter < 100*time.Millisecond:
		return 0.5
	case jitter < 200*time.Millisecond:
		return 0.3
	default:
		return 0.1
	}
}

func anyConnectivity(tcp profile.TCPHealth, tls profile.TLSHealth) float64 {
	if tcp.SuccessRate > 0 || tls.SuccessRate > 0 {
		return 1.0
	}
	return 0.15
}

func reasonsLong(tcp profile.TCPHealth, tls profile.TLSHealth, path profile.PathHealth) []string {
	var reasons []string
	if tcp.SuccessRate > 0.8 {
		reasons = append(reasons, fmt.Sprintf("TCP 成功率 %.0f%% 适合长连接", tcp.SuccessRate*100))
	}
	if !tls.HasSNIFiltering {
		reasons = append(reasons, "未检测到 SNI 过滤信号")
	}
	if path.Jitter < 50*time.Millisecond && path.Jitter > 0 {
		reasons = append(reasons, fmt.Sprintf("链路抖动 %.0fms 较低", float64(path.Jitter)/float64(time.Millisecond)))
	}
	if tls.SuccessRate < 0.5 {
		reasons = append(reasons, "⚠ TLS 成功率偏低，长连接风险高")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "基础连通性良好")
	}
	return reasons
}

func reasonsUDP(dns profile.DNSHealth, path profile.PathHealth) []string {
	var reasons []string
	if dns.AvgLatency < 200*time.Millisecond && dns.AvgLatency > 0 {
		reasons = append(reasons, fmt.Sprintf("DNS 延迟 %.0fms 表明 UDP 路径通畅", float64(dns.AvgLatency)/float64(time.Millisecond)))
	}
	if path.Jitter < 50*time.Millisecond && path.Jitter > 0 {
		reasons = append(reasons, "链路抖动低，适合 UDP 实时业务")
	}
	if path.TraceAvailable && !path.Reachable {
		reasons = append(reasons, "⚠ 路径不可达，UDP 不建议")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "UDP 基本可达")
	}
	return reasons
}

func reasonsConservative(tcp profile.TCPHealth, tls profile.TLSHealth, prof profile.Profile) []string {
	var reasons []string
	if tcp.SuccessRate > 0.5 {
		reasons = append(reasons, "TCP 基础连通可用")
	}
	if tls.HasSNIFiltering {
		reasons = append(reasons, "检测到 SNI 过滤，建议使用保守 TLS 配置")
	}
	if prof.OverallStability < 0.5 {
		reasons = append(reasons, "网络稳定性偏低，保守策略更安全")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "保守策略可无风险启用")
	}
	return reasons
}

func reasonsRedundant(tcp profile.TCPHealth, tls profile.TLSHealth, path profile.PathHealth) []string {
	var reasons []string
	if tcp.SuccessRate < 0.7 {
		reasons = append(reasons, "TCP 不稳定，建议高重试策略")
	}
	if tls.SuccessRate < 0.5 {
		reasons = append(reasons, "TLS 成功率低，需要冗余重试")
	}
	if path.Jitter > 50*time.Millisecond {
		reasons = append(reasons, fmt.Sprintf("链路抖动大 (%.0fms)，适合冗余策略", float64(path.Jitter)/float64(time.Millisecond)))
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "重试开销小，无风险启用")
	}
	return reasons
}

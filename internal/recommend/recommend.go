package recommend

import (
	"fmt"
	"math"
	"sort"
	"time"

	"iscan/internal/model"
	"iscan/internal/profile"
)

type Recommendation struct {
	Rankings []Ranking       `json:"rankings"`
	Profile  profile.Profile `json:"profile"`
}

type Ranking struct {
	Category string   `json:"category"`
	Score    float64  `json:"score"`
	Reasons  []string `json:"reasons"`
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
				{0.30, tcp.SuccessRate},
				{0.25, tierScore(tls.Tier)},
				{0.25, tierScore(path.Tier)},
				{0.20, invertBool(tls.HasSNIFiltering)},
			}),
		Reasons: reasonsLong(tcp, tls, path),
	}

	udp := Ranking{
		Category: "UDP友好型 (UDP-friendly)",
		Score: weighted(
			[][2]float64{
				{0.25, dnsGood(dns)},
				{0.35, tierScore(path.Tier)},
				{0.25, lowJitterScore(path.Jitter)},
				{0.15, invertBool(tls.HasSNIFiltering)},
			}),
		Reasons: reasonsUDP(dns, path),
	}

	conservative := Ranking{
		Category: "保守TCP/TLS型 (conservative TCP/TLS)",
		Score: weighted(
			[][2]float64{
				{0.30, tcp.SuccessRate},
				{0.30, tierScore(tls.Tier) * (1 - sniPenalty(tls))},
				{0.20, tierScore(path.Tier)},
				{0.20, prof.OverallStability},
			}),
		Reasons: reasonsConservative(tcp, tls, prof),
	}

	redundant := Ranking{
		Category: "高重试鲁棒型 (high-redundancy retry)",
		Score: weighted(
			[][2]float64{
				{0.45, anyConnectivity(tcp, tls)},
				{0.30, 1.0 - prof.OverallStability},
				{0.25, tierScore(path.Tier)},
			}),
		Reasons: reasonsRedundant(tcp, tls, path),
	}

	r.Rankings = []Ranking{long, udp, conservative, redundant}
	sort.Slice(r.Rankings, func(i, j int) bool {
		return r.Rankings[i].Score > r.Rankings[j].Score
	})
	return r
}

func weighted(pairs [][2]float64) float64 {
	var sum float64
	for _, p := range pairs {
		sum += p[0] * p[1]
	}
	return math.Round(sum*100) / 100
}

func tierScore(t profile.QualityTier) float64 {
	switch t {
	case profile.QualityExcellent:
		return 1.0
	case profile.QualityGood:
		return 0.75
	case profile.QualityFair:
		return 0.45
	case profile.QualityPoor:
		return 0.15
	default:
		return 0
	}
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
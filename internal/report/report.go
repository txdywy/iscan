package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"iscan/internal/model"
	"iscan/internal/profile"
	"iscan/internal/recommend"
)

func JSON(scan model.ScanReport) ([]byte, error) {
	return json.MarshalIndent(scan, "", "  ")
}

func JSONExtended(scan model.ScanReport, prof *profile.Profile, rec *recommend.Recommendation) ([]byte, error) {
	out := struct {
		Scan           model.ScanReport             `json:"scan"`
		Profile        *profile.Profile             `json:"profile,omitempty"`
		Recommendation *recommend.Recommendation     `json:"recommendation,omitempty"`
	}{Scan: scan, Profile: prof, Recommendation: rec}
	return json.MarshalIndent(out, "", "  ")
}

func Summary(scan model.ScanReport) string {
	var builder strings.Builder
	builder.WriteString("TARGET\tDNS\tTCP\tTLS\tQUIC\tHTTP\tTRACE\tFINDINGS\n")
	for _, target := range scan.Targets {
		fmt.Fprintf(
			&builder,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			target.Target.Domain,
			statusDNS(target.DNS),
			statusTCP(target.TCP),
			statusTLS(target.TLS),
			statusQUIC(target.QUIC),
			statusHTTP(target.HTTP),
			statusTrace(target.Trace),
			findingTypes(target.Findings),
		)
	}
	for _, warning := range scan.Warnings {
		fmt.Fprintf(&builder, "warning: %s\n", warning)
	}
	return builder.String()
}

func SummaryExtended(scan model.ScanReport, rec *recommend.Recommendation) string {
	builder := SummaryBuilder{}
	builder.WriteString(Summary(scan))
	if rec != nil {
		builder.WriteString("\nPROTOCOL RANKINGS\n")
		for _, r := range rec.Rankings {
			fmt.Fprintf(&builder, "  %s  score:%.2f  %s\n", icon(r.Score), r.Score, r.Category)
			for _, reason := range r.Reasons {
				fmt.Fprintf(&builder, "    %s\n", reason)
			}
		}
	}
	return builder.String()
}

func icon(score float64) string {
	switch {
	case score >= 0.7:
		return "●"
	case score >= 0.4:
		return "◑"
	default:
		return "○"
	}
}

type SummaryBuilder struct {
	strings.Builder
}

func statusDNS(observations []model.DNSObservation) string {
	if len(observations) == 0 {
		return "skip"
	}
	for _, observation := range observations {
		if observation.Success {
			return "ok"
		}
	}
	return "fail"
}

func statusTCP(observations []model.TCPObservation) string {
	return statusBool(len(observations), func(i int) bool { return observations[i].Success })
}

func statusQUIC(observations []model.QUICObservation) string {
	return statusBool(len(observations), func(i int) bool { return observations[i].Success })
}

func statusTLS(observations []model.TLSObservation) string {
	return statusBool(len(observations), func(i int) bool { return observations[i].Success })
}

func statusHTTP(observations []model.HTTPObservation) string {
	return statusBool(len(observations), func(i int) bool { return observations[i].Success })
}

func statusTrace(observation *model.TraceObservation) string {
	if observation == nil {
		return "skip"
	}
	if observation.Success {
		return "ok"
	}
	return "warn"
}

func statusBool(count int, success func(int) bool) string {
	if count == 0 {
		return "skip"
	}
	for i := 0; i < count; i++ {
		if success(i) {
			return "ok"
		}
	}
	return "fail"
}

func findingTypes(findings []model.Finding) string {
	if len(findings) == 0 {
		return "-"
	}
	types := make([]string, 0, len(findings))
	for _, finding := range findings {
		types = append(types, string(finding.Type))
	}
	return strings.Join(types, ",")
}

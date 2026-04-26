package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"iscan/internal/model"
	"iscan/internal/profile"
	"iscan/internal/recommend"
)

func JSON(scan model.ScanReport) ([]byte, error) {
	return json.MarshalIndent(scan, "", "  ")
}

func JSONExtended(scan model.ScanReport, prof *profile.Profile, rec *recommend.Recommendation) ([]byte, error) {
	out := struct {
		Scan           model.ScanReport          `json:"scan"`
		Profile        *profile.Profile          `json:"profile,omitempty"`
		Recommendation *recommend.Recommendation `json:"recommendation,omitempty"`
	}{Scan: scan, Profile: prof, Recommendation: rec}
	return json.MarshalIndent(out, "", "  ")
}

func Summary(scan model.ScanReport) string {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TARGET\tDNS\tTCP\tTLS\tQUIC\tHTTP\tTRACE\tFINDINGS")
	for _, target := range scan.Targets {
		_, _ = fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			target.Target.Domain,
			statusBool(len(target.DNS), func(i int) bool { return target.DNS[i].Success }),
			statusBool(len(target.TCP), func(i int) bool { return target.TCP[i].Success }),
			statusBool(len(target.TLS), func(i int) bool { return target.TLS[i].Success }),
			statusBool(len(target.QUIC), func(i int) bool { return target.QUIC[i].Success }),
			statusBool(len(target.HTTP), func(i int) bool { return target.HTTP[i].Success }),
			statusTrace(target.Trace),
			findingTypes(target.Findings),
		)
	}
	_ = w.Flush()
	for _, warning := range scan.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", warning)
	}
	return b.String()
}

func SummaryExtended(scan model.ScanReport, rec *recommend.Recommendation) string {
	var b strings.Builder
	b.WriteString(Summary(scan))
	if rec != nil {
		b.WriteString("\nPROTOCOL RANKINGS\n")
		for _, r := range rec.Rankings {
			icon := asciiIcon(r.Score)
			if r.IsFallback {
				icon = "[F]"
			}
			fmt.Fprintf(&b, "  %s %s  score:%.2f  %s\n", icon, categoryStatus(r.Score), r.Score, r.Category)
			for _, reason := range r.Reasons {
				fmt.Fprintf(&b, "    %s\n", reason)
			}
		}
	}
	return b.String()
}

func asciiIcon(score float64) string {
	switch {
	case score >= 0.7:
		return "[+]"
	case score >= 0.4:
		return "[~]"
	default:
		return "[ ]"
	}
}

func categoryStatus(score float64) string {
	switch {
	case score >= 0.7:
		return "good"
	case score >= 0.4:
		return "fair"
	default:
		return "poor"
	}
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
	seen := map[string]struct{}{}
	types := make([]string, 0, len(findings))
	for _, finding := range findings {
		t := string(finding.Type)
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		types = append(types, t)
	}
	return strings.Join(types, ",")
}

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
			statusFromResults(target.Results, model.LayerDNS),
			statusFromResults(target.Results, model.LayerTCP),
			statusFromResults(target.Results, model.LayerTLS),
			statusFromResults(target.Results, model.LayerQUIC),
			statusFromResults(target.Results, model.LayerHTTP),
			statusFromResults(target.Results, model.LayerTrace),
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

// statusFromResults determines the status string for a given layer
// by checking all ProbeResults for that layer.
func statusFromResults(results []model.ProbeResult, layer model.Layer) string {
	for _, r := range results {
		if r.Layer != layer {
			continue
		}
		if hasSuccess(r.Data) {
			return "ok"
		}
		return "fail"
	}
	return "skip"
}

// hasSuccess checks whether a probe result's Data payload indicates success.
func hasSuccess(data any) bool {
	switch v := data.(type) {
	case model.DNSObservation:
		return v.Success
	case model.TCPObservation:
		return v.Success
	case model.TLSObservation:
		return v.Success
	case model.HTTPObservation:
		return v.Success
	case model.QUICObservation:
		return v.Success
	case model.TraceObservation:
		return v.Success
	}
	return false
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

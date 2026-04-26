package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"iscan/internal/model"
)

func JSON(scan model.ScanReport) ([]byte, error) {
	return json.MarshalIndent(scan, "", "  ")
}

func Summary(scan model.ScanReport) string {
	var builder strings.Builder
	builder.WriteString("TARGET\tDNS\tTCP\tTLS\tHTTP\tTRACE\tFINDINGS\n")
	for _, target := range scan.Targets {
		fmt.Fprintf(
			&builder,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			target.Target.Domain,
			statusDNS(target.DNS),
			statusTCP(target.TCP),
			statusTLS(target.TLS),
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

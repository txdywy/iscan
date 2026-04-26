package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"iscan/internal/model"
	"iscan/internal/profile"
	"iscan/internal/recommend"
	"iscan/internal/report"
	"iscan/internal/scanner"

	"iscan/internal/probe/icmpping"
)

func main() {
	if err := rootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCommand() *cobra.Command {
	var jsonPath string
	var summary bool
	var timeout time.Duration
	var retries int
	var trace bool
	var quic bool
	var targetSet string
	var analyze bool
	var pingTimeout time.Duration
	var icmpPing bool

	cmd := &cobra.Command{
		Use:   "iscan",
		Short: "Layered network diagnostics",
		Long: `iscan runs DNS, TCP, TLS, HTTP, and optional traceroute probes
against a built-in target set, then emits a terminal summary and a
structured JSON report. Findings are evidence-backed signals rather
than absolute censorship claims.`,
	}
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Run builtin network diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetSet != "builtin" {
				return fmt.Errorf("unsupported target set %q", targetSet)
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			scan := scanner.Run(ctx, model.ScanOptions{
				Timeout:  timeout,
				Retries:  retries,
				Trace:    trace,
				QUIC:     quic,
				ICMPPing: icmpPing,
			})
			var prof *profile.Profile
			var rec *recommend.Recommendation
			if analyze {
				p := profile.BuildProfile(scan)
				prof = &p
				r := recommend.Rank(scan, p)
				rec = &r
			}
			if jsonPath != "" {
				var b []byte
				var err error
				if analyze {
					b, err = report.JSONExtended(scan, prof, rec)
				} else {
					b, err = report.JSON(scan)
				}
				if err != nil {
					return err
				}
				if err := os.WriteFile(jsonPath, append(b, '\n'), 0o644); err != nil {
					return err
				}
			}
			if summary {
				if analyze {
					fmt.Print(report.SummaryExtended(scan, rec))
				} else {
					fmt.Print(report.Summary(scan))
				}
			}
			return nil
		},
	}
	scanCmd.Flags().StringVar(&jsonPath, "json", "", "write JSON report to path")
	scanCmd.Flags().BoolVar(&summary, "summary", true, "print terminal summary")
	scanCmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-probe timeout")
	scanCmd.Flags().IntVar(&retries, "retries", 3, "retry count recorded in report")
	scanCmd.Flags().BoolVar(&trace, "trace", false, "enable privileged ICMP trace probe")
	scanCmd.Flags().BoolVar(&quic, "quic", false, "probe QUIC/UDP handshake on targets with quic_port")
	scanCmd.Flags().StringVar(&targetSet, "target-set", "builtin", "target set to scan")
	scanCmd.Flags().BoolVar(&analyze, "analyze", false, "include network profile and protocol rankings")
	scanCmd.Flags().BoolVar(&icmpPing, "icmp-ping", false, "enable ICMP ping probe")

	pingCmd := &cobra.Command{
		Use:   "ping <target>",
		Short: "ICMP ping a target and print RTT + TTL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			obs := icmpping.Probe(ctx, target, pingTimeout)
			if obs.Success {
				fmt.Printf("PING %s (%s): rtt=%s ttl=%d\n", target, obs.Address, obs.RTT, obs.TTL)
			} else {
				fmt.Printf("PING %s: failed — %s\n", target, obs.Error)
				if model.IsLocalPermissionError(obs.Error) {
					fmt.Fprintln(os.Stderr, "Note: ICMP ping requires root/administrator privileges on this system.")
				}
			}
			if !obs.Success {
				return fmt.Errorf("ping failed: %s", obs.Error)
			}
			return nil
		},
	}
	pingCmd.Flags().DurationVar(&pingTimeout, "timeout", 5*time.Second, "ping timeout")

	cmd.AddCommand(pingCmd)
	cmd.AddCommand(scanCmd)
	return cmd
}

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"iscan/internal/model"
	"iscan/internal/report"
	"iscan/internal/scanner"
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
	var targetSet string

	cmd := &cobra.Command{
		Use:   "iscan",
		Short: "Layered network diagnostics",
	}
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Run builtin network diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetSet != "builtin" {
				return fmt.Errorf("unsupported target set %q", targetSet)
			}
			scan := scanner.Run(context.Background(), model.ScanOptions{
				Timeout: timeout,
				Retries: retries,
				Trace:   trace,
			})
			if jsonPath != "" {
				bytes, err := report.JSON(scan)
				if err != nil {
					return err
				}
				if err := os.WriteFile(jsonPath, append(bytes, '\n'), 0o644); err != nil {
					return err
				}
			}
			if summary {
				fmt.Print(report.Summary(scan))
			}
			return nil
		},
	}
	scanCmd.Flags().StringVar(&jsonPath, "json", "", "write JSON report to path")
	scanCmd.Flags().BoolVar(&summary, "summary", true, "print terminal summary")
	scanCmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-probe timeout")
	scanCmd.Flags().IntVar(&retries, "retries", 3, "retry count recorded in report")
	scanCmd.Flags().BoolVar(&trace, "trace", true, "enable privileged ICMP trace probe")
	scanCmd.Flags().StringVar(&targetSet, "target-set", "builtin", "target set to scan")
	cmd.AddCommand(scanCmd)
	return cmd
}

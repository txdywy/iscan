package middleware

import (
	"context"
	"fmt"
	"iscan/internal/model"
	"iscan/internal/probe"
	"time"
)

func Logging(logFn func(format string, args ...any)) Middleware {
	if logFn == nil {
		logFn = func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		}
	}
	return func(next probe.Probe) probe.Probe {
		return probe.ProbeFunc(func(ctx context.Context, target model.Target) model.ProbeResult {
			start := time.Now()
			result := next.Run(ctx, target)
			logFn("[probe] layer=%s target=%s duration=%v",
				result.Layer, target.Domain, time.Since(start))
			return result
		})
	}
}

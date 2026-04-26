package middleware

import (
	"context"
	"iscan/internal/model"
	"iscan/internal/probe"
	"math"
	"time"
)

func Retry(maxRetries int, baseDelay time.Duration) Middleware {
	return func(next probe.Probe) probe.Probe {
		return probe.ProbeFunc(func(ctx context.Context, target model.Target) model.ProbeResult {
			var lastResult model.ProbeResult
			for attempt := 0; attempt <= maxRetries; attempt++ {
				if attempt > 0 {
					delay := baseDelay * time.Duration(math.Pow(2, float64(attempt-1)))
					timer := time.NewTimer(delay)
					select {
					case <-ctx.Done():
						timer.Stop()
						return model.ProbeResult{
							Layer: lastResult.Layer,
							Data:  ctx.Err().Error(),
						}
					case <-timer.C:
					}
				}
				lastResult = next.Run(ctx, target)
				if errStr, ok := lastResult.Data.(string); ok && errStr != "" {
					continue // retry on error
				}
				return lastResult // success, no retry needed
			}
			return lastResult
		})
	}
}

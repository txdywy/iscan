package middleware

import (
	"context"
	"iscan/internal/model"
	"iscan/internal/probe"
	"time"
)

func Timeout(timeout time.Duration) Middleware {
	return func(next probe.Probe) probe.Probe {
		return probe.ProbeFunc(func(ctx context.Context, target model.Target) model.ProbeResult {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			result := next.Run(ctx, target)
			if ctx.Err() != nil {
				return model.ProbeResult{
					Layer: result.Layer,
					Data:  ctx.Err().Error(),
				}
			}
			return result
		})
	}
}

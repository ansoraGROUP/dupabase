package middleware

import "context"

func setContextValue(ctx context.Context, key contextKey, value string) context.Context {
	return context.WithValue(ctx, key, value)
}

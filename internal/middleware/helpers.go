package middleware

import (
	"context"
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func setContextValue(ctx context.Context, key contextKey, value string) context.Context {
	return context.WithValue(ctx, key, value)
}

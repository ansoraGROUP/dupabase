package httputil

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// WriteJSON encodes v as JSON and writes it to w with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

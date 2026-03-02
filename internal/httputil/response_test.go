package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	t.Run("sets content type and status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteJSON(rec, http.StatusCreated, map[string]string{"id": "123"})

		if rec.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
	})

	t.Run("encodes body as json", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteJSON(rec, http.StatusOK, map[string]string{"status": "ok"})

		var body map[string]string
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		if body["status"] != "ok" {
			t.Errorf("expected status=ok, got %q", body["status"])
		}
	})

	t.Run("handles struct values", func(t *testing.T) {
		type resp struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		}
		rec := httptest.NewRecorder()
		WriteJSON(rec, http.StatusOK, resp{Name: "test", Count: 42})

		var body resp
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode: %v", err)
		}
		if body.Name != "test" || body.Count != 42 {
			t.Errorf("unexpected body: %+v", body)
		}
	})

	t.Run("handles nil value", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteJSON(rec, http.StatusOK, nil)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("handles error status codes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteJSON(rec, http.StatusInternalServerError, map[string]string{"error": "boom"})

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rec.Code)
		}
	})
}

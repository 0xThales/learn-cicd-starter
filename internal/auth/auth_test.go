package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("returns error when no auth header included", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
		}
	})

	t.Run("returns error when auth header is malformed", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "malformed")
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("expected error for malformed header, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("expected error message 'malformed authorization header', got %v", err)
		}
	})

	t.Run("returns error when auth header has wrong prefix", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer some-token")
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("expected error for wrong prefix, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("expected error message 'malformed authorization header', got %v", err)
		}
	})

	t.Run("returns API key when auth header is valid", func(t *testing.T) {
		expectedKey := "test-api-key"
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey "+expectedKey)
		
		key, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if key != expectedKey {
			t.Errorf("expected API key %q, got %q", expectedKey, key)
		}
	})
}

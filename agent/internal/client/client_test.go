package client

import "testing"

func TestValidateServerURL(t *testing.T) {
	ok := []string{"https://sec.example.com", "https://sec.example.com/", "http://localhost:3000"}
	for _, u := range ok {
		if _, err := ValidateServerURL(u); err != nil {
			t.Errorf("%s should be valid: %v", u, err)
		}
	}
	bad := []string{"http://sec.example.com", "ftp://x", "", "sec.example.com"}
	for _, u := range bad {
		if _, err := ValidateServerURL(u); err == nil {
			t.Errorf("%s should be rejected", u)
		}
	}
}

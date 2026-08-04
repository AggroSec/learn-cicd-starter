package auth

import (
	"reflect"
	"testing"
)

func TestSuccessfulGetAPIKey(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"ApiKey my-api-key"},
	}
	expected := "my-api-key"
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !reflect.DeepEqual(apiKey, expected) {
		t.Errorf("Expected %v, got %v", expected, apiKey)
	}
}

func TestGetAPIKeyNoAuthHeader(t *testing.T) {
	headers := map[string][]string{}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKeyMalformedAuthHeader(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"Bearer my-api-key"},
	}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Errorf("Expected error 'malformed authorization header', got %v", err)
	}
}

func TestGetAPIKeyEmptyAuthHeader(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {""},
	}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKeyMissingApiKey(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"ApiKey"},
	}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Errorf("Expected error 'malformed authorization header', got %v", err)
	}
}

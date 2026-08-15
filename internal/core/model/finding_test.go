package model

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestFinding_JSONRoundTrip(t *testing.T) {
	original := Finding{
		ID:        "finding-001",
		CheckName: "sqli-boolean",
		Endpoint: Endpoint{
			Method: "GET",
			Path:   "/users/{id}",
			Parameters: []Parameter{
				{Name: "id", In: "path", Type: "integer", Required: true},
			},
			RequiresAuth:   true,
			SecurityScheme: "bearer",
			Destructive:    false,
		},
		Severity:      "high",
		OWASPCategory: "A03:2021-Injection",
		Request: CapturedRequest{
			Method: "GET",
			URL:    "http://localhost:8080/users/1' OR '1'='1",
			Headers: map[string]string{
				"Authorization": "Bearer token",
			},
			Body:          "",
			InjectedParam: "id",
			Payload:       "' OR '1'='1",
		},
		Evidence: Evidence{
			BaselineResponse: "{\"user\":null}",
			ResponseSnippet:  "{\"user\":{\"id\":1,\"admin\":true}}",
			ResponseTime:     250 * time.Millisecond,
			StatusCode:       200,
		},
		Confirmed: true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if !reflect.DeepEqual(original, decoded) {
		t.Errorf("round-trip mismatch:\noriginal = %+v\ndecoded  = %+v", original, decoded)
	}
}

func TestFinding_JSONRoundTrip_ZeroValue(t *testing.T) {
	original := Finding{}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if !reflect.DeepEqual(original, decoded) {
		t.Errorf("round-trip mismatch:\noriginal = %+v\ndecoded  = %+v", original, decoded)
	}
}

func TestFindingsFile_JSONRoundTrip(t *testing.T) {
	original := FindingsFile{
		SchemaVersion: SchemaVersion,
		Findings: []Finding{
			{ID: "finding-001", CheckName: "missing-headers", Severity: "low"},
			{ID: "finding-002", CheckName: "xss-reflected", Severity: "high", Confirmed: true},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded FindingsFile
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if !reflect.DeepEqual(original, decoded) {
		t.Errorf("round-trip mismatch:\noriginal = %+v\ndecoded  = %+v", original, decoded)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal() into map error = %v", err)
	}
	if _, ok := raw["schema_version"]; !ok {
		t.Error("serialized FindingsFile is missing the schema_version field")
	}
}

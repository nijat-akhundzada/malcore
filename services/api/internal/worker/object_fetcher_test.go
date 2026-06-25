package worker

import "testing"

func TestValidateObjectKeyAcceptsNormalizedRelativeKey(t *testing.T) {
	key, err := validateObjectKey("quarantine/job-123/file.bin")
	if err != nil {
		t.Fatalf("validate key: %v", err)
	}

	if key != "quarantine/job-123/file.bin" {
		t.Fatalf("expected normalized key, got %q", key)
	}
}

func TestValidateObjectKeyRejectsUnsafeKeys(t *testing.T) {
	tests := []string{
		"",
		"/quarantine/job-123/file.bin",
		"quarantine/job-123/../file.bin",
		"quarantine//job-123/file.bin",
		`quarantine\job-123\file.bin`,
	}

	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			if _, err := validateObjectKey(test); err == nil {
				t.Fatalf("expected %q to be rejected", test)
			}
		})
	}
}

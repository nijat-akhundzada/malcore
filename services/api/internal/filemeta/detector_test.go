package filemeta

import "testing"

func TestExtensionExtractsFromFilename(t *testing.T) {
	if got := Extension("sample.EXE"); got != ".exe" {
		t.Fatalf("expected .exe, got %q", got)
	}
}

func TestExtensionExtractsFromURLPath(t *testing.T) {
	if got := Extension("https://example.com/files/payload.PDF?token=abc"); got != ".pdf" {
		t.Fatalf("expected .pdf, got %q", got)
	}
}

func TestHasMIMEExtensionMismatch(t *testing.T) {
	tests := []struct {
		name      string
		mimeType  string
		extension string
		want      bool
	}{
		{
			name:      "exe matches PE",
			mimeType:  "application/x-dosexec",
			extension: ".exe",
			want:      false,
		},
		{
			name:      "pdf matches pdf",
			mimeType:  "application/pdf",
			extension: ".pdf",
			want:      false,
		},
		{
			name:      "jpg claiming PE mismatches",
			mimeType:  "application/x-dosexec",
			extension: ".jpg",
			want:      true,
		},
		{
			name:      "pdf extension with PE content mismatches",
			mimeType:  "application/x-dosexec",
			extension: ".pdf",
			want:      true,
		},
		{
			name:      "unknown extension does not mismatch",
			mimeType:  "application/octet-stream",
			extension: ".unknown",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasMIMEExtensionMismatch(tt.mimeType, tt.extension)
			if got != tt.want {
				t.Fatalf("expected mismatch=%v, got %v", tt.want, got)
			}
		})
	}
}

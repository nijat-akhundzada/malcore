package storage

import "testing"

func TestMinIOStorageObjectKey(t *testing.T) {
	store := &MinIOStorage{}

	got := store.objectKey("quarantine", validJobID, "/tmp/staging/"+validJobID+"/payload.bin")
	want := "quarantine/" + validJobID + "/payload.bin"

	if got != want {
		t.Fatalf("expected object key %q, got %q", want, got)
	}
}

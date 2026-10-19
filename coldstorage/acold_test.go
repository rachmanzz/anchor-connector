package coldstorage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestColdStorageWriteRead(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coldstorage_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "orders_2025.acold")

	// Phase 1: Write records
	w, err := CreateWriter(filePath, 1000)
	if err != nil {
		t.Fatalf("failed to create cold writer: %v", err)
	}

	records := []struct {
		lsn     uint64
		recType byte
		data    []byte
	}{
		{lsn: 1000, recType: 1, data: []byte("entity_order_1001_created")},
		{lsn: 1001, recType: 2, data: []byte("entity_order_1002_created")},
		{lsn: 1002, recType: 3, data: []byte("edge_linked_1001_to_1002")},
	}

	for _, r := range records {
		if err := w.AppendRecord(r.lsn, r.recType, r.data); err != nil {
			t.Fatalf("failed to append record %d: %v", r.lsn, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	// Phase 2: Read records
	reader, err := OpenReader(filePath)
	if err != nil {
		t.Fatalf("failed to open cold reader: %v", err)
	}
	defer reader.Close()

	hdr := reader.Header()
	if hdr.BaseLSN != 1000 {
		t.Errorf("baseLSN mismatch: got %d, want 1000", hdr.BaseLSN)
	}
	if hdr.EndLSN != 1002 {
		t.Errorf("endLSN mismatch: got %d, want 1002", hdr.EndLSN)
	}
	if hdr.RecordCount != 3 {
		t.Errorf("record count mismatch: got %d, want 3", hdr.RecordCount)
	}

	var readRecords []Record
	err = reader.Iterate(func(rec Record) error {
		readRecords = append(readRecords, rec)
		return nil
	})
	if err != nil {
		t.Fatalf("failed to iterate cold records: %v", err)
	}

	if len(readRecords) != len(records) {
		t.Fatalf("read record count mismatch: got %d, want %d", len(readRecords), len(records))
	}

	for i, r := range records {
		if readRecords[i].LSN != r.lsn {
			t.Errorf("record %d LSN mismatch: got %d, want %d", i, readRecords[i].LSN, r.lsn)
		}
		if readRecords[i].RecordType != r.recType {
			t.Errorf("record %d type mismatch: got %d, want %d", i, readRecords[i].RecordType, r.recType)
		}
		if !bytes.Equal(readRecords[i].Payload, r.data) {
			t.Errorf("record %d payload mismatch: got %s, want %s", i, string(readRecords[i].Payload), string(r.data))
		}
	}
}

func TestColdStorageSealImmutability(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coldstorage_seal_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "sealed_model.acold")

	w, err := CreateWriter(filePath, 500)
	if err != nil {
		t.Fatalf("failed to create cold writer: %v", err)
	}

	_ = w.AppendRecord(500, 1, []byte("data1"))
	if err := w.Seal(); err != nil {
		t.Fatalf("failed to seal cold file: %v", err)
	}

	// Appending after seal must fail
	err = w.AppendRecord(501, 1, []byte("data2"))
	if err == nil {
		t.Fatal("expected error appending to sealed file, but got nil")
	}

	_ = w.Close()

	// Re-opening sealed file for append must fail
	_, err = CreateWriter(filePath, 502)
	if err == nil {
		t.Fatal("expected error opening sealed file for write, but got nil")
	}
}

func TestColdStorageTamperDetection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coldstorage_tamper_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "tampered.acold")

	w, err := CreateWriter(filePath, 1)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}
	_ = w.AppendRecord(1, 1, []byte("vital_record_1"))
	_ = w.Close()

	// Read raw file bytes and corrupt payload
	raw, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read raw file: %v", err)
	}

	// Corrupt a byte in the payload
	raw[len(raw)-6] ^= 0xFF
	if err := os.WriteFile(filePath, raw, 0644); err != nil {
		t.Fatalf("failed to write corrupted file: %v", err)
	}

	reader, err := OpenReader(filePath)
	if err != nil {
		t.Fatalf("open reader failed: %v", err)
	}
	defer reader.Close()

	err = reader.Iterate(func(rec Record) error {
		return nil
	})

	if err == nil {
		t.Fatal("expected CRC32 corruption error during iterate, but got nil")
	}
}

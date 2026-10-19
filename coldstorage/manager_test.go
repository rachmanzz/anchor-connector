package coldstorage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
)

func TestManager_AppendAndGetRange(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cold_manager_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := config.ColdStorageConfig{
		Enabled:              true,
		StorageDir:           tempDir,
		MaxFileSizeMB:        10,
		SyncStrategy:         "always",
		FsyncIntervalSeconds: 1,
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	// Append mutations to two models
	for i := uint64(1); i <= 10; i++ {
		payload := []byte(fmt.Sprintf("user_payload_%d", i))
		if err := mgr.Append("users", i, 1, payload); err != nil {
			t.Fatalf("Append failed for users at LSN %d: %v", i, err)
		}
	}

	for i := uint64(100); i <= 105; i++ {
		payload := []byte(fmt.Sprintf("order_payload_%d", i))
		if err := mgr.Append("orders", i, 2, payload); err != nil {
			t.Fatalf("Append failed for orders at LSN %d: %v", i, err)
		}
	}

	// Verify range read for users [3, 7]
	userRecords, err := mgr.GetRange("users", 3, 7)
	if err != nil {
		t.Fatalf("GetRange users failed: %v", err)
	}
	if len(userRecords) != 5 {
		t.Fatalf("expected 5 records, got %d", len(userRecords))
	}
	if userRecords[0].LSN != 3 || userRecords[4].LSN != 7 {
		t.Fatalf("unexpected LSN range for users: [%d, %d]", userRecords[0].LSN, userRecords[4].LSN)
	}
	expectedPayload := []byte("user_payload_3")
	if !bytes.Equal(userRecords[0].Payload, expectedPayload) {
		t.Fatalf("payload mismatch: got %s, want %s", string(userRecords[0].Payload), string(expectedPayload))
	}

	// Verify range read for orders [100, 105]
	orderRecords, err := mgr.GetRange("orders", 100, 105)
	if err != nil {
		t.Fatalf("GetRange orders failed: %v", err)
	}
	if len(orderRecords) != 6 {
		t.Fatalf("expected 6 records, got %d", len(orderRecords))
	}
}

func TestManager_SegmentRotation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cold_rotation_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Set MaxFileSizeMB to 1MB
	cfg := config.ColdStorageConfig{
		Enabled:              true,
		StorageDir:           tempDir,
		MaxFileSizeMB:        1,
		SyncStrategy:         "always",
		FsyncIntervalSeconds: 1,
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	// Write large payloads (60KB each) to force segment rotation beyond 1MB
	payload := make([]byte, 60*1024)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}

	totalRecords := 25 // 25 * 60KB = 1.5MB > 1MB threshold
	for i := uint64(1); i <= uint64(totalRecords); i++ {
		if err := mgr.Append("large_model", i, 1, payload); err != nil {
			t.Fatalf("Append failed at LSN %d: %v", i, err)
		}
	}

	// Verify that multiple .acold files were created
	modelDir := filepath.Join(tempDir, "large_model")
	entries, err := os.ReadDir(modelDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	var acoldFiles []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".acold" {
			acoldFiles = append(acoldFiles, e.Name())
		}
	}

	if len(acoldFiles) < 2 {
		t.Fatalf("expected at least 2 rotated segments, got %d files: %v", len(acoldFiles), acoldFiles)
	}

	// Verify that the first segment was sealed with FlagImmutable
	firstFilePath := filepath.Join(modelDir, acoldFiles[0])
	f, err := os.Open(firstFilePath)
	if err != nil {
		t.Fatalf("failed to open first segment: %v", err)
	}
	hdr, err := ReadHeader(f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("failed to read header from first segment: %v", err)
	}
	if hdr.Flags&FlagImmutable == 0 {
		t.Fatalf("expected first rotated segment to be sealed with FlagImmutable, got flags: %d", hdr.Flags)
	}

	// Verify seamless range query across segment boundary [1, totalRecords]
	records, err := mgr.GetRange("large_model", 1, uint64(totalRecords))
	if err != nil {
		t.Fatalf("GetRange across segments failed: %v", err)
	}
	if len(records) != totalRecords {
		t.Fatalf("expected %d records across rotated segments, got %d", totalRecords, len(records))
	}
	for idx, r := range records {
		expectedLSN := uint64(idx + 1)
		if r.LSN != expectedLSN {
			t.Fatalf("record %d LSN mismatch: got %d, want %d", idx, r.LSN, expectedLSN)
		}
	}
}

func TestManager_IntervalFlusher(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cold_flusher_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := config.ColdStorageConfig{
		Enabled:              true,
		StorageDir:           tempDir,
		MaxFileSizeMB:        10,
		SyncStrategy:         "interval",
		FsyncIntervalSeconds: 1, // 1 second interval
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	if err := mgr.Append("metric_stream", 1, 1, []byte("val_1")); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Wait for background flusher cycle
	time.Sleep(1200 * time.Millisecond)

	records, err := mgr.GetRange("metric_stream", 1, 1)
	if err != nil {
		t.Fatalf("GetRange failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record after flusher interval, got %d", len(records))
	}
}

func TestManager_ConcurrencySafe(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cold_concurrent_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := config.ColdStorageConfig{
		Enabled:              true,
		StorageDir:           tempDir,
		MaxFileSizeMB:        50,
		SyncStrategy:         "always",
		FsyncIntervalSeconds: 1,
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	workers := 4
	recordsPerWorker := 50
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			modelName := fmt.Sprintf("partition_%d", workerID%2)
			for i := 1; i <= recordsPerWorker; i++ {
				lsn := uint64(workerID*1000 + i)
				payload := []byte(fmt.Sprintf("worker_%d_record_%d", workerID, i))
				if err := mgr.Append(modelName, lsn, 1, payload); err != nil {
					t.Errorf("worker %d append failed at LSN %d: %v", workerID, lsn, err)
					return
				}
			}
		}(w)
	}

	wg.Wait()

	// Read partition_0 records
	part0Records, err := mgr.GetRange("partition_0", 0, 100000)
	if err != nil {
		t.Fatalf("GetRange partition_0 failed: %v", err)
	}
	expectedCount := 2 * recordsPerWorker // workers 0 and 2
	if len(part0Records) != expectedCount {
		t.Fatalf("expected %d records in partition_0, got %d", expectedCount, len(part0Records))
	}
}

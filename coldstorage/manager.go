package coldstorage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
)

var (
	ErrStorageDisabled = errors.New("coldstorage: cold storage is disabled")
	ErrManagerClosed   = errors.New("coldstorage: storage manager is closed")
)

type activeWriter struct {
	mu       sync.Mutex
	writer   *Writer
	model    string
	baseLSN  uint64
	lastLSN  uint64
	filePath string
	fileSize int64
}

// Manager orchestrates native .acold binary storage archives per model,
// handling real-time synchronization, periodic fsync, and automatic segment rotation.
type Manager struct {
	cfg         config.ColdStorageConfig
	writers     map[string]*activeWriter
	mu          sync.RWMutex
	stopChan    chan struct{}
	flusherDone chan struct{}
	closed      atomic.Bool
	flusherOnce sync.Once
}

// NewManager creates a storage manager and initializes background fsync workers if configured.
func NewManager(cfg config.ColdStorageConfig) (*Manager, error) {
	if cfg.StorageDir == "" {
		cfg.StorageDir = "./data/cold"
	}
	if cfg.FsyncIntervalSeconds <= 0 {
		cfg.FsyncIntervalSeconds = 5
	}
	if cfg.MaxFileSizeMB <= 0 {
		cfg.MaxFileSizeMB = 512
	}

	if cfg.Enabled {
		if err := os.MkdirAll(cfg.StorageDir, 0755); err != nil {
			return nil, fmt.Errorf("coldstorage: failed to create storage directory: %w", err)
		}
	}

	m := &Manager{
		cfg:         cfg,
		writers:     make(map[string]*activeWriter),
		stopChan:    make(chan struct{}),
		flusherDone: make(chan struct{}),
	}

	if cfg.Enabled && cfg.SyncStrategy == "interval" {
		m.startFlusher(time.Duration(cfg.FsyncIntervalSeconds) * time.Second)
	} else {
		close(m.flusherDone)
	}

	return m, nil
}

func (m *Manager) startFlusher(interval time.Duration) {
	m.flusherOnce.Do(func() {
		go func() {
			defer close(m.flusherDone)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					_ = m.Sync()
				case <-m.stopChan:
					_ = m.Sync()
					return
				}
			}
		}()
	})
}

// Append appends a mutation record to the active .acold segment of the specified model.
// Automatically rotates the segment when file size exceeds MaxFileSizeMB.
func (m *Manager) Append(model string, lsn uint64, recordType byte, payload []byte) error {
	if !m.cfg.Enabled {
		return nil
	}
	if m.closed.Load() {
		return ErrManagerClosed
	}
	if model == "" {
		model = "default"
	}

	aw, err := m.getOrCreateWriter(model, lsn)
	if err != nil {
		return err
	}

	aw.mu.Lock()
	defer aw.mu.Unlock()

	// Estimated record size: Header (12B) + Payload + CRC32 (4B)
	recSize := int64(12 + len(payload) + 4)
	maxBytes := int64(m.cfg.MaxFileSizeMB) * 1024 * 1024

	// Rotate segment if threshold reached
	if aw.fileSize+recSize > maxBytes {
		_ = aw.writer.Seal()
		_ = aw.writer.Close()

		newPath := filepath.Join(m.cfg.StorageDir, model, fmt.Sprintf("%s_%020d.acold", model, lsn))
		newWriter, err := CreateWriter(newPath, lsn)
		if err != nil {
			return fmt.Errorf("coldstorage: failed to rotate segment for %s: %w", model, err)
		}
		aw.writer = newWriter
		aw.baseLSN = lsn
		aw.filePath = newPath
		aw.fileSize = HeaderSize
	}

	if err := aw.writer.AppendRecord(lsn, recordType, payload); err != nil {
		return err
	}

	aw.lastLSN = lsn
	aw.fileSize += recSize

	if m.cfg.SyncStrategy == "always" {
		return aw.writer.Sync()
	}

	return nil
}

func (m *Manager) getOrCreateWriter(model string, lsn uint64) (*activeWriter, error) {
	m.mu.RLock()
	aw, exists := m.writers[model]
	m.mu.RUnlock()
	if exists {
		return aw, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-checked locking
	if aw, exists = m.writers[model]; exists {
		return aw, nil
	}

	modelDir := filepath.Join(m.cfg.StorageDir, model)
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		return nil, fmt.Errorf("coldstorage: failed to create model dir: %w", err)
	}

	filePath := filepath.Join(modelDir, fmt.Sprintf("%s_%020d.acold", model, lsn))
	w, err := CreateWriter(filePath, lsn)
	if err != nil {
		return nil, fmt.Errorf("coldstorage: failed to initialize writer: %w", err)
	}

	aw = &activeWriter{
		writer:   w,
		model:    model,
		baseLSN:  lsn,
		lastLSN:  lsn,
		filePath: filePath,
		fileSize: HeaderSize,
	}

	m.writers[model] = aw
	return aw, nil
}

// Sync commits all buffered mutation records across all active model writers to disk.
func (m *Manager) Sync() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var firstErr error
	for _, aw := range m.writers {
		aw.mu.Lock()
		if err := aw.writer.Sync(); err != nil && firstErr == nil {
			firstErr = err
		}
		aw.mu.Unlock()
	}

	return firstErr
}

// GetRange scans archived .acold segment files for the specified model within [fromLSN, toLSN].
func (m *Manager) GetRange(model string, fromLSN, toLSN uint64) ([]Record, error) {
	if model == "" {
		model = "default"
	}
	if fromLSN > toLSN {
		return nil, nil
	}

	// Commit any in-flight buffer for this model
	m.mu.RLock()
	aw := m.writers[model]
	m.mu.RUnlock()
	if aw != nil {
		aw.mu.Lock()
		_ = aw.writer.Sync()
		aw.mu.Unlock()
	}

	// Locate all segment files for the model
	modelDir := filepath.Join(m.cfg.StorageDir, model)
	entries, err := os.ReadDir(modelDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("coldstorage: failed to read model directory: %w", err)
	}

	type segmentMeta struct {
		filePath string
		baseLSN  uint64
		endLSN   uint64
	}

	var matchingSegments []segmentMeta
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".acold") {
			continue
		}

		fullPath := filepath.Join(modelDir, entry.Name())
		f, err := os.Open(fullPath)
		if err != nil {
			continue
		}

		hdr, err := ReadHeader(f)
		_ = f.Close()
		if err != nil {
			continue
		}

		// Overlap check: segment range [hdr.BaseLSN, hdr.EndLSN] overlaps [fromLSN, toLSN]
		if !(hdr.EndLSN < fromLSN || hdr.BaseLSN > toLSN) {
			matchingSegments = append(matchingSegments, segmentMeta{
				filePath: fullPath,
				baseLSN:  hdr.BaseLSN,
				endLSN:   hdr.EndLSN,
			})
		}
	}

	// Sort segments chronologically
	sort.Slice(matchingSegments, func(i, j int) bool {
		return matchingSegments[i].baseLSN < matchingSegments[j].baseLSN
	})

	var result []Record
	for _, seg := range matchingSegments {
		reader, err := OpenReader(seg.filePath)
		if err != nil {
			return nil, fmt.Errorf("coldstorage: failed to open reader for %s: %w", seg.filePath, err)
		}

		err = reader.Iterate(func(rec Record) error {
			if rec.LSN >= fromLSN && rec.LSN <= toLSN {
				result = append(result, rec)
			}
			return nil
		})
		_ = reader.Close()

		if err != nil {
			return nil, fmt.Errorf("coldstorage: error iterating records in %s: %w", seg.filePath, err)
		}
	}

	return result, nil
}

// Close flushes all active writers and shuts down background flusher workers.
func (m *Manager) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(m.stopChan)
	<-m.flusherDone

	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for _, aw := range m.writers {
		aw.mu.Lock()
		if err := aw.writer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		aw.mu.Unlock()
	}

	return firstErr
}

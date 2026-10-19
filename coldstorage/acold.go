package coldstorage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	// Magic string for Anchor Connector Native Cold Binary File: "ACOL" (4 bytes)
	MagicString = "ACOL"
	Version     = byte(0x01)
	HeaderSize  = 32

	// Compression types
	CompNone byte = 0x00

	// Flags
	FlagNone      uint16 = 0x0000
	FlagImmutable uint16 = 0x0001
	FlagEncrypted uint16 = 0x0002
)

var (
	ErrInvalidMagic    = errors.New("coldstorage: invalid file magic")
	ErrCorruptHeader   = errors.New("coldstorage: header crc32 mismatch")
	ErrCorruptRecord   = errors.New("coldstorage: record crc32 mismatch")
	ErrFileImmutable   = errors.New("coldstorage: file is sealed and immutable")
	ErrRecordTruncated = errors.New("coldstorage: unexpected eof while reading record")
)

// Header represents the 32-byte header of a .acold binary file.
type Header struct {
	Magic       [4]byte
	Version     byte
	CompType    byte
	Flags       uint16
	BaseLSN     uint64
	EndLSN      uint64
	RecordCount uint32
	Checksum    uint32
}

// Record represents a single archived mutation entry in cold storage.
type Record struct {
	LSN        uint64
	RecordType byte
	Payload    []byte
}

// Writer appends records to an .acold binary file.
type Writer struct {
	file        *os.File
	filePath    string
	baseLSN     uint64
	currentLSN  uint64
	recordCount uint32
	writeOffset int64
	mu          sync.Mutex
	closed      bool
	sealed      bool
}

// CreateWriter opens or creates a new .acold file for appending.
func CreateWriter(filePath string, baseLSN uint64) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open cold storage file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	w := &Writer{
		file:       f,
		filePath:   filePath,
		baseLSN:    baseLSN,
		currentLSN: baseLSN,
	}

	if info.Size() == 0 {
		// Write initial placeholder 32-byte header
		if err := w.writeHeader(baseLSN, baseLSN, 0, FlagNone); err != nil {
			_ = f.Close()
			return nil, err
		}
		w.writeOffset = HeaderSize
	} else {
		// Existing file: read and validate header
		hdr, err := ReadHeader(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("cannot append to corrupt cold file: %w", err)
		}
		if hdr.Flags&FlagImmutable != 0 {
			_ = f.Close()
			return nil, ErrFileImmutable
		}
		w.baseLSN = hdr.BaseLSN
		w.currentLSN = hdr.EndLSN
		w.recordCount = hdr.RecordCount
		w.writeOffset = info.Size()
	}

	return w, nil
}

func (w *Writer) writeHeader(baseLSN, endLSN uint64, count uint32, flags uint16) error {
	var buf [HeaderSize]byte
	copy(buf[0:4], MagicString)
	buf[4] = Version
	buf[5] = CompNone
	binary.BigEndian.PutUint16(buf[6:8], flags)
	binary.BigEndian.PutUint64(buf[8:16], baseLSN)
	binary.BigEndian.PutUint64(buf[16:24], endLSN)
	binary.BigEndian.PutUint32(buf[24:28], count)

	// Checksum covers bytes 0 to 28
	csum := crc32.ChecksumIEEE(buf[0:28])
	binary.BigEndian.PutUint32(buf[28:32], csum)

	if _, err := w.file.WriteAt(buf[:], 0); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	return nil
}

// AppendRecord writes a single record block to the .acold file with a trailing CRC32 checksum.
func (w *Writer) AppendRecord(lsn uint64, recordType byte, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("coldstorage: writer is closed")
	}
	if w.sealed {
		return ErrFileImmutable
	}
	if len(payload) > 65535 {
		return fmt.Errorf("cold record payload exceeds max 65535 bytes: %d", len(payload))
	}

	// Record block layout:
	// LSN (8B) + RecordType (1B) + Reserved (1B) + Length (2B) + Payload (NB) + CRC32 (4B)
	headerLen := 8 + 1 + 1 + 2
	totalLen := headerLen + len(payload) + 4
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint64(buf[0:8], lsn)
	buf[8] = recordType
	buf[9] = 0x00 // Reserved
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(payload)))
	copy(buf[12:12+len(payload)], payload)

	// Compute CRC32 over LSN through payload
	csum := crc32.ChecksumIEEE(buf[0 : headerLen+len(payload)])
	binary.BigEndian.PutUint32(buf[headerLen+len(payload):], csum)

	if _, err := w.file.WriteAt(buf, w.writeOffset); err != nil {
		return fmt.Errorf("failed to append record to cold store: %w", err)
	}

	w.writeOffset += int64(totalLen)
	w.currentLSN = lsn
	w.recordCount++

	// Update header in-place
	return w.writeHeader(w.baseLSN, w.currentLSN, w.recordCount, FlagNone)
}

// Seal marks the cold file as immutable so no more appends are permitted.
func (w *Writer) Seal() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("coldstorage: writer closed")
	}
	w.sealed = true
	return w.writeHeader(w.baseLSN, w.currentLSN, w.recordCount, FlagImmutable)
}

// Sync commits current buffered data to disk (fsync).
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Sync()
}

// Close flushes and closes the cold storage file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	_ = w.writeHeader(w.baseLSN, w.currentLSN, w.recordCount, func() uint16 {
		if w.sealed {
			return FlagImmutable
		}
		return FlagNone
	}())
	_ = w.file.Sync()
	return w.file.Close()
}

// ReadHeader parses and validates the 32-byte header from an io.ReaderAt.
func ReadHeader(r io.ReaderAt) (Header, error) {
	var buf [HeaderSize]byte
	if _, err := r.ReadAt(buf[:], 0); err != nil {
		return Header{}, err
	}

	if string(buf[0:4]) != MagicString {
		return Header{}, ErrInvalidMagic
	}
	if buf[4] != Version {
		return Header{}, fmt.Errorf("unsupported .acold version: %d", buf[4])
	}

	expectedChecksum := binary.BigEndian.Uint32(buf[28:32])
	actualChecksum := crc32.ChecksumIEEE(buf[0:28])
	if actualChecksum != expectedChecksum {
		return Header{}, ErrCorruptHeader
	}

	var magic [4]byte
	copy(magic[:], buf[0:4])

	return Header{
		Magic:       magic,
		Version:     buf[4],
		CompType:    buf[5],
		Flags:       binary.BigEndian.Uint16(buf[6:8]),
		BaseLSN:     binary.BigEndian.Uint64(buf[8:16]),
		EndLSN:      binary.BigEndian.Uint64(buf[16:24]),
		RecordCount: binary.BigEndian.Uint32(buf[24:28]),
		Checksum:    expectedChecksum,
	}, nil
}

// Reader reads and validates records sequentially from an .acold file.
type Reader struct {
	file     *os.File
	header   Header
	filePath string
}

// OpenReader opens an .acold file for inspection and record iteration.
func OpenReader(filePath string) (*Reader, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	hdr, err := ReadHeader(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	return &Reader{
		file:     f,
		header:   hdr,
		filePath: filePath,
	}, nil
}

// Header returns the parsed file header metadata.
func (r *Reader) Header() Header {
	return r.header
}

// Iterate scans all records from the file, executing the callback for each.
func (r *Reader) Iterate(fn func(rec Record) error) error {
	if _, err := r.file.Seek(HeaderSize, io.SeekStart); err != nil {
		return err
	}

	var hdrBuf [12]byte
	for {
		_, err := io.ReadFull(r.file, hdrBuf[:])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read record header error: %w", err)
		}

		lsn := binary.BigEndian.Uint64(hdrBuf[0:8])
		recType := hdrBuf[8]
		payloadLen := binary.BigEndian.Uint16(hdrBuf[10:12])

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r.file, payload); err != nil {
			return ErrRecordTruncated
		}

		var csumBuf [4]byte
		if _, err := io.ReadFull(r.file, csumBuf[:]); err != nil {
			return ErrRecordTruncated
		}
		expectedCsum := binary.BigEndian.Uint32(csumBuf[:])

		// Verify record CRC32
		dataToHash := make([]byte, 12+int(payloadLen))
		copy(dataToHash[0:12], hdrBuf[:])
		copy(dataToHash[12:], payload)
		actualCsum := crc32.ChecksumIEEE(dataToHash)

		if actualCsum != expectedCsum {
			return ErrCorruptRecord
		}

		rec := Record{
			LSN:        lsn,
			RecordType: recType,
			Payload:    payload,
		}

		if err := fn(rec); err != nil {
			return err
		}
	}

	return nil
}

// Close closes the underlying reader file.
func (r *Reader) Close() error {
	return r.file.Close()
}

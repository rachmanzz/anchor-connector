package wire

import (
	"bytes"
	"testing"
)

func BenchmarkFrameEncodeDecode(b *testing.B) {
	frame := Frame{
		Magic:   Magic,
		Version: Version,
		OpCode:  OpSave,
		Flags:   FlagNone,
		Seq:     12345,
		Payload: []byte(`{"key":"user:1001","name":"Alice Smith","role":"admin"}`),
	}

	buf := new(bytes.Buffer)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := WriteFrame(buf, frame); err != nil {
			b.Fatalf("WriteFrame failed: %v", err)
		}
		decoded, err := ReadFrame(buf)
		if err != nil {
			b.Fatalf("ReadFrame failed: %v", err)
		}
		if decoded.Seq != 12345 {
			b.Fatalf("unexpected seq: %d", decoded.Seq)
		}
	}
}

func BenchmarkReadHeader(b *testing.B) {
	rawHeader := []byte{
		Magic,                  // 0xA5
		Version,                // 0x01
		OpGet,                  // OpCode
		0x00,                   // Flags
		0x2A, 0x00, 0x00, 0x00, // Seq = 42
		0x10, 0x00, 0x00, 0x00, // Length = 16
		0x00, 0x00, 0x00, 0x00, // Checksum = 0
	}

	reader := bytes.NewReader(rawHeader)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader.Reset(rawHeader)
		opCode, _, seq, _, _, err := ReadHeader(reader)
		if err != nil {
			b.Fatalf("ReadHeader failed: %v", err)
		}
		if opCode != OpGet || seq != 42 {
			b.Fatalf("unexpected header values")
		}
	}
}

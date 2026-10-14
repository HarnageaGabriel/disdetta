package cluster

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"math/rand"
	"testing"
)

// gzipPayload compresses data with gzip, the middle step of the Helm release
// encoding (docs/research/RESEARCH-NOTES.md section 9: JSON -> gzip -> base64,
// as Helm's encodeRelease does in
// https://github.com/helm/helm/blob/main/pkg/storage/driver/util.go).
func gzipPayload(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestDecodeReleasePayloadGzip covers the current encoding: base64 StdEncoding
// of gzip-compressed JSON (docs/research/RESEARCH-NOTES.md section 9).
func TestDecodeReleasePayloadGzip(t *testing.T) {
	document := []byte(`{"chart":{"metadata":{"name":"postgresql"}},"config":{"a":1}}`)
	encoded := base64.StdEncoding.EncodeToString(gzipPayload(t, document))
	got, err := DecodeReleasePayload([]byte(encoded))
	if err != nil {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: %v", err)
	}
	if !bytes.Equal(got, document) {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: got %q", got)
	}
	padded := append([]byte("\n  "), encoded...)
	padded = append(padded, '\n')
	if _, err := DecodeReleasePayload(padded); err != nil {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: surrounding whitespace: %v", err)
	}
}

// TestDecodeReleasePayloadLegacy covers an uncompressed legacy payload, which is
// plain JSON (docs/research/RESEARCH-NOTES.md section 9).
func TestDecodeReleasePayloadLegacy(t *testing.T) {
	document := []byte(`{"name":"pg","config":{}}`)
	got, err := DecodeReleasePayload(document)
	if err != nil || !bytes.Equal(got, document) {
		t.Fatalf("source docs/research/RESEARCH-NOTES.md section 9: got %q err %v", got, err)
	}
}

// TestDecodeReleasePayloadNotDecodable covers payloads that are neither
// base64+gzip JSON nor plain JSON, which the scan reports as DSD-SCN-009
// (spec v0.2 sections 4 and 5).
func TestDecodeReleasePayloadNotDecodable(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"blank":           []byte("   \n"),
		"not base64":      []byte("!!!not-base64!!!"),
		"gzip magic only": []byte(base64.StdEncoding.EncodeToString([]byte{0x1f, 0x8b, 0x08, 0xff, 0x00})),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeReleasePayload(in); !errors.Is(err, ErrReleaseNotDecodable) {
				t.Fatalf("source docs/spec/v0.2-cluster.md section 4: err %v", err)
			}
		})
	}
}

// TestDecodeReleasePayloadCaps covers the three bounded-decoding caps and the
// ratio guard against a zip bomb (spec v0.2 section 4, threat model T3).
func TestDecodeReleasePayloadCaps(t *testing.T) {
	t.Run("compressed cap", func(t *testing.T) {
		incompressible := make([]byte, MaxReleasePayloadSize+4096)
		rand.New(rand.NewSource(1)).Read(incompressible)
		compressed := gzipPayload(t, incompressible)
		if len(compressed) <= MaxReleasePayloadSize {
			t.Fatalf("test setup: compressed %d not over cap", len(compressed))
		}
		e := base64.StdEncoding.EncodeToString(compressed)
		if _, err := DecodeReleasePayload([]byte(e)); !errors.Is(err, ErrReleasePayloadTooLarge) {
			t.Fatalf("source docs/spec/v0.2-cluster.md section 4: err %v", err)
		}
	})
	t.Run("legacy JSON cap", func(t *testing.T) {
		big := append([]byte("{"), bytes.Repeat([]byte("a"), MaxReleasePayloadSize)...)
		if _, err := DecodeReleasePayload(big); !errors.Is(err, ErrReleasePayloadTooLarge) {
			t.Fatalf("source docs/spec/v0.2-cluster.md section 4: err %v", err)
		}
	})
	t.Run("ratio cap zip bomb", func(t *testing.T) {
		bomb := gzipPayload(t, make([]byte, 8<<20))
		encoded := base64.StdEncoding.EncodeToString(bomb)
		if _, err := DecodeReleasePayload([]byte(encoded)); !errors.Is(err, ErrReleaseRatio) {
			t.Fatalf("source docs/spec/v0.2-cluster.md section 4: err %v", err)
		}
	})
	t.Run("decompressed cap", func(t *testing.T) {
		// A large incompressible prefix keeps the compressed payload over 1/100
		// of the absolute cap, so the 32 MiB cap is the binding limit.
		data := make([]byte, 400<<10)
		rand.New(rand.NewSource(2)).Read(data)
		data = append(data, make([]byte, 33<<20)...)
		compressed := gzipPayload(t, data)
		encoded := base64.StdEncoding.EncodeToString(compressed)
		if _, err := DecodeReleasePayload([]byte(encoded)); !errors.Is(err, ErrReleaseDecodedTooLarge) {
			t.Fatalf("source docs/spec/v0.2-cluster.md section 4: err %v (compressed %d)", err, len(compressed))
		}
	})
}

// TestDecodeReleasePayloadRejectsLongEncoding checks review 03 m1: an input
// longer than the base64 encoding of the compressed cap is rejected before it is
// decoded, even when it would fail base64 decoding anyway and after trimming
// surrounding whitespace.
func TestDecodeReleasePayloadRejectsLongEncoding(t *testing.T) {
	tooLong := bytes.Repeat([]byte("A"), base64.StdEncoding.EncodedLen(MaxReleasePayloadSize)+1)
	cases := map[string][]byte{
		"no padding": tooLong,
		"surrounded": append(append([]byte("\n  "), tooLong...), '\n'),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeReleasePayload(in); !errors.Is(err, ErrReleasePayloadTooLarge) {
				t.Fatalf("review 03 m1: err %v", err)
			}
		})
	}
}

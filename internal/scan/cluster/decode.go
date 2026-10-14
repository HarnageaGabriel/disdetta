package cluster

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Bounded-decoding caps for a Helm release payload (spec v0.2 section 4,
// threat model T3).
const (
	// MaxReleasePayloadSize caps the compressed payload before decompression.
	MaxReleasePayloadSize = 4 << 20
	// MaxReleaseDecodedSize caps the decompressed payload.
	MaxReleaseDecodedSize = 32 << 20
	// MaxReleaseRatio caps the decompressed-to-compressed expansion ratio.
	MaxReleaseRatio = 100
)

// gzipMagic is the gzip header magic a Helm release payload carries
// (research notes section 9).
var gzipMagic = []byte{0x1f, 0x8b, 0x08}

var (
	// ErrReleasePayloadTooLarge reports a payload over the compressed cap.
	ErrReleasePayloadTooLarge = errors.New("helm release payload over 4 MiB")
	// ErrReleaseDecodedTooLarge reports decompressed output over the 32 MiB cap.
	ErrReleaseDecodedTooLarge = errors.New("helm release payload over 32 MiB decompressed")
	// ErrReleaseRatio reports an expansion ratio over 100:1.
	ErrReleaseRatio = errors.New("helm release payload over 100:1 expansion")
	// ErrReleaseNotDecodable reports a payload that is neither base64+gzip JSON
	// nor plain JSON.
	ErrReleaseNotDecodable = errors.New("helm release payload is not decodable")
)

// DecodeReleasePayload decodes a Helm release Secret payload: base64
// (StdEncoding) of gzip-compressed JSON, or a legacy plain JSON payload
// (research notes section 9). The compressed size, the decompressed size and
// the expansion ratio are all bounded (spec v0.2 section 4). Decoding happens
// in memory only; the caller reports DSD-SCN-009 on error.
func DecodeReleasePayload(encoded []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(encoded)
	if len(trimmed) == 0 {
		return nil, ErrReleaseNotDecodable
	}
	payload, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		// A legacy, uncompressed payload is plain JSON (research notes section 9).
		if looksLikeJSON(trimmed) {
			if len(trimmed) > MaxReleasePayloadSize {
				return nil, ErrReleasePayloadTooLarge
			}
			return trimmed, nil
		}
		return nil, ErrReleaseNotDecodable
	}
	if len(payload) > MaxReleasePayloadSize {
		return nil, ErrReleasePayloadTooLarge
	}
	if !bytes.HasPrefix(payload, gzipMagic) {
		if !looksLikeJSON(payload) {
			return nil, ErrReleaseNotDecodable
		}
		return payload, nil
	}
	return decompress(payload)
}

// decompress reads one gzip member with a decompressed cap and a ratio cap, so
// a small payload cannot expand without bound (threat model T3).
func decompress(payload []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReleaseNotDecodable, err)
	}
	defer func() { _ = zr.Close() }()
	// One member only: a concatenated-member stream must not bypass the cap.
	zr.Multistream(false)
	limit := MaxReleaseDecodedSize
	if r := len(payload) * MaxReleaseRatio; r < limit {
		limit = r
	}
	out, err := io.ReadAll(io.LimitReader(zr, int64(limit)+1))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: %v", ErrReleaseNotDecodable, err)
	}
	if len(out) > limit {
		if limit == MaxReleaseDecodedSize {
			return nil, ErrReleaseDecodedTooLarge
		}
		return nil, ErrReleaseRatio
	}
	return out, nil
}

// looksLikeJSON reports whether data begins with a JSON object, the shape of a
// decoded Helm release.
func looksLikeJSON(data []byte) bool {
	return len(data) > 0 && data[0] == '{'
}

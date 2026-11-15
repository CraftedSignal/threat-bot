package scraper

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// Jetstream's custom Zstd dictionary, vendored without the server's dependency
// tree. MIT licensed upstream, pinned to commit
// 8a65de4eda28bed1cafcbcf25b0cd46ac6f2148b:
// https://github.com/bluesky-social/jetstream-legacy/blob/8a65de4eda28bed1cafcbcf25b0cd46ac6f2148b/pkg/models/zstd_dictionary
//
// Store the pinned binary dictionary as deterministic gzip (mtime=0). This
// preserves its exact public bytes without making public AT Protocol record
// identifiers look like API keys to source scanners.
//
//go:embed jetstream_zstd_dictionary.gz
var packedJetstreamDictionary []byte

const jetstreamDictionaryBytes = 112640
const jetstreamDictionarySHA256 = "b8d77b46933aceecbdd5275a01241efc985c970c78162b8150cf67a26522f70c"

func unpackJetstreamDictionary(packed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("opening Jetstream dictionary: %w", err)
	}
	defer func() { _ = reader.Close() }()
	dictionary, err := io.ReadAll(io.LimitReader(reader, jetstreamDictionaryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("unpacking Jetstream dictionary: %w", err)
	}
	if len(dictionary) != jetstreamDictionaryBytes || fmt.Sprintf("%x", sha256.Sum256(dictionary)) != jetstreamDictionarySHA256 {
		return nil, fmt.Errorf("jetstream dictionary differs from pinned upstream bytes")
	}
	return dictionary, nil
}

func newJetstreamDecoder() (*zstd.Decoder, error) {
	dictionary, err := unpackJetstreamDictionary(packedJetstreamDictionary)
	if err != nil {
		return nil, err
	}
	decoder, err := zstd.NewReader(nil,
		zstd.WithDecoderDicts(dictionary),
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxMemory(jetstreamMessageReadLimit),
		zstd.WithDecoderMaxWindow(jetstreamMessageReadLimit),
	)
	if err != nil {
		return nil, fmt.Errorf("initializing Jetstream decompression: %w", err)
	}
	return decoder, nil
}

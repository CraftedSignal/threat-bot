package scraper

import (
	_ "embed"
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// Jetstream's custom Zstd dictionary, vendored without the server's dependency
// tree. MIT licensed upstream, pinned to commit
// 8a65de4eda28bed1cafcbcf25b0cd46ac6f2148b:
// https://github.com/bluesky-social/jetstream-legacy/blob/8a65de4eda28bed1cafcbcf25b0cd46ac6f2148b/pkg/models/zstd_dictionary
//
//go:embed jetstream_zstd_dictionary
var jetstreamZstdDictionary []byte

func newJetstreamDecoder() (*zstd.Decoder, error) {
	decoder, err := zstd.NewReader(nil,
		zstd.WithDecoderDicts(jetstreamZstdDictionary),
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

package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// unmarshalJSON decodes LLM output into out. It tolerates common Gemini quirks:
// markdown code fences, single objects wrapped in one-element arrays,
// unsupported JSON escapes inside strings, and trailing commas. If the raw
// text cannot be coerced into out, the original text is included in the error
// for diagnostics.
func unmarshalJSON(text string, out any) error {
	cleaned := removeTrailingCommas(escapeUnsupportedJSONEscapes(stripFences(text)))

	err := json.Unmarshal([]byte(cleaned), out)
	if err == nil {
		return nil
	}

	if !isArrayMismatch(err) {
		return fmt.Errorf("parsing LLM JSON response: %w (raw: %s)", err, text)
	}

	var arr []json.RawMessage
	if aerr := json.Unmarshal([]byte(cleaned), &arr); aerr != nil {
		return fmt.Errorf("parsing LLM JSON response: %w (raw: %s)", err, text)
	}
	if len(arr) == 0 {
		return fmt.Errorf("parsing LLM JSON response: empty array (raw: %s)", text)
	}
	if uerr := json.Unmarshal(arr[0], out); uerr != nil {
		return fmt.Errorf("parsing LLM JSON response: %w (raw: %s)", uerr, text)
	}
	return nil
}

// escapeUnsupportedJSONEscapes turns backslashes that do not introduce a
// valid JSON escape into literal backslashes, but only inside strings. This
// recovers common LLM output such as \x65 without accepting malformed JSON
// structure.
func escapeUnsupportedJSONEscapes(text string) string {
	var repaired strings.Builder
	repaired.Grow(len(text))
	inString := false

	for i := 0; i < len(text); i++ {
		char := text[i]
		if char == '"' {
			inString = !inString
			repaired.WriteByte(char)
			continue
		}
		if char != '\\' || !inString || i+1 == len(text) {
			repaired.WriteByte(char)
			continue
		}

		next := text[i+1]
		switch next {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u':
			repaired.WriteByte(char)
			repaired.WriteByte(next)
			i++
		default:
			repaired.WriteString(`\\`)
		}
	}

	return repaired.String()
}

// removeTrailingCommas drops commas that end an array or object, outside
// strings, as Gemini occasionally emits even in JSON mode. Only a comma that
// follows a value is dropped, so empty elements such as [,] or {"key":,}
// still fail to parse.
func removeTrailingCommas(text string) string {
	var repaired strings.Builder
	repaired.Grow(len(text))
	inString := false
	var prev byte // last non-whitespace byte written outside strings

	for i := 0; i < len(text); i++ {
		char := text[i]
		if inString {
			repaired.WriteByte(char)
			if char == '\\' && i+1 < len(text) {
				i++
				repaired.WriteByte(text[i])
			} else if char == '"' {
				inString = false
				prev = char
			}
			continue
		}
		if char == ',' && endsValue(prev) && closesNext(text[i+1:]) {
			continue
		}
		repaired.WriteByte(char)
		switch char {
		case ' ', '\t', '\n', '\r':
		case '"':
			inString = true
		default:
			prev = char
		}
	}

	return repaired.String()
}

// endsValue reports whether prev, the last structural byte before a comma,
// can end a JSON value.
func endsValue(prev byte) bool {
	switch prev {
	case 0, '{', '[', ',', ':':
		return false
	}
	return true
}

// closesNext reports whether the next non-whitespace byte in text closes an
// array or object.
func closesNext(text string) bool {
	rest := strings.TrimLeft(text, " \t\n\r")
	return rest != "" && (rest[0] == ']' || rest[0] == '}')
}

// stripFences removes surrounding markdown code fences (```json ... ```).
func stripFences(text string) string {
	s := strings.TrimSpace(text)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

// isArrayMismatch reports whether err is a json.UnmarshalTypeError caused by
// the decoder encountering a JSON array where an object was expected.
func isArrayMismatch(err error) bool {
	var te *json.UnmarshalTypeError
	if !errors.As(err, &te) {
		return false
	}
	return te.Value == "array"
}

// DecodeStructured decodes the answer to a schema-constrained request into
// out. A constrained answer is plain JSON, so none of unmarshalJSON's repairs
// apply: anything that does not decode is an *OutputError carrying the
// decoder's typed finding.
func DecodeStructured(text string, out any) error {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return &OutputError{Err: errors.New("empty answer"), Text: text}
	}
	if err := json.Unmarshal([]byte(trimmed), out); err != nil {
		return &OutputError{Err: err, Text: text}
	}
	return nil
}

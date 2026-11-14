package llm

import "testing"

type quality struct {
	Credibility   float64 `json:"credibility"`
	Actionability float64 `json:"actionability"`
	Novelty       float64 `json:"novelty"`
	Summary       string  `json:"summary"`
}

func TestUnmarshalJSON_Object(t *testing.T) {
	raw := `{"credibility":3,"actionability":2,"novelty":4,"summary":"ok"}`
	var got quality
	if err := unmarshalJSON(raw, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Credibility != 3 || got.Summary != "ok" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestUnmarshalJSON_SingleElementArray(t *testing.T) {
	raw := `[
  {
    "credibility": 3,
    "actionability": 2,
    "novelty": 4,
    "summary": "wrapped"
  }
]`
	var got quality
	if err := unmarshalJSON(raw, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Summary != "wrapped" {
		t.Fatalf("expected summary=wrapped, got %q", got.Summary)
	}
}

func TestUnmarshalJSON_CodeFencedObject(t *testing.T) {
	raw := "```json\n{\"credibility\":5,\"actionability\":4,\"novelty\":3,\"summary\":\"fenced\"}\n```"
	var got quality
	if err := unmarshalJSON(raw, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Credibility != 5 || got.Summary != "fenced" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestUnmarshalJSON_CodeFencedArray(t *testing.T) {
	raw := "```json\n[{\"credibility\":1,\"actionability\":1,\"novelty\":1,\"summary\":\"fenced-array\"}]\n```"
	var got quality
	if err := unmarshalJSON(raw, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Summary != "fenced-array" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestUnmarshalJSON_RepairsUnescapedHexSequencesInStrings(t *testing.T) {
	raw := `{
  "grounded": false,
  "issues": [
    "The brief suggests deploying a 'Sigma rule', whereas the source material is an Elastic rule defined in TOML format for use with EQL, not a Sigma rule.",
    "The brief defines specific detection logic using Sigma-style regex syntax ('CommandLine|re: (\\x[0-9a-fA-F]{2}){5,}') which is not present in the source material's EQL query.",
    "The brief includes a 'tests' section with specific positive and negative examples (e.g., 'printf \x65\x63\x68\x6f...') and expected telemetry/pass criteria that are not present in the source material."
  ]
}`
	var got struct {
		Grounded bool     `json:"grounded"`
		Issues   []string `json:"issues"`
	}
	if err := unmarshalJSON(raw, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Grounded {
		t.Fatal("expected grounded=false")
	}
	want := []string{
		"The brief suggests deploying a 'Sigma rule', whereas the source material is an Elastic rule defined in TOML format for use with EQL, not a Sigma rule.",
		`The brief defines specific detection logic using Sigma-style regex syntax ('CommandLine|re: (\x[0-9a-fA-F]{2}){5,}') which is not present in the source material's EQL query.`,
		`The brief includes a 'tests' section with specific positive and negative examples (e.g., 'printf \x65\x63\x68\x6f...') and expected telemetry/pass criteria that are not present in the source material.`,
	}
	if len(got.Issues) != len(want) {
		t.Fatalf("issues length = %d, want %d: %#v", len(got.Issues), len(want), got.Issues)
	}
	for i := range want {
		if got.Issues[i] != want[i] {
			t.Errorf("issues[%d] = %q, want %q", i, got.Issues[i], want[i])
		}
	}
}

func TestUnmarshalJSON_RepairsTrailingCommas(t *testing.T) {
	raw := `{
  "grounded": false,
  "issues": [
    "The source material does not contain information about 'session hijacking', 'unauthorized actions', or 'data exfiltration' as specific impacts of the vulnerability.",
    "The source material does not mention CPEs, specifically 'cpe:2.3:a:highsoft:highcharts_dashboards:*:*:*:*:*:*:*:*'.",
  ],
}`
	var got struct {
		Grounded bool     `json:"grounded"`
		Issues   []string `json:"issues"`
	}
	if err := unmarshalJSON(raw, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Grounded {
		t.Fatal("expected grounded=false")
	}
	want := []string{
		"The source material does not contain information about 'session hijacking', 'unauthorized actions', or 'data exfiltration' as specific impacts of the vulnerability.",
		"The source material does not mention CPEs, specifically 'cpe:2.3:a:highsoft:highcharts_dashboards:*:*:*:*:*:*:*:*'.",
	}
	if len(got.Issues) != len(want) {
		t.Fatalf("issues length = %d, want %d: %#v", len(got.Issues), len(want), got.Issues)
	}
	for i := range want {
		if got.Issues[i] != want[i] {
			t.Errorf("issues[%d] = %q, want %q", i, got.Issues[i], want[i])
		}
	}
}

func TestUnmarshalJSON_PreservesCommasInsideStrings(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "comma before closing bracket",
			raw:  `{"summary":"list: [a, b,]"}`,
			want: "list: [a, b,]",
		},
		{
			name: "comma before closing brace after escaped quote",
			raw:  `{"summary":"quote: \", }"}`,
			want: `quote: ", }`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got quality
			if err := unmarshalJSON(tt.raw, &got); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Summary != tt.want {
				t.Errorf("summary = %q, want %q", got.Summary, tt.want)
			}
		})
	}
}

func TestUnmarshalJSON_PreservesSupportedEscapeSemantics(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "escaped quote",
			raw:  `{"summary":"quote: \"ok\""}`,
			want: `quote: "ok"`,
		},
		{
			name: "even backslash run",
			raw:  `{"summary":"even: \\\\x31"}`,
			want: `even: \\x31`,
		},
		{
			name: "odd backslash run",
			raw:  `{"summary":"odd: \\\x31"}`,
			want: `odd: \\x31`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got quality
			if err := unmarshalJSON(tt.raw, &got); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Summary != tt.want {
				t.Errorf("summary = %q, want %q", got.Summary, tt.want)
			}
		})
	}
}

func TestUnmarshalJSON_RejectsOtherMalformedJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "invalid unicode escape", raw: `{"summary":"\u12G4"}`},
		{name: "truncated unicode escape", raw: `{"summary":"\u123"}`},
		{name: "unsupported escape outside string", raw: `{"summary":\x31}`},
		{name: "missing comma after repaired string", raw: `{"summary":"\x31" "credibility":3}`},
		{name: "missing closing brace after repaired string", raw: `{"summary":"\x31"`},
		{name: "comma in empty object", raw: `{,}`},
		{name: "comma in empty array", raw: `{"summary":"ok","issues":[,]}`},
		{name: "double trailing comma", raw: `{"summary":"ok",,}`},
		{name: "trailing comma after key", raw: `{"summary":,}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got quality
			if err := unmarshalJSON(tt.raw, &got); err == nil {
				t.Fatal("expected malformed JSON error")
			}
		})
	}
}

func TestUnmarshalJSON_EmptyArray(t *testing.T) {
	raw := `[]`
	var got quality
	if err := unmarshalJSON(raw, &got); err == nil {
		t.Fatal("expected error for empty array")
	}
}

func TestUnmarshalJSON_Invalid(t *testing.T) {
	raw := `not json`
	var got quality
	if err := unmarshalJSON(raw, &got); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

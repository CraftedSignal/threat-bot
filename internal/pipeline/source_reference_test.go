package pipeline

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEnsureInitialSourceReference(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  []string
	}{
		{"missing", "title: Example\n", []string{"https://source.example/advisory"}},
		{"empty", "title: Example\nreferences: []\n", []string{"https://source.example/advisory"}},
		{"existing", "title: Example\nreferences:\n  - https://other.example/report\n", []string{"https://other.example/report", "https://source.example/advisory"}},
		{"duplicate", "title: Example\nreferences:\n  - https://source.example/advisory\n", []string{"https://source.example/advisory"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotYAML, err := ensureInitialSourceReference(tc.input, "https://source.example/advisory")
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				References []string `yaml:"references"`
			}
			if err := yaml.Unmarshal([]byte(gotYAML), &got); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.References, tc.want) {
				t.Fatalf("references = %#v, want %#v", got.References, tc.want)
			}
		})
	}
}

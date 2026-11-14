package publicationprobe

import "testing"

func TestPublicationRequiredCheckProbe(t *testing.T) {
	t.Fatal("intentional failure to verify the protected external-fork PR check")
}

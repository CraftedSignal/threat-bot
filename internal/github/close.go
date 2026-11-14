package github

// discardClose releases a read resource or a resource on an already-failed
// path. Reads, Rows.Err and explicit commits determine operation success.
func discardClose(resource interface{ Close() error }) {
	_ = resource.Close()
}

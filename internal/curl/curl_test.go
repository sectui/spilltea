package curl

import (
	"testing"

	"github.com/sectui/spilltea/internal/message"
)

func TestFormat(t *testing.T) {
	req, err := message.ParseRequest([]byte("POST /a?b=1 HTTP/1.1\nHost: h.test\nAccept-Encoding: gzip\nContent-Length: 9\nX-A: it's\n\n{\"a\": 1}"), "https")
	if err != nil {
		t.Fatal(err)
	}
	want := "curl \\\n  -X 'POST' \\\n  'https://h.test/a?b=1' \\\n  -H 'X-A: it'\\''s' \\\n  --compressed \\\n  --data-binary '{\"a\": 1}'"
	if got := Format(req); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

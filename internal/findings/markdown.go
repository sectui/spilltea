package findings

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sectui/spilltea/internal/message"
	"github.com/sectui/spilltea/internal/project"
)

// Markdown has the finding's first request still stored.
func Markdown(p *project.Project, f project.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n- Detector: %s\n", f.Title, f.Detector)
	seen := fmt.Sprint(len(f.Entries))
	if f.Full() {
		seen += "+"
	}
	fmt.Fprintf(&b, "- Seen in %s requests, first on %s\n", seen, f.First.Local().Format("2006-01-02 15:04"))
	if f.Note != "" {
		fmt.Fprintf(&b, "- Note: %s\n", strings.ReplaceAll(f.Note, "\n", "\n  "))
	}
	b.WriteString("\n" + block("", f.Detail))
	for _, id := range f.Entries {
		req, err := p.ReadRequest(id)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "\n### Request #%d\n\n%s", id, block("http", capped(message.Text(req))))
		if resp, err := p.ReadResponse(id); err == nil && resp != nil {
			head, _ := message.Split(resp)
			fmt.Fprintf(&b, "\n### Response #%d\n\n%s", id, block("http", message.Text(head)))
		}
		break
	}
	return b.String()
}

func capped(s string) string {
	if len(s) > 4096 {
		return s[:4096] + "\n[...]"
	}
	return s
}

var backticks = regexp.MustCompile("`{3,}")

// block uses a fence longer than any run of backticks in s.
func block(lang, s string) string {
	fence := "```"
	for _, run := range backticks.FindAllString(s, -1) {
		if len(run) >= len(fence) {
			fence = strings.Repeat("`", len(run)+1)
		}
	}
	return fence + lang + "\n" + strings.TrimRight(s, "\n") + "\n" + fence + "\n"
}

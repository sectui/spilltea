package findings

import (
	"bytes"
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/html"

	"github.com/sectui/spilltea/internal/message"
)

type Reflection struct{}

func (Reflection) Name() string { return "reflection" }

type param struct{ name, value string }

func (Reflection) Detect(req *message.Request, resp *message.Response) []Hit {
	if req == nil || resp == nil || len(resp.Body) == 0 {
		return nil
	}
	if mime := message.Mime(resp.Header.Get("Content-Type")); mime != "text/html" && mime != "application/xhtml+xml" {
		return nil
	}
	where := req.URL.Host + req.URL.EscapedPath()
	var hits []Hit
	seen := map[string]bool{}
	for _, p := range params(req) {
		if seen[p.name] || boring(p.value) || !bytes.Contains(resp.Body, []byte(p.value)) {
			continue
		}
		ctx := contexts(resp.Body, p.value)
		if len(ctx) == 0 {
			continue
		}
		seen[p.name] = true
		i := bytes.Index(resp.Body, []byte(p.value))
		hits = append(hits, Hit{
			Key:    where + ":" + p.name,
			Title:  p.name + " reflected in " + strings.Join(ctx, ", "),
			Detail: where + "\n" + p.name + "=" + short(p.value) + "\n\n" + around(resp.Body, []int{i, i + len(p.value)}),
		})
	}
	return hits
}

func params(req *message.Request) []param {
	var out []param
	add := func(v url.Values) {
		for name, vs := range v {
			for _, s := range vs {
				out = append(out, param{name, s})
			}
		}
	}
	add(req.URL.Query())
	switch message.Mime(req.Header.Get("Content-Type")) {
	case "application/x-www-form-urlencoded":
		if v, err := url.ParseQuery(string(req.Body)); err == nil {
			add(v)
		}
	case "application/json":
		var v any
		if json.Unmarshal(req.Body, &v) == nil {
			walkJSON("", v, &out)
		}
	}
	slices.SortFunc(out, func(a, b param) int { return strings.Compare(a.name, b.name) })
	return out
}

func walkJSON(name string, v any, out *[]param) {
	switch v := v.(type) {
	case string:
		*out = append(*out, param{name, v})
	case map[string]any:
		for k, x := range v {
			walkJSON(strings.TrimPrefix(name+"."+k, "."), x, out)
		}
	case []any:
		for _, x := range v {
			walkJSON(name, x, out)
		}
	}
}

var boringValues = []string{"true", "false", "null", "undefined", "none", "asc", "desc"}

func boring(v string) bool {
	if len(v) < 4 || slices.Contains(boringValues, strings.ToLower(v)) {
		return true
	}
	return !strings.ContainsFunc(v, func(r rune) bool { return r < '0' || r > '9' })
}

// Data blobs of Next.js, Nuxt and the like hold the whole URL.
var dataScripts = []string{"self.__next_f", "window.__NUXT__", "__NUXT_DATA__", "window.__INITIAL_STATE__"}

func contexts(body []byte, value string) []string {
	var out []string
	add := func(c string) {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	inScript, dataScript, inStyle := false, false, false
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return out
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			switch t.Data {
			case "script":
				inScript = tt == html.StartTagToken
				dataScript = false
				for _, a := range t.Attr {
					if a.Key == "type" && strings.Contains(a.Val, "json") || a.Key == "id" && a.Val == "__NEXT_DATA__" {
						dataScript = true
					}
				}
			case "style":
				inStyle = tt == html.StartTagToken
			case "meta", "link":
				continue
			}
			for _, a := range t.Attr {
				if !strings.Contains(a.Val, value) {
					continue
				}
				switch {
				case strings.HasPrefix(a.Key, "on"):
					add("event handler")
				case slices.Contains([]string{"href", "src", "action", "formaction"}, a.Key):
					add(a.Key)
				default:
					add("attribute")
				}
			}
		case html.EndTagToken:
			switch t := z.Token(); t.Data {
			case "script":
				inScript, dataScript = false, false
			case "style":
				inStyle = false
			}
		case html.TextToken:
			text := string(z.Text())
			if !strings.Contains(text, value) {
				continue
			}
			switch {
			case inStyle:
			case inScript:
				trimmed := strings.TrimSpace(text)
				if !dataScript && !slices.ContainsFunc(dataScripts, func(d string) bool { return strings.HasPrefix(trimmed, d) }) {
					add("script")
				}
			default:
				add("text")
			}
		case html.CommentToken:
			if strings.Contains(string(z.Text()), value) {
				add("comment")
			}
		}
	}
}

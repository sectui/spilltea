package project

import (
	"testing"
	"time"
)

func TestFindings(t *testing.T) {
	root := t.TempDir()
	p, _ := Open(root)
	see := func(key string, entry int) bool { return sight(t, p, key, entry) }
	if !see("a", 1) || !see("a", 2) || see("a", 2) || !see("b", 2) {
		t.Fatal("a new entry is a change, the same one is not")
	}
	for i := 3; i < MaxSightings+5; i++ {
		see("a", i)
	}
	if err := p.SetTriage("b", Triage{Status: StatusNoise, Note: "test key"}); err != nil {
		t.Fatal(err)
	}
	if see("b", 9) {
		t.Fatal("a triaged finding is not updated")
	}
	if got := p.FindingsOf(2); len(got) != 2 || got[0].Key != "a" || got[1].Key != "b" {
		t.Fatalf("FindingsOf(2) = %+v", got)
	}
	p.Close()

	q, _ := Open(root)
	fs, err := q.Findings()
	if err != nil || len(fs) != 2 {
		t.Fatalf("%v, %v", fs, err)
	}
	if a := fs[0]; a.Key != "a" || len(a.Entries) != MaxSightings || !a.Full() || a.Entries[1] != 2 || a.Status != StatusNew {
		t.Fatalf("a: %+v", a)
	}
	if b := fs[1]; b.Status != StatusNoise || b.Note != "test key" || len(b.Entries) != 1 {
		t.Fatalf("b: %+v", b)
	}
	if err := q.SetTriage("b", Triage{}); err != nil {
		t.Fatal(err)
	}
	if !sight(t, q, "b", 9) {
		t.Fatal("back to new, it is updated again")
	}
}

func sight(t *testing.T, p *Project, key string, entry int) bool {
	t.Helper()
	ok, err := p.AddSighting(Sighting{Key: key, Detector: "secrets", Title: "t " + key, Entry: entry, Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

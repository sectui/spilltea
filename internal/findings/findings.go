// Package findings runs detectors on the traffic and stores what they find.
package findings

import (
	"sync"
	"time"

	"github.com/sectui/spilltea/internal/config"
	"github.com/sectui/spilltea/internal/message"
	"github.com/sectui/spilltea/internal/project"
)

type Hit struct {
	Key    string
	Title  string
	Detail string
}

// resp may be nil.
type Detector interface {
	Name() string
	Detect(req *message.Request, resp *message.Response) []Hit
}

func Detectors(cfg config.Findings) ([]Detector, error) {
	var out []Detector
	if cfg.Secrets {
		d, err := NewSecrets()
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if cfg.Cookies {
		out = append(out, Cookies{})
	}
	if cfg.CORS {
		out = append(out, CORS{})
	}
	if cfg.Disclosure {
		out = append(out, Disclosure{})
	}
	return out, nil
}

type job struct {
	entry int
	req   *message.Request
	resp  *message.Response
}

const queueSize = 256

type Scanner struct {
	p    *project.Project
	ds   []Detector
	jobs chan job
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// changed is called from the scanner's goroutine.
func New(p *project.Project, ds []Detector, changed func(error)) *Scanner {
	s := &Scanner{p: p, ds: ds, jobs: make(chan job, queueSize), stop: make(chan struct{}), done: make(chan struct{})}
	go s.run(changed)
	return s
}

// Scan returns false when the queue is full.
func (s *Scanner) Scan(entry int, req *message.Request, resp *message.Response) bool {
	select {
	case s.jobs <- job{entry, req, resp}:
		return true
	default:
		return false
	}
}

func (s *Scanner) Close() {
	s.once.Do(func() { close(s.stop) })
	<-s.done
}

func (s *Scanner) run(changed func(error)) {
	defer close(s.done)
	for {
		var j job
		select {
		case j = <-s.jobs:
		case <-s.stop:
			return
		}
		found := false
		for _, d := range s.ds {
			for _, h := range d.Detect(j.req, j.resp) {
				ok, err := s.p.AddSighting(project.Sighting{Key: d.Name() + ":" + h.Key, Detector: d.Name(),
					Title: h.Title, Detail: h.Detail, Entry: j.entry, Time: time.Now()})
				if err != nil {
					changed(err)
				}
				found = found || ok
			}
		}
		if found {
			changed(nil)
		}
	}
}

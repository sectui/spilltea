// Package scan hands the recorded messages to handlers, in the background.
package scan

import (
	"sync"

	"github.com/sectui/spilltea/internal/message"
	"github.com/sectui/spilltea/internal/project"
)

// Handle is called from the scanner's goroutine. resp may be nil.
type Handler interface {
	Handle(e project.Entry, req *message.Request, resp *message.Response)
}

type job struct {
	e    project.Entry
	req  *message.Request
	resp *message.Response
}

const queueSize = 256

type Scanner struct {
	hs   []Handler
	jobs chan job
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func New(hs ...Handler) *Scanner {
	s := &Scanner{hs: hs, jobs: make(chan job, queueSize), stop: make(chan struct{}), done: make(chan struct{})}
	go s.run()
	return s
}

// Scan returns false when the queue is full.
func (s *Scanner) Scan(e project.Entry, req *message.Request, resp *message.Response) bool {
	select {
	case s.jobs <- job{e, req, resp}:
		return true
	default:
		return false
	}
}

func (s *Scanner) Close() {
	s.once.Do(func() { close(s.stop) })
	<-s.done
}

func (s *Scanner) run() {
	defer close(s.done)
	for {
		select {
		case j := <-s.jobs:
			for _, h := range s.hs {
				h.Handle(j.e, j.req, j.resp)
			}
		case <-s.stop:
			return
		}
	}
}

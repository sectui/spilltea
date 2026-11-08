package ui

import (
	tea "charm.land/bubbletea/v2"

	"github.com/sectui/foam/theme"

	"github.com/sectui/spilltea/internal/config"
	"github.com/sectui/spilltea/internal/project"
	"github.com/sectui/spilltea/internal/proxy"
)

func Run(cfg *config.Config) error {
	theme.Set(cfg.Theme)
	open := project.Open
	if !cfg.App.CreateProject {
		open = project.OpenExisting
	}
	proj, err := open(cfg.App.Project)
	if err != nil {
		return err
	}
	px, err := proxy.New(cfg, proj)
	if err != nil {
		return err
	}
	m, err := New(cfg, proj, px)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := px.Start(); err != nil {
		return err
	}
	_, err = tea.NewProgram(m).Run()
	return err
}

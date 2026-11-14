package main

import (
	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/publisher"
)

func publicationSettings(cfg *config.Config) publisher.PublisherOption {
	return publisher.WithPublicationSettings(publisher.PublicationSettings{
		SiteURL: cfg.Publish.SiteURL, Branch: cfg.Publish.Branch,
		AuthorName: cfg.Publish.AuthorName, AuthorEmail: cfg.Publish.AuthorEmail,
	})
}

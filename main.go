package main

import (
	"context"
	"github.com/Khan/genqlient/graphql"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"github.com/chitoku-k/cloudflare-exporter/application/server"
	"github.com/chitoku-k/cloudflare-exporter/infrastructure/cloudflare"
	"github.com/chitoku-k/cloudflare-exporter/infrastructure/config"
	cf "github.com/cloudflare/cloudflare-go"
)

var signals = []os.Signal{os.Interrupt}

type authedTransport struct {
	wrapped http.RoundTripper
	api     api
}

type api struct {
	APIKey   string
	APIEmail string
	APIToken string
	AuthType int
}

func (t *authedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.api.AuthType&cf.AuthKeyEmail != 0 {
		req.Header.Set("X-Auth-Key", t.api.APIKey)
		req.Header.Set("X-Auth-Email", t.api.APIEmail)
	}
	if t.api.AuthType&cf.AuthToken != 0 {
		req.Header.Set("Authorization", "Bearer "+t.api.APIToken)
	}
	return t.wrapped.RoundTrip(req)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), signals...)
	defer stop()

	env, err := config.Get()
	if err != nil {
		slog.Error("Failed to initialize config", "err", err)
		os.Exit(1)
	}
	httpClient := http.DefaultClient
	var authType int
	var client *cf.API
	if env.Cloudflare.APIToken == "" {
		client, err = cf.New(env.Cloudflare.APIKey, env.Cloudflare.APIEmail, cf.HTTPClient(httpClient))
		authType = cf.AuthKeyEmail
	} else {
		client, err = cf.NewWithAPIToken(env.Cloudflare.APIToken, cf.HTTPClient(httpClient))
		authType = cf.AuthToken
	}

	if err != nil {
		slog.Error("Failed to initialize Cloudflare client", "err", err)
		os.Exit(1)
	}
	var rc *cf.ResourceContainer
	if env.Cloudflare.AccountID == "" {
		rc = cf.UserIdentifier("")
	} else {
		rc = cf.AccountIdentifier(env.Cloudflare.AccountID)
	}
	zoneIds, err := cloudflare.GetZoneIds(ctx, client)
	if err != nil {
		slog.Error("", err)
		os.Exit(1)
	}
	graphqlClient := graphql.NewClient(
		"https://api.cloudflare.com/client/v4/graphql/",
		&http.Client{
			Transport: &authedTransport{
				wrapped: http.DefaultTransport,
				api: api{
					env.Cloudflare.APIKey,
					env.Cloudflare.APIEmail,
					env.Cloudflare.APIToken,
					authType,
				},
			},
		})
	engine := server.NewEngine(
		env.Port,
		env.TLSCert,
		env.TLSKey,
		cloudflare.NewLoadBalancerService(client, rc),
		zoneIds,
		graphqlClient,
		env.Cloudflare.ScrapeDelay,
	)
	err = engine.Start(ctx)
	if err != nil {
		slog.Error("Failed to start web server", "err", err)
		os.Exit(1)
	}
}

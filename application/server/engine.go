package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	"github.com/chitoku-k/cloudflare-exporter/infrastructure/analytics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chitoku-k/cloudflare-exporter/service"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
)

type engine struct {
	Client       graphql.Client
	LoadBalancer service.LoadBalancer
	ZoneIds      map[string]string
	ScrapeDelay  int
	Port         string
	CertFile     string
	KeyFile      string
}

type Engine interface {
	Start(ctx context.Context) error
}

func NewEngine(
	port string,
	certFile string,
	keyFile string,
	loadBalancer service.LoadBalancer,
	zoneIds map[string]string,
	client graphql.Client,
	scrapeDelay int,
) Engine {
	return &engine{
		Port:         port,
		CertFile:     certFile,
		KeyFile:      keyFile,
		LoadBalancer: loadBalancer,
		ZoneIds:      zoneIds,
		Client:       client,
		ScrapeDelay:  scrapeDelay,
	}
}

func (e *engine) findZoneName(id string) string {
	for zoneName, zoneId := range e.ZoneIds {
		if zoneId == id {
			return zoneName
		}
	}

	return ""
}
func (e *engine) Start(ctx context.Context) error {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Formatter: e.Formatter(),
		SkipPaths: []string{"/healthz"},
	}))

	router.Any("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	router.GET("/metrics", func(c *gin.Context) {
		health := prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "cloudflare",
			Name:      "origin_health",
			Help:      "Result of health check",
		}, []string{"pool_name", "health_region", "origin_address", "code"})

		rtt := prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "cloudflare",
			Name:      "origin_rtt_seconds",
			Help:      "RTT to the pool origin",
		}, []string{"pool_name", "health_region", "origin_address", "code"})

		poolReq := prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "cloudflare",
			Name:      "pool_requests_total",
			Help:      "Requests per pool",
		}, []string{"zone", "load_balancer_name", "pool_name", "origin_name"})

		zoneReq := prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "cloudflare",
			Name:      "zone_requests_status_country_host",
			Help:      "Count of not cached requests for zone per origin HTTP status per country per host",
		}, []string{"zone", "status", "country", "host", "cache"})

		now := time.Now().Add(-time.Duration(e.ScrapeDelay*100) * time.Second).Truncate(60 * time.Second).UTC()
		now1mAgo := now.Add(-60 * time.Second)

		defer func() {
			registry := prometheus.NewRegistry()
			registry.MustRegister(health, rtt, poolReq, zoneReq)
			handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
			handler.ServeHTTP(c.Writer, c.Request)
		}()
		pool, okP := c.GetQuery("pool")
		target, okT := c.GetQuery("target")
		queryZone, okZ := c.GetQuery("zone")
		if !okP || !okT || !okZ {
			c.Status(http.StatusBadRequest)
			return
		}
		poolNames := strings.Split(pool, ",")
		pools, err := e.LoadBalancer.Collect(c, poolNames)
		if err != nil {
			slog.Error("Error in Cloudflare", "err", err)
			c.Status(http.StatusInternalServerError)
			return
		}

		for _, p := range pools {
			for _, h := range p.PopHealths {
				for _, o := range h.Origins {
					var value float64
					if o.Healthy {
						value = 1
					}

					labels := prometheus.Labels{
						"pool_name":      p.Name,
						"health_region":  h.Region,
						"origin_address": o.Address,
						"code":           fmt.Sprint(o.ResponseCode),
					}
					health.With(labels).Set(value)
					rtt.With(labels).Set(o.RTT.Seconds())
				}
			}
		}
		zoneIDs := []string{}
		for _, zone := range strings.Split(queryZone, ",") {
			if zoneId, ok := e.ZoneIds[zone]; ok {
				zoneIDs = append(zoneIDs, zoneId)
			}
		}
		if len(zoneIDs) == 0 {
			return
		}
		hosts := strings.Split(target, ",")
		if resp, err := analytics.FetchZoneTotals(c, e.Client, zoneIDs, poolNames, hosts, now1mAgo, now, 1000); err == nil {
			for _, zone := range resp.Viewer.GetZones() {
				for _, g := range zone.LoadBalancingRequestsAdaptiveGroups {
					poolReq.WithLabelValues(
						e.findZoneName(zone.ZoneTag),
						g.Dimensions.LbName,
						g.Dimensions.SelectedPoolName,
						g.Dimensions.SelectedOriginName,
					).Add(float64(g.Count))
				}
				for _, g := range zone.HttpRequestsAdaptiveGroups {
					zoneReq.WithLabelValues(
						e.findZoneName(zone.ZoneTag),
						strconv.Itoa(int(g.Dimensions.EdgeResponseStatus)),
						g.Dimensions.ClientCountryName,
						g.Dimensions.ClientRequestHTTPHost,
						g.Dimensions.CacheStatus,
					).Add(float64(g.Count))
				}
			}
			slog.Info("FetchZoneTotals zoneIDs: ", zoneIDs, "e.ZoneIds", e.ZoneIds, "resp", resp)
		}
	})

	server := http.Server{
		Addr:    net.JoinHostPort("", e.Port),
		Handler: router,
	}

	var eg errgroup.Group
	eg.Go(func() error {
		<-ctx.Done()
		return server.Shutdown(context.Background())
	})

	var err error
	if e.CertFile != "" && e.KeyFile != "" {
		server.TLSConfig = &tls.Config{
			GetCertificate: e.getCertificate,
		}
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}

	if err == http.ErrServerClosed {
		return eg.Wait()
	}

	return err
}

func (e *engine) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(e.CertFile, e.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return &cert, nil
}

func (e *engine) Formatter() gin.LogFormatter {
	return func(param gin.LogFormatterParams) string {
		remoteHost, _, err := net.SplitHostPort(param.Request.RemoteAddr)
		if remoteHost == "" || err != nil {
			remoteHost = "-"
		}

		bodySize := fmt.Sprintf("%v", param.BodySize)
		if param.BodySize == 0 {
			bodySize = "-"
		}

		referer := param.Request.Header.Get("Referer")
		if referer == "" {
			referer = "-"
		}

		userAgent := param.Request.Header.Get("User-Agent")
		if userAgent == "" {
			userAgent = "-"
		}

		forwardedFor := param.Request.Header.Get("X-Forwarded-For")
		if forwardedFor == "" {
			forwardedFor = "-"
		}

		return fmt.Sprintf(`%s %s %s [%s] "%s %s %s" %v %s "%s" "%s" "%s"%s`,
			remoteHost,
			"-",
			"-",
			param.TimeStamp.Format("02/Jan/2006:15:04:05 -0700"),
			param.Request.Method,
			param.Request.RequestURI,
			param.Request.Proto,
			param.StatusCode,
			bodySize,
			referer,
			userAgent,
			forwardedFor,
			"\n",
		)
	}
}

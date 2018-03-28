package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	log "github.com/Sirupsen/logrus"
	_ "github.com/lib/pq"

	"github.com/patrickmn/go-cache"
	"github.com/urfave/cli"
	"golang.org/x/crypto/blowfish"
)

var (
	version   string
	builddate string
	logger    *log.Logger
)

var hexReg, _ = regexp.Compile("[^a-fA-F0-9]+")

func main2(galaxyDb, galaxySecret, listenAddr, connect, header, statsd_address, statsd_prefix string, looseCookie bool) {
	db, err := sql.Open("postgres", galaxyDb)
	if err != nil {
		log.Fatal("Could not connect: %s", err)
	}

	// Setup metrics stuff
	configure_metrics(statsd_address, statsd_prefix)

	bf, err := blowfish.NewCipher([]byte(galaxySecret))
	if err != nil {
		log.Fatal(err)
	}

	var query_string string
	if looseCookie {
		// If we are being loose in our session cookie acceptance
		query_string = LOOSE_QUERY_STRING
	} else {
		// Otherwise, be strict by default.
		query_string = STRICT_QUERY_STRING
	}

	// and finally, extract frontends

	mux := http.NewServeMux()

	var request_handler http.Handler = &ProxyHandler{
		Transport: &http.Transport{
			DisableKeepAlives:  false,
			DisableCompression: false,
		},
		// Frontend
		AddForwarded: true,
		// Backend
		BackendScheme:  "http",
		BackendAddress: connect,
		GalaxyDB:       db,
		GalaxyCipher:   bf,
		Cache:          cache.New(1*time.Hour, 5*time.Minute),
		EmailCache:     cache.New(1*time.Hour, 5*time.Minute),
		Header:         header,
		QueryString:    query_string,
	}

	if logger != nil {
		request_handler = NewRequestLogger(request_handler, *logger)
	}

	mux.Handle("/", request_handler)

	srv := &http.Server{Handler: mux, Addr: listenAddr}

	log.Printf("Listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("Starting proxy failed: %v", err)
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "gx-cookie-proxy"
	app.Usage = "Proxy requests, transparently determining galaxy user based on gxsession cookie and adding a REMOTE_USER header"
	app.Version = fmt.Sprintf("%s (%s)", version, builddate)

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "galaxyDb",
			Value:  "postgresql://galaxy:galaxy@localhost:32777/galaxy?client_encoding=utf8&sslmode=disable",
			Usage:  "Galaxy Database Address",
			EnvVar: "GALAXY_DB_URL",
		},
		cli.StringFlag{
			Name:   "galaxySecret",
			Value:  "USING THE DEFAULT IS NOT SECURE!",
			Usage:  "Galaxy Secret",
			EnvVar: "GALAXY_SECRET",
		},
		cli.StringFlag{
			Name:   "listenAddr",
			Value:  "0.0.0.0:5000",
			Usage:  "Address to listen on",
			EnvVar: "GXC_LISTEN_ADDR",
		},
		cli.StringFlag{
			Name:   "connect",
			Value:  "localhost:8000",
			Usage:  "Backend URL.",
			EnvVar: "GXC_BACKEND_URL",
		},
		cli.StringFlag{
			Name:   "logLevel",
			Value:  "INFO",
			Usage:  "Log level, choose from (DEBUG, INFO, WARN, ERROR)",
			EnvVar: "GXC_LOGLEVEL",
		},
		cli.BoolFlag{
			Name:   "looseCookie",
			Usage:  "Require that a cookie is present but do not require that is_valid=True. This will allow people with expired Galaxy session cookies to access apollo. Probably provides better UX? Not sure of security implications.",
			EnvVar: "GXC_LOOSE_COOKIE",
		},
		cli.StringFlag{
			Name:   "header",
			Value:  "REMOTE_USER",
			Usage:  "Customize the HTTP Header (for those picky applications)",
			EnvVar: "GXC_HEADER",
		},
		cli.StringFlag{
			Name:   "statsd_address",
			Value:  "",
			Usage:  "Set this if you wish to send data to statsd somewhere",
			EnvVar: "GXC_STATSD",
		},
		cli.StringFlag{
			Name:   "statsd_prefix",
			Value:  "gxc.",
			Usage:  "statsd statistics prefix.",
			EnvVar: "GXC_STATSD_PREFIX",
		},
		cli.BoolFlag{
			Name:   "statsd_influxdb",
			Usage:  "Format statsd output to be compatible with influxdb/telegraf",
			EnvVar: "GXC_STATSD_INFLUXDB",
		},
	}

	app.Action = func(c *cli.Context) {

		// Output to stdout instead of the default stderr, could also be a file.
		log.SetOutput(os.Stdout)
		// Only log the warning severity or above.
		if c.String("logLevel") == "DEBUG" {
			log.SetLevel(log.DebugLevel)
		} else if c.String("logLevel") == "INFO" {
			log.SetLevel(log.InfoLevel)
		} else if c.String("logLevel") == "WARN" {
			log.SetLevel(log.WarnLevel)
		} else if c.String("logLevel") == "ERROR" {
			log.SetLevel(log.ErrorLevel)
		} else {
			panic("Unknown log level")
		}

		statsd_influxdb = c.Bool("statsd_influxdb")

		main2(
			c.String("galaxyDb"),
			c.String("galaxySecret"),
			c.String("listenAddr"),
			c.String("connect"),
			c.String("header"),
			c.String("statsd_address"),
			c.String("statsd_prefix"),
			c.Bool("looseCookie"),
		)
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

package main

import (
	"bufio"
	"database/sql"
	"github.com/patrickmn/go-cache"
	"github.com/urfave/cli"
	"regexp"
	"time"

	"encoding/hex"
	"fmt"
	log "github.com/Sirupsen/logrus"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/blowfish"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

var (
	// Require a valid cookie.
	STRICT_QUERY_STRING = `
SELECT galaxy_user.email
FROM galaxy_session, galaxy_user
WHERE galaxy_user.id = galaxy_session.user_id and galaxy_session.session_key=$1
AND is_valid = true`
	// Accept an outdated / superceded one.
	LOOSE_QUERY_STRING = `
SELECT galaxy_user.email
FROM galaxy_session, galaxy_user
WHERE galaxy_user.id = galaxy_session.user_id and galaxy_session.session_key=$1`
)

var (
	version   string
	builddate string
	logger    *log.Logger
)

type Backend struct {
	Name          string
	ConnectString string
	GalaxyDB      *sql.DB
	GalaxyCipher  *blowfish.Cipher
	Cache         *cache.Cache
	QueryString   string
	Header        string
}

var hexReg, _ = regexp.Compile("[^a-fA-F0-9]+")

type Frontend struct {
	Name         string
	BindString   string
	HTTPS        bool
	AddForwarded bool
	Hosts        []string
	Backends     []string
	KeyFile      string
	CertFile     string
}

func Copy(dest *bufio.ReadWriter, src *bufio.ReadWriter) {
	buf := make([]byte, 40*1024)
	for {
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			log.Printf("Read failed: %v", err)
			return
		}
		if n == 0 {
			return
		}
		dest.Write(buf[0:n])
		dest.Flush()
	}
}

func CopyBidir(conn1 io.ReadWriteCloser, rw1 *bufio.ReadWriter, conn2 io.ReadWriteCloser, rw2 *bufio.ReadWriter) {
	finished := make(chan bool)

	go func() {
		Copy(rw2, rw1)
		conn2.Close()
		finished <- true
	}()
	go func() {
		Copy(rw1, rw2)
		conn1.Close()
		finished <- true
	}()

	<-finished
	<-finished
}

type RequestHandler struct {
	Transport    *http.Transport
	Frontend     *Frontend
	HostBackends map[string]chan *Backend
	Backends     chan *Backend
	Header       string
}

func (h *RequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//log.Printf("incoming request: %#v", *r)
	r.RequestURI = ""
	r.URL.Scheme = "http"

	if h.Frontend.AddForwarded {
		remote_addr := r.RemoteAddr
		idx := strings.LastIndex(remote_addr, ":")
		if idx != -1 {
			remote_addr = remote_addr[0:idx]
			if remote_addr[0] == '[' && remote_addr[len(remote_addr)-1] == ']' {
				remote_addr = remote_addr[1 : len(remote_addr)-1]
			}
		}
		r.Header.Add("X-Forwarded-For", remote_addr)
	}

	var backend *Backend
	if len(h.Frontend.Hosts) == 0 {
		backend = <-h.Backends
		r.URL.Host = backend.ConnectString
		h.Backends <- backend
	} else {
		backend_list := h.HostBackends[r.Host]
		if backend_list == nil {
			if len(h.Frontend.Backends) == 0 {
				http.Error(w, "no suitable backend found for request", http.StatusServiceUnavailable)
				return
			} else {
				backend = <-h.Backends
				r.URL.Host = backend.ConnectString
				h.Backends <- backend
			}
		} else {
			backend = <-backend_list
			r.URL.Host = backend.ConnectString
			backend_list <- backend
		}
	}

	conn_hdr := ""
	conn_hdrs := r.Header["Connection"]

	if len(conn_hdrs) > 0 {
		log.WithFields(log.Fields{
			"headers": conn_hdrs,
		}).Debug("Connection headers")
		conn_hdr = conn_hdrs[0]
	}

	var email = ""
	gx_cookie, err := r.Cookie("galaxysession")
	if err == nil {
		email, _ = lookupEmailByCookie(backend, gx_cookie.String())
		if email != "" {
			r.Header[h.Header] = []string{email}

			log.WithFields(log.Fields{
				"user": email,
				"path": r.URL.Path,
			}).Info("Authenticated request")
		} else {
			log.Info("Unauthenticated request")
		}
	} else {
		log.Error(err)
		w.WriteHeader(http.StatusBadRequest)
	}

	upgrade_websocket := false
	if strings.ToLower(conn_hdr) == "upgrade" {
		log.Debug("got Connection: Upgrade")

		upgrade_hdrs := r.Header["Upgrade"]
		//log.Printf("Upgrade headers: %v", upgrade_hdrs)
		if len(upgrade_hdrs) > 0 {
			upgrade_websocket = (strings.ToLower(upgrade_hdrs[0]) == "websocket")
		}
	}

	if upgrade_websocket {
		hj, ok := w.(http.Hijacker)

		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}

		conn, bufrw, err := hj.Hijack()
		defer conn.Close()

		conn2, err := net.Dial("tcp", r.URL.Host)
		if err != nil {
			http.Error(w, "couldn't connect to backend server", http.StatusServiceUnavailable)
			return
		}
		defer conn2.Close()

		err = r.Write(conn2)
		if err != nil {
			log.Printf("writing WebSocket request to backend server failed: %v", err)
			return
		}

		CopyBidir(conn, bufrw, conn2, bufio.NewReadWriter(bufio.NewReader(conn2), bufio.NewWriter(conn2)))

	} else {

		resp, err := h.Transport.RoundTrip(r)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "Error: %v", err)
			return
		}

		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}

		w.WriteHeader(resp.StatusCode)

		io.Copy(w, resp.Body)
		resp.Body.Close()
	}
}

func lookupEmailByCookie(b *Backend, cookie string) (string, bool) {
	cachedEmail, found := b.Cache.Get(cookie[14:])
	log.WithFields(log.Fields{
		"hit": found,
	}).Debug("Cache hit")
	if found {
		return cachedEmail.(string), found
	}

	data, err := hex.DecodeString(cookie[14:])
	pt := make([]byte, 40)
	for i := 0; i < len(data); i += blowfish.BlockSize {
		j := i + blowfish.BlockSize
		b.GalaxyCipher.Decrypt(pt[i:j], data[i:j])
	}
	session_key := strings.Replace(string(pt), "!", "", -1)
	safe_session_key := hexReg.ReplaceAllString(session_key, "")
	log.WithFields(log.Fields{
		"sk": safe_session_key,
	}).Debug("Session Key Decoded")

	var email string

	err = b.GalaxyDB.QueryRow(b.QueryString, safe_session_key).Scan(&email)

	if err != nil {
		if fmt.Sprintf("%s", err) == "sql: no rows in result set" {
			log.Info("Invalid session key / cookie")
		} else {
			log.Error(err)
		}
		return "", false
	}
	log.WithFields(log.Fields{
		"email": email,
	}).Debug("Invalid session key / cookie")

	b.Cache.Set(cookie[14:], email, cache.DefaultExpiration)
	return email, false
}

func main2(galaxyDb, galaxySecret, listenAddr, connect, header string, looseCookie bool) {
	db, err := sql.Open("postgres", galaxyDb)
	if err != nil {
		log.Fatal("Could not connect: %s", err)
	}

	bf, err := blowfish.NewCipher([]byte(galaxySecret))
	if err != nil {
		log.Fatal(err)
	}

	backend := &Backend{
		Name:          "default_b",
		ConnectString: connect,
		GalaxyDB:      db,
		GalaxyCipher:  bf,
		Cache:         cache.New(1*time.Hour, 5*time.Minute),
		Header:        header,
	}

	if looseCookie {
		// If we are being loose in our session cookie acceptance
		backend.QueryString = LOOSE_QUERY_STRING
	} else {
		// Otherwise, be strict by default.
		backend.QueryString = STRICT_QUERY_STRING
	}

	// and finally, extract frontends
	frontend := &Frontend{
		Name:         "default_f",
		BindString:   listenAddr,
		Backends:     []string{"default_b"},
		AddForwarded: true,
	}

	exit_chan := make(chan int)
	go func(fe *Frontend) {
		fe.Start(backend)
		exit_chan <- 1
	}(frontend)

	// this shouldn't return
	<-exit_chan
}

func (f *Frontend) Start(backend *Backend) {
	mux := http.NewServeMux()

	hosts_chans := make(map[string]chan *Backend)

	backends_chan := make(chan *Backend, 1)
	backends_chan <- backend

	var request_handler http.Handler = &RequestHandler{
		Transport: &http.Transport{
			DisableKeepAlives:  false,
			DisableCompression: false,
		},
		Frontend:     f,
		HostBackends: hosts_chans,
		Backends:     backends_chan,
		Header:       backend.Header,
	}

	if logger != nil {
		request_handler = NewRequestLogger(request_handler, *logger)
	}

	mux.Handle("/", request_handler)

	srv := &http.Server{Handler: mux, Addr: f.BindString}

	log.Printf("Listening on %s", f.BindString)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("Starting frontend %s failed: %v", f.Name, err)
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

		main2(
			c.String("galaxyDb"),
			c.String("galaxySecret"),
			c.String("listenAddr"),
			c.String("connect"),
			c.String("header"),
			c.Bool("looseCookie"),
		)
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

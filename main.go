package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	texttemplate "text/template"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"gopkg.in/alecthomas/kingpin.v2"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

const (
	usernameRegexp         = `^([a-zA-Z0-9_.\-@])+$`
	usernameMaxLength      = 64
	passwordMinLength      = 6
	passwordMaxLength      = 128
	certsArchiveFileName   = "certs.tar.gz"
	ccdArchiveFileName     = "ccd.tar.gz"
	indexTxtDateLayout     = "060102150405Z"
	stringDateFormat       = "2006-01-02 15:04:05"
	downloadCertsApiUrl    = "api/data/certs/download"
	downloadCcdApiUrl      = "api/data/ccd/download"
	labelKeyIndexTxt       = "index.txt"
	labelKeyType           = "type"
	labelKeyName           = "name"
	labelKeyManagedBy      = "app.kubernetes.io/managed-by"
	labelValueClientAuth   = "clientAuth"
	labelValueManagedByApp = "ovpn-admin"
	prefixStaticRoute      = "ifconfig-push"

	kubeNamespaceFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	// The management interface is now consulted while serving a request, so both the
	// connect and the read have to be bounded. mgmtRead stops only when it recognises a
	// sentinel in the reply, so a socket that accepts and then says nothing useful would
	// otherwise block the handler for ever.
	mgmtDialTimeout = 3 * time.Second
	// mgmtReadTimeout is an idle limit between reads, not a cap on the whole
	// reply; mgmtReadOverallTimeout is the cap, so a socket that keeps
	// trickling data cannot hold a handler forever.
	mgmtReadTimeout        = 3 * time.Second
	mgmtReadOverallTimeout = 30 * time.Second
	// authLogParseLimit bounds how many login-log entries one request parses.
	// Sized for a 60-90 user fleet where reconnects can write a few thousand
	// lines a day: deep enough that a quiet user's last login stays visible,
	// while both size-capped generations together stay a few-millisecond parse.
	authLogParseLimit = 50000
)

var (
	listenHost               = kingpin.Flag("listen.host", "host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	listenPort               = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8080").Envar("OVPN_LISTEN_PORT").String()
	listenBaseUrl            = kingpin.Flag("listen.base-url", "base url for ovpn-admin").Default("/").Envar("OVPN_LISTEN_BASE_URL").String()
	serverRole               = kingpin.Flag("role", "server role, master or slave").Default("master").Envar("OVPN_ROLE").HintOptions("master", "slave").String()
	masterHost               = kingpin.Flag("master.host", "URL for the master server").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	masterBasicAuthUser      = kingpin.Flag("master.basic-auth.user", "user for master server's Basic Auth").Default("").Envar("OVPN_MASTER_USER").String()
	masterBasicAuthPassword  = kingpin.Flag("master.basic-auth.password", "password for master server's Basic Auth").Default("").Envar("OVPN_MASTER_PASSWORD").String()
	masterSyncFrequency      = kingpin.Flag("master.sync-frequency", "master host data sync frequency in seconds").Default("600").Envar("OVPN_MASTER_SYNC_FREQUENCY").Int()
	masterSyncToken          = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	openvpnNetwork           = kingpin.Flag("ovpn.network", "NETWORK/MASK_PREFIX for OpenVPN server").Default("172.16.100.0/24").Envar("OVPN_NETWORK").String()
	openvpnServer            = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("127.0.0.1:7777:tcp").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	openvpnServerBehindLB    = kingpin.Flag("ovpn.server.behindLB", "enable if your OpenVPN server is behind Kubernetes Service having the LoadBalancer type").Default("false").Envar("OVPN_LB").Bool()
	openvpnServiceName       = kingpin.Flag("ovpn.service", "the name of Kubernetes Service having the LoadBalancer type if your OpenVPN server is behind it").Default("openvpn-external").Envar("OVPN_LB_SERVICE").Strings()
	mgmtAddress              = kingpin.Flag("mgmt", "ALIAS=HOST:PORT for OpenVPN server mgmt interface; can have multiple values").Default("main=127.0.0.1:8989").Envar("OVPN_MGMT").Strings()
	metricsPath              = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaDirPath           = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("./easyrsa").Envar("EASYRSA_PATH").String()
	indexTxtPath             = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file").Default("").Envar("OVPN_INDEX_PATH").String()
	easyrsaBinPath           = kingpin.Flag("easyrsa.bin-path", "path to easyrsa script").Default("easyrsa").Envar("EASYRSA_BIN_PATH").String()
	authLogPath              = kingpin.Flag("auth.log-path", "path to the login attempt log written by auth.sh").Default("").Envar("OVPN_AUTH_LOG_PATH").String()
	ccdEnabled               = kingpin.Flag("ccd", "enable client-config-dir").Default("false").Envar("OVPN_CCD").Bool()
	ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	ccdTemplatePath          = kingpin.Flag("templates.ccd-path", "path to custom ccd.tpl").Default("").Envar("OVPN_TEMPLATES_CCD_PATH").String()
	authByPassword           = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase             = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	authDataBaseInit         = kingpin.Flag("auth.db-init", "enable database initialization if db user not exists or size is 0").Default("false").Envar("OVPN_AUTH_DB_INIT").Bool()
	logLevel                 = kingpin.Flag("log.level", "set log level: trace, debug, info, warn, error (default info)").Default("info").Envar("LOG_LEVEL").String()
	logFormat                = kingpin.Flag("log.format", "set log format: text, json (default text)").Default("text").Envar("LOG_FORMAT").String()
	storageBackend           = kingpin.Flag("storage.backend", "storage backend: filesystem, kubernetes.secrets (default filesystem)").Default("filesystem").Envar("STORAGE_BACKEND").String()
	clientCertExpirationDays = kingpin.Flag("client-cert.expiration-days", "Expiration period of OpenVPN client certificates in days, the period will shrink automatically to the CA expiration period").Default("3650").Envar("CLIENT_CERT_EXPIRATION_DAYS").String()

	certsArchivePath = "/tmp/" + certsArchiveFileName
	ccdArchivePath   = "/tmp/" + ccdArchiveFileName

	// mgmtConnectRetries and mgmtConnectRetrySleep pace the startup wait for a
	// management interface that is still coming up. Variables, not constants, so
	// tests do not have to sit through the real ~50s per dead interface.
	mgmtConnectRetries    = 10
	mgmtConnectRetrySleep = 2 * time.Second

	version = "2.0.0"
)

var logLevels = map[string]log.Level{
	"trace": log.TraceLevel,
	"debug": log.DebugLevel,
	"info":  log.InfoLevel,
	"warn":  log.WarnLevel,
	"error": log.ErrorLevel,
}

var logFormats = map[string]log.Formatter{
	"text": &log.TextFormatter{},
	"json": &log.JSONFormatter{},
}

var (
	ovpnServerCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_cert_expire",
		Help: "openvpn server certificate expire time in days",
	},
	)

	ovpnServerCaCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_ca_cert_expire",
		Help: "openvpn server CA certificate expire time in days",
	},
	)

	ovpnClientsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_total",
		Help: "total openvpn users",
	},
	)

	ovpnClientsRevoked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_revoked",
		Help: "revoked openvpn users",
	},
	)

	ovpnClientsExpired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_expired",
		Help: "expired openvpn users",
	},
	)

	ovpnClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_connected",
		Help: "total connected openvpn clients",
	},
	)

	ovpnUniqClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_uniq_clients_connected",
		Help: "uniq connected openvpn clients",
	},
	)

	ovpnClientCertificateExpire = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_cert_expire",
		Help: "openvpn user certificate expire time in days",
	},
		[]string{"client"},
	)

	ovpnClientConnectionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_info",
		Help: "openvpn user connection info. ip - assigned address from ovpn network. value - last time when connection was refreshed in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientConnectionFrom = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_from",
		Help: "openvpn user connection info. ip - from which address connection was initialized. value - time when connection was initialized in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientBytesReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_received",
		Help: "openvpn user bytes received",
	},
		[]string{"client"},
	)

	ovpnClientBytesSent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_sent",
		Help: "openvpn user bytes sent",
	},
		[]string{"client"},
	)
)

type OvpnAdmin struct {
	role                   string
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	clients                []OpenvpnClient
	activeClients          []clientStatus
	// clientsMutex guards clients and activeClients, which are written by request
	// handlers and by the background sync goroutine concurrently. Both slices are
	// replaced wholesale and never mutated in place, so handing out the current
	// reference under RLock is safe. Access them through the accessors below.
	clientsMutex sync.RWMutex
	// syncTimesMutex guards lastSyncTime and lastSuccessfulSyncTime, written by
	// the slave's sync goroutine while handlers read them.
	syncTimesMutex       sync.RWMutex
	promRegistry         *prometheus.Registry
	mgmtInterfaces       map[string]string
	modules              []string
	mgmtStatusTimeFormat string
	createUserMutex      *sync.Mutex
	htmlTemplates        *template.Template
}

type OpenvpnServer struct {
	Host     string
	Port     string
	Protocol string
}

type openvpnClientConfig struct {
	Hosts      []OpenvpnServer
	CA         string
	Cert       string
	Key        string
	TLS        string
	PasswdAuth bool
}

type OpenvpnClient struct {
	// IdentityHTML is only set while a search is active: the username with the
	// matched characters wrapped in <mark>, pre-escaped. Render-only, never synced.
	IdentityHTML template.HTML `json:"-"`
	// LastLogin and FailedLogins come from the auth.sh attempt log when password
	// auth is in use: the last successful login, and how many attempts have
	// failed since it. Render-only, never synced.
	LastLogin    string `json:"-"`
	FailedLogins int    `json:"-"`
	// CreationDate is the certificate's NotBefore, read from the certificate
	// file - the index records no issue time. Render-only, never synced.
	CreationDate string `json:"-"`
	// createdUnix and expirationUnix order the sortable columns without
	// reparsing their date strings per comparison.
	createdUnix    int64
	expirationUnix int64

	Identity         string `json:"Identity"`
	AccountStatus    string `json:"AccountStatus"`
	ExpirationDate   string `json:"ExpirationDate"`
	RevocationDate   string `json:"RevocationDate"`
	ConnectionStatus string `json:"ConnectionStatus"`
	Connections      int    `json:"Connections"`
	ExpiringSoon     bool   `json:"ExpiringSoon"`
}

type DashboardStats struct {
	TotalUsers        int `json:"TotalUsers"`
	ActiveConnections int `json:"ActiveConnections"`
	RevokedUsers      int `json:"RevokedUsers"`
	ExpiringSoon      int `json:"ExpiringSoon"`
}

type ccdRoute struct {
	Address     string `json:"Address"`
	Mask        string `json:"Mask"`
	Description string `json:"Description"`
}

type Ccd struct {
	User          string     `json:"User"`
	ClientAddress string     `json:"ClientAddress"`
	CustomRoutes  []ccdRoute `json:"CustomRoutes"`
}

type indexTxtLine struct {
	Flag              string
	ExpirationDate    string
	RevocationDate    string
	SerialNumber      string
	Filename          string
	DistinguishedName string
	Identity          string
}

type clientStatus struct {
	CommonName              string
	RealAddress             string
	BytesReceived           string
	BytesSent               string
	ConnectedSince          string
	VirtualAddress          string
	LastRef                 string
	ConnectedSinceFormatted string
	LastRefFormatted        string
	ConnectedTo             string
}

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	if *storageBackend == "kubernetes.secrets" {
		err := app.updateIndexTxtOnDisk()
		if err != nil {
			log.Errorln(err)
		}
		oAdmin.setClients(oAdmin.usersList())
	}

	users := oAdmin.visibleUsers(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users":      users,
		"ServerRole": oAdmin.role,
		"Modules":    oAdmin.modules,
		"Filtered":   oAdmin.filtersActive(r),
	})
	if err != nil {
		log.Errorf("Error rendering user_rows template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
	fmt.Fprintf(w, "%s", userStatistic)
}

func (oAdmin *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, "Operation not allowed in slave mode", http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	userCreated, userCreateStatus, userCreateErr := oAdmin.userCreate(r.FormValue("username"), r.FormValue("password"))

	if userCreated {
		oAdmin.setClients(oAdmin.usersList())
		w.Header().Set("HX-Trigger", hxToast(userCreateStatus, "success"))
		oAdmin.renderUserRows(w, r)
		return
	} else {
		http.Error(w, userCreateStatus, httpStatusFor(userCreateErr))
	}
}
func (oAdmin *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, "Operation not allowed in slave mode", http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	username := oAdmin.extractUsername(r)
	msg, err := oAdmin.userRotate(username, r.FormValue("password"))
	if err != nil {
		http.Error(w, msg, httpStatusFor(err))
	} else {
		w.Header().Set("HX-Trigger", hxToast("Certificates rotated for "+username, "success"))
		oAdmin.renderUserRows(w, r)
	}
}

func (oAdmin *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, "Operation not allowed in slave mode", http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	username := oAdmin.extractUsername(r)
	msg, err := oAdmin.userDelete(username)
	if err != nil {
		http.Error(w, msg, httpStatusFor(err))
	} else {
		w.Header().Set("HX-Trigger", hxToast("User "+username+" deleted", "success"))
		oAdmin.renderUserRows(w, r)
	}
}

func (oAdmin *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, "Operation not allowed in slave mode", http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	username := oAdmin.extractUsername(r)
	msg, err := oAdmin.userRevoke(username)
	if err != nil {
		http.Error(w, msg, httpStatusFor(err))
	} else {
		w.Header().Set("HX-Trigger", hxToast("User "+username+" revoked", "warn"))
		oAdmin.renderUserRows(w, r)
	}
}

func (oAdmin *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, "Operation not allowed in slave mode", http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	username := oAdmin.extractUsername(r)
	msg, err := oAdmin.userUnrevoke(username)
	if err != nil {
		http.Error(w, msg, httpStatusFor(err))
	} else {
		w.Header().Set("HX-Trigger", hxToast("User "+username+" unrevoked", "success"))
		oAdmin.renderUserRows(w, r)
	}
}

// Helper function to extract username from URL path or form
func (oAdmin *OvpnAdmin) extractUsername(r *http.Request) string {
	// Try to get from URL path first (e.g., /users/john/revoke)
	path := strings.TrimPrefix(r.URL.Path, *listenBaseUrl)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "users" {
		return parts[1]
	}
	// Modal partials address the user in the last segment (e.g. /modal/password/john)
	if len(parts) >= 3 && parts[0] == "modal" {
		return parts[2]
	}
	// Fall back to form value
	return r.FormValue("username")
}

// fuzzyMatch matches needle against haystack the way a filter box is used: every
// character of needle must appear in haystack in the same order, but not
// necessarily adjacent, compared case-insensitively. It returns a ranking score
// and the matched rune positions for highlighting. A prefix beats a plain
// substring, a substring beats a scattered subsequence, and earlier, tighter
// matches beat later, looser ones.
func fuzzyMatch(needle, haystack string) (int, []int, bool) {
	n := []rune(strings.ToLower(needle))
	h := []rune(strings.ToLower(haystack))
	if len(n) == 0 {
		return 0, nil, true
	}
	if len(n) > len(h) {
		return 0, nil, false
	}

	// A contiguous match is both the strongest signal and the clearest highlight.
	for start := 0; start+len(n) <= len(h); start++ {
		if string(h[start:start+len(n)]) == string(n) {
			positions := make([]int, len(n))
			for i := range positions {
				positions[i] = start + i
			}
			if start == 0 {
				return 1000, positions, true
			}
			return 800 - start, positions, true
		}
	}

	// Otherwise a subsequence, matched greedily left to right.
	positions := make([]int, 0, len(n))
	next := 0
	for i, r := range h {
		if next < len(n) && r == n[next] {
			positions = append(positions, i)
			next++
		}
	}
	if next < len(n) {
		return 0, nil, false
	}
	spread := positions[len(positions)-1] - positions[0] + 1
	return 500 - positions[0]*2 - (spread-len(n))*3, positions, true
}

// highlightIdentity renders identity with the runes at positions wrapped in
// <mark>, escaping every character itself, so a row can show why it matched
// without the username ever being treated as markup.
func highlightIdentity(identity string, positions []int) template.HTML {
	matched := make(map[int]bool, len(positions))
	for _, p := range positions {
		matched[p] = true
	}
	var b strings.Builder
	open := false
	for i, r := range []rune(identity) {
		if matched[i] != open {
			if open {
				b.WriteString("</mark>")
			} else {
				b.WriteString("<mark>")
			}
			open = matched[i]
		}
		b.WriteString(template.HTMLEscapeString(string(r)))
	}
	if open {
		b.WriteString("</mark>")
	}
	return template.HTML(b.String())
}

// paramOrCookie reads one view setting: an explicit query/form parameter wins,
// otherwise the cookie the toolbar persists the setting in. Cookies travel on
// every request, so mutation re-renders keep the current view without the
// templates having to thread state through hx-include.
func paramOrCookie(r *http.Request, param, cookieName string) string {
	if v := r.FormValue(param); v != "" {
		return v
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		return cookie.Value
	}
	return ""
}

// sortUsers orders users by key ("name", "created", "expires", "status"),
// username A-Z as the tie-break and for any unknown key.
func sortUsers(users []OpenvpnClient, key string, desc bool) {
	less := func(a, b OpenvpnClient) bool {
		switch key {
		case "created":
			if a.createdUnix != b.createdUnix {
				return a.createdUnix < b.createdUnix
			}
		case "expires":
			if a.expirationUnix != b.expirationUnix {
				return a.expirationUnix < b.expirationUnix
			}
		case "status":
			if a.AccountStatus != b.AccountStatus {
				return a.AccountStatus < b.AccountStatus
			}
		}
		return strings.ToLower(a.Identity) < strings.ToLower(b.Identity)
	}
	sort.SliceStable(users, func(i, j int) bool {
		if desc {
			return less(users[j], users[i])
		}
		return less(users[i], users[j])
	})
}

// visibleUsers applies the toolbar's view state - the status filter, the search box
// and the column sort - to the client list. The search is fuzzy: characters must
// appear in order but not adjacent, results come back best match first with the
// matched characters marked for highlighting; an explicit column sort overrides
// that ranking. Both the plain list request and the re-render that follows a
// mutation go through here, so an action taken while a filter is active does not
// reset the table to every user.
func (oAdmin *OvpnAdmin) visibleUsers(r *http.Request) []OpenvpnClient {
	// A copy: the shared slice is handed out by reference under RLock and must
	// never be reordered in place.
	shared := oAdmin.getClients()
	users := make([]OpenvpnClient, len(shared))
	copy(users, shared)

	// The status filter narrows the table to one account state; "all" (or no
	// setting) shows everyone.
	if status := paramOrCookie(r, "status", "statusFilter"); status != "" && status != "all" {
		filtered := make([]OpenvpnClient, 0, len(users))
		for _, user := range users {
			if strings.EqualFold(user.AccountStatus, status) {
				filtered = append(filtered, user)
			}
		}
		users = filtered
	}

	// FormValue covers the query string on a GET and the posted body on a mutation, which
	// is how hx-include delivers the term back to us.
	search := r.FormValue("search")
	if search != "" {
		type match struct {
			user  OpenvpnClient
			score int
		}
		matches := make([]match, 0, len(users))
		for _, user := range users {
			if score, positions, ok := fuzzyMatch(search, user.Identity); ok {
				user.IdentityHTML = highlightIdentity(user.Identity, positions)
				matches = append(matches, match{user, score})
			}
		}
		// Best match first; the stable sort keeps the index order between equals.
		sort.SliceStable(matches, func(i, j int) bool { return matches[i].score > matches[j].score })
		users = make([]OpenvpnClient, len(matches))
		for i, m := range matches {
			users[i] = m.user
		}
	}

	// An explicit column sort orders whatever survived the filters. Without one,
	// an active search keeps its relevance ranking and everything else defaults
	// to username A-Z.
	sortKey := paramOrCookie(r, "sort", "sortKey")
	if search != "" && sortKey == "" {
		return users
	}
	sortUsers(users, sortKey, paramOrCookie(r, "dir", "sortDir") == "desc")
	return users
}

// filtersActive reports whether the row list was narrowed by the toolbar, so the empty
// state can tell "nothing matches your filter" apart from "there are no users". Sorting
// never hides a row, so it does not count.
func (oAdmin *OvpnAdmin) filtersActive(r *http.Request) bool {
	if r.FormValue("search") != "" {
		return true
	}
	status := paramOrCookie(r, "status", "statusFilter")
	return status != "" && status != "all"
}

// certCreationTime reads the issue time of identity's certificate: the index has
// no issue column, but the certificate itself records NotBefore. A revoked or
// archived certificate's file was moved aside under its serial.
func certCreationTime(identity, serial string) (time.Time, bool) {
	candidates := []string{
		*easyrsaDirPath + "/pki/issued/" + identity + ".crt",
		*easyrsaDirPath + "/pki/revoked/certs_by_serial/" + serial + ".crt",
		*easyrsaDirPath + "/pki/certs_by_serial/" + serial + ".pem",
	}
	for _, path := range candidates {
		if !fExist(path) {
			continue
		}
		block, _ := pem.Decode([]byte(fRead(path)))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		return cert.NotBefore, true
	}
	return time.Time{}, false
}

// userAccountStatus reports the status the UI shows for username - "Active", "Revoked" or
// "Expired" - or "" when the user is not in the certificate index.
func (oAdmin *OvpnAdmin) userAccountStatus(username string) string {
	for _, user := range oAdmin.usersList() {
		if user.Identity == username {
			return user.AccountStatus
		}
	}
	return ""
}

// Helper function to render user rows
func (oAdmin *OvpnAdmin) renderUserRows(w http.ResponseWriter, r *http.Request) {
	// usersList reads activeClients to decide who is online, so refresh that first or the
	// rows carry certificate data from disk next to connection data from up to 28s ago.
	oAdmin.setActiveClients(oAdmin.mgmtGetActiveClients())
	oAdmin.setClients(oAdmin.usersList())

	users := oAdmin.visibleUsers(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users":      users,
		"ServerRole": oAdmin.role,
		"Modules":    oAdmin.modules,
		"Filtered":   oAdmin.filtersActive(r),
	})
	if err != nil {
		log.Errorf("Error rendering user_rows template: %v", err)
	}
}

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	if *authByPassword {
		username := oAdmin.extractUsername(r)
		msg, err := oAdmin.userChangePassword(username, r.FormValue("password"))
		if err != nil {
			http.Error(w, msg, httpStatusFor(err))
		} else {
			w.Header().Set("HX-Trigger", hxToast("Password changed for "+username, "success"))
			oAdmin.renderUserRows(w, r)
		}
	} else {
		http.Error(w, "Password authentication not enabled", http.StatusNotImplemented)
	}
}

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	username := oAdmin.extractUsername(r)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", oAdmin.renderClientConfig(username))
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
	fmt.Fprintf(w, "%s", r.FormValue("username"))
}

func (oAdmin *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	username := oAdmin.extractUsername(r)
	ccd := oAdmin.getCcd(username)
	ccd.User = username

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_ccd", map[string]interface{}{
		"Ccd":        ccd,
		"ServerRole": oAdmin.role,
		"Modules":    oAdmin.modules,
	})
	if err != nil {
		log.Errorf("Error rendering modal_ccd template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (oAdmin *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, "Operation not allowed in slave mode", http.StatusLocked)
		return
	}
	_ = r.ParseForm()

	username := oAdmin.extractUsername(r)

	// Parse form data into Ccd struct
	ccd := Ccd{
		User:          username,
		ClientAddress: r.FormValue("clientAddress"),
		CustomRoutes:  []ccdRoute{},
	}

	// Parse routes from form
	for i := 0; ; i++ {
		address := r.FormValue(fmt.Sprintf("routes[%d].address", i))
		if address == "" {
			break
		}
		mask := r.FormValue(fmt.Sprintf("routes[%d].mask", i))
		description := r.FormValue(fmt.Sprintf("routes[%d].description", i))
		ccd.CustomRoutes = append(ccd.CustomRoutes, ccdRoute{
			Address:     address,
			Mask:        mask,
			Description: description,
		})
	}

	ccdApplied, applyStatus := oAdmin.modifyCcd(ccd)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if ccdApplied {
		w.Header().Set("HX-Trigger", hxToast("Routes updated for "+username, "success"))
		err := oAdmin.htmlTemplates.ExecuteTemplate(w, "alert_success", map[string]interface{}{
			"Message": applyStatus,
		})
		if err != nil {
			log.Errorf("Error rendering alert template: %v", err)
		}
	} else {
		err := oAdmin.htmlTemplates.ExecuteTemplate(w, "alert_error", map[string]interface{}{
			"Message": applyStatus,
		})
		if err != nil {
			log.Errorf("Error rendering alert template: %v", err)
		}
	}
}

func (oAdmin *OvpnAdmin) serverSettingsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enabledModules, enabledModulesErr := json.Marshal(oAdmin.modules)
	if enabledModulesErr != nil {
		log.Errorln(enabledModulesErr)
	}
	fmt.Fprintf(w, `{"status":"ok", "serverRole": "%s", "modules": %s }`, oAdmin.role, string(enabledModules))
}

// calculateStats computes dashboard statistics from clients
func (oAdmin *OvpnAdmin) calculateStats() DashboardStats {
	stats := DashboardStats{}
	now := time.Now()
	thirtyDaysFromNow := now.AddDate(0, 0, 30)

	for _, client := range oAdmin.getClients() {
		stats.TotalUsers++
		stats.ActiveConnections += client.Connections

		if client.AccountStatus == "Revoked" {
			stats.RevokedUsers++
		}

		// Check if certificate expires within 30 days
		if client.AccountStatus == "Active" && client.ExpirationDate != "" {
			expDate, err := time.Parse("2006-01-02 15:04:05", client.ExpirationDate)
			if err == nil && expDate.Before(thirtyDaysFromNow) && expDate.After(now) {
				stats.ExpiringSoon++
			}
		}
	}

	return stats
}

// Stats handler - returns stats HTML fragment for HTMX refresh
func (oAdmin *OvpnAdmin) statsHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)

	// Refresh state to get latest data
	if *storageBackend == "kubernetes.secrets" {
		err := app.updateIndexTxtOnDisk()
		if err != nil {
			log.Errorln(err)
		}
	}
	oAdmin.setActiveClients(oAdmin.mgmtGetActiveClients())
	oAdmin.setClients(oAdmin.usersList())

	stats := oAdmin.calculateStats()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "stats_cards", map[string]interface{}{
		"Stats": stats,
	})
	if err != nil {
		log.Errorf("Error rendering stats template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Index page handler - renders the main page
// humanBytes renders a byte count (as the management interface reports it, a
// decimal string) in the nearest unit, for the connections table.
func humanBytes(s string) string {
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", n)
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}

// indexPageHandler renders the Users management page.
func (oAdmin *OvpnAdmin) indexPageHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	// The toolbar's persisted view state, so the initial render marks the right
	// segment and sort column before any JS runs.
	statusFilter := paramOrCookie(r, "status", "statusFilter")
	if statusFilter == "" {
		statusFilter = "all"
	}
	sortKey := paramOrCookie(r, "sort", "sortKey")
	if sortKey == "" {
		sortKey = "name"
	}
	sortDir := paramOrCookie(r, "dir", "sortDir")
	if sortDir != "desc" {
		sortDir = "asc"
	}
	_, lastSuccessfulSync := oAdmin.getSyncTimes()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "base", map[string]interface{}{
		"Page":         "users",
		"Users":        oAdmin.getClients(),
		"ServerRole":   oAdmin.role,
		"Modules":      oAdmin.modules,
		"StatusFilter": statusFilter,
		"SortKey":      sortKey,
		"SortDir":      sortDir,
		"LastSync":     lastSuccessfulSync,
		"Stats":        oAdmin.calculateStats(),
		"Version":      version,
	})
	if err != nil {
		log.Errorf("Error rendering index template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// dashboardPageHandler renders the home page: who is connected right now, the
// summary figures, and the latest login attempts.
func (oAdmin *OvpnAdmin) dashboardPageHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	_, lastSuccessfulSync := oAdmin.getSyncTimes()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "base", map[string]interface{}{
		"Page":              "dashboard",
		"ServerRole":        oAdmin.role,
		"Modules":           oAdmin.modules,
		"LastSync":          lastSuccessfulSync,
		"Stats":             oAdmin.calculateStats(),
		"ActiveConnections": oAdmin.getActiveClients(),
		"RecentAttempts":    parseAuthLog(*authLogPath, 8),
		"Version":           version,
	})
	if err != nil {
		log.Errorf("Error rendering dashboard template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// connectionsHandler re-renders the dashboard's connection list with fresh
// management-interface data, for the explicit refresh.
func (oAdmin *OvpnAdmin) connectionsHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)

	oAdmin.setActiveClients(oAdmin.mgmtGetActiveClients())

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "connections", map[string]interface{}{
		"ActiveConnections": oAdmin.getActiveClients(),
	})
	if err != nil {
		log.Errorf("Error rendering connections template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Modal handlers
func (oAdmin *OvpnAdmin) modalCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_create", map[string]interface{}{
		"Modules": oAdmin.modules,
	})
	if err != nil {
		log.Errorf("Error rendering modal_create template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (oAdmin *OvpnAdmin) modalActivityHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	// ?user=<name> narrows the view to one account's history. An attempt belongs
	// to a user if they typed the name OR their certificate was used - the
	// latter is how a cn-mismatch probe against their account shows up.
	filterUser := r.FormValue("user")
	attempts := parseAuthLog(*authLogPath, authLogParseLimit)
	if filterUser != "" {
		filtered := make([]authAttempt, 0, len(attempts))
		for _, a := range attempts {
			if a.Username == filterUser || a.CommonName == filterUser {
				filtered = append(filtered, a)
			}
		}
		attempts = filtered
	}
	if len(attempts) > 100 {
		attempts = attempts[:100]
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_activity", map[string]interface{}{
		"Attempts":   attempts,
		"FilterUser": filterUser,
	})
	if err != nil {
		log.Errorf("Error rendering modal_activity template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (oAdmin *OvpnAdmin) modalPasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	username := oAdmin.extractUsername(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_password", map[string]interface{}{
		"Username": username,
		"Modules":  oAdmin.modules,
	})
	if err != nil {
		log.Errorf("Error rendering modal_password template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (oAdmin *OvpnAdmin) modalRotateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	username := oAdmin.extractUsername(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_rotate", map[string]interface{}{
		"Username": username,
		"Modules":  oAdmin.modules,
	})
	if err != nil {
		log.Errorf("Error rendering modal_rotate template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (oAdmin *OvpnAdmin) modalDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	username := oAdmin.extractUsername(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_delete", map[string]interface{}{
		"Username": username,
	})
	if err != nil {
		log.Errorf("Error rendering modal_delete template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (oAdmin *OvpnAdmin) lastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	lastTry, _ := oAdmin.getSyncTimes()
	fmt.Fprint(w, lastTry)
}

func (oAdmin *OvpnAdmin) lastSuccessfulSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	_, lastSuccessful := oAdmin.getSyncTimes()
	fmt.Fprint(w, lastSuccessful)
}

func (oAdmin *OvpnAdmin) downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	// Constant-time: this token gates the whole PKI, private keys included.
	if subtle.ConstantTimeCompare([]byte(token), []byte(oAdmin.masterSyncToken)) != 1 {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, certsArchivePath)
}

func (oAdmin *OvpnAdmin) downloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if subtle.ConstantTimeCompare([]byte(token), []byte(oAdmin.masterSyncToken)) != 1 {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, ccdArchivePath)
}

var app OpenVPNPKI

func main() {
	kingpin.Version(version)
	kingpin.Parse()

	log.SetLevel(logLevels[*logLevel])
	log.SetFormatter(logFormats[*logFormat])

	if *storageBackend == "kubernetes.secrets" {
		err := app.run()
		if err != nil {
			log.Error(err)
		}
	}

	if *indexTxtPath == "" {
		*indexTxtPath = *easyrsaDirPath + "/pki/index.txt"
	}
	if *authLogPath == "" {
		// Matches AUTH_LOG in setup/auth.sh: log/ is the one subdirectory the
		// unprivileged openvpn user can write into (the PKI stays root-owned),
		// and it sits outside pki/ so an easyrsa re-init keeps the history.
		*authLogPath = *easyrsaDirPath + "/log/auth.log"
	}

	if *authDataBaseInit {
		ovpnUserInitDb()
	}

	ovpnAdmin := new(OvpnAdmin)

	ovpnAdmin.lastSyncTime = "unknown"
	ovpnAdmin.role = *serverRole
	ovpnAdmin.lastSuccessfulSyncTime = "unknown"
	ovpnAdmin.masterSyncToken = *masterSyncToken
	ovpnAdmin.promRegistry = prometheus.NewRegistry()
	ovpnAdmin.modules = []string{}
	ovpnAdmin.createUserMutex = &sync.Mutex{}
	ovpnAdmin.mgmtInterfaces = make(map[string]string)

	for _, mgmtInterface := range *mgmtAddress {
		parts := strings.SplitN(mgmtInterface, "=", 2)
		ovpnAdmin.mgmtInterfaces[parts[0]] = parts[len(parts)-1]
	}

	ovpnAdmin.mgmtSetTimeFormat()

	ovpnAdmin.registerMetrics()
	ovpnAdmin.setState()

	go ovpnAdmin.updateState()

	if *masterBasicAuthPassword != "" && *masterBasicAuthUser != "" {
		ovpnAdmin.masterHostBasicAuth = true
	} else {
		ovpnAdmin.masterHostBasicAuth = false
	}

	ovpnAdmin.modules = append(ovpnAdmin.modules, "core")

	if *authByPassword {
		if *storageBackend != "kubernetes.secrets" {
			ovpnAdmin.modules = append(ovpnAdmin.modules, "passwdAuth")
		} else {
			log.Fatal("Right now the keys `--storage.backend=kubernetes.secret` and `--auth.password` are not working together. Please use only one of them ")
		}
	}

	if *ccdEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "ccd")
	}

	if ovpnAdmin.role == "slave" {
		ovpnAdmin.syncDataFromMaster()
		go ovpnAdmin.syncWithMaster()
	}

	// Load HTML templates with helper functions
	funcMap := template.FuncMap{
		"hasModule": func(modules []string, module string) bool {
			for _, m := range modules {
				if m == module {
					return true
				}
			}
			return false
		},
		"add": func(a, b int) int {
			return a + b
		},
		"humanBytes": humanBytes,
		"dict": func(values ...interface{}) map[string]interface{} {
			dict := make(map[string]interface{})
			for i := 0; i+1 < len(values); i += 2 {
				key, _ := values[i].(string)
				dict[key] = values[i+1]
			}
			return dict
		},
	}

	var err error
	ovpnAdmin.htmlTemplates, err = template.New("").Funcs(funcMap).ParseFS(templatesFS, "templates/*.html", "templates/partials/*.html")
	if err != nil {
		log.Fatalf("Error loading HTML templates: %v", err)
	}

	// Serve static files from embedded filesystem
	staticSubFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("Error creating static sub-filesystem: %v", err)
	}
	staticHandler := CacheControlWrapper(http.FileServer(http.FS(staticSubFS)))

	// Static files route
	http.Handle(*listenBaseUrl+"static/", http.StripPrefix(strings.TrimRight(*listenBaseUrl, "/")+"/static", staticHandler))

	// Main page route
	http.HandleFunc(*listenBaseUrl, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == *listenBaseUrl || r.URL.Path == strings.TrimRight(*listenBaseUrl, "/") {
			ovpnAdmin.dashboardPageHandler(w, r)
		} else {
			http.NotFound(w, r)
		}
	})

	// Users management page, and create user (the POST target keeps its URL)
	http.HandleFunc(*listenBaseUrl+"users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ovpnAdmin.userCreateHandler(w, r)
			return
		}
		ovpnAdmin.indexPageHandler(w, r)
	})

	// HTMX partials
	http.HandleFunc(*listenBaseUrl+"partials/users", ovpnAdmin.userListHandler)
	http.HandleFunc(*listenBaseUrl+"partials/connections", ovpnAdmin.connectionsHandler)

	// Stats (HTMX partial for dashboard refresh)
	http.HandleFunc(*listenBaseUrl+"stats", ovpnAdmin.statsHandler)

	// User operations
	http.HandleFunc(*listenBaseUrl+"users/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, *listenBaseUrl+"users/")
		parts := strings.Split(path, "/")

		if len(parts) == 0 || parts[0] == "" {
			// POST /users - create user
			if r.Method == http.MethodPost {
				ovpnAdmin.userCreateHandler(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}

		username := parts[0]

		if len(parts) == 1 {
			// DELETE /users/{username} - delete user
			if r.Method == http.MethodDelete {
				ovpnAdmin.userDeleteHandler(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}

		action := parts[1]
		switch action {
		case "revoke":
			ovpnAdmin.userRevokeHandler(w, r)
		case "unrevoke":
			ovpnAdmin.userUnrevokeHandler(w, r)
		case "rotate":
			ovpnAdmin.userRotateHandler(w, r)
		case "password":
			ovpnAdmin.userChangePasswordHandler(w, r)
		case "config":
			ovpnAdmin.userShowConfigHandler(w, r)
		case "ccd":
			if r.Method == http.MethodPost {
				ovpnAdmin.userApplyCcdHandler(w, r)
			} else {
				ovpnAdmin.userShowCcdHandler(w, r)
			}
		default:
			log.Warnf("Unknown action: %s for user: %s", action, username)
			http.NotFound(w, r)
		}
	})

	// Modal routes
	http.HandleFunc(*listenBaseUrl+"modal/create", ovpnAdmin.modalCreateHandler)
	http.HandleFunc(*listenBaseUrl+"modal/activity", ovpnAdmin.modalActivityHandler)
	http.HandleFunc(*listenBaseUrl+"modal/password/", ovpnAdmin.modalPasswordHandler)
	http.HandleFunc(*listenBaseUrl+"modal/rotate/", ovpnAdmin.modalRotateHandler)
	http.HandleFunc(*listenBaseUrl+"modal/delete/", ovpnAdmin.modalDeleteHandler)
	http.HandleFunc(*listenBaseUrl+"modal/ccd/", ovpnAdmin.userShowCcdHandler)

	// Keep API routes for backwards compatibility and internal use
	http.HandleFunc(*listenBaseUrl+"api/server/settings", ovpnAdmin.serverSettingsHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/unrevoke", ovpnAdmin.userUnrevokeHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/config/show", ovpnAdmin.userShowConfigHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/disconnect", ovpnAdmin.userDisconnectHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/statistic", ovpnAdmin.userStatisticHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/ccd", ovpnAdmin.userShowCcdHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/ccd/apply", ovpnAdmin.userApplyCcdHandler)

	http.HandleFunc(*listenBaseUrl+"api/sync/last/try", ovpnAdmin.lastSyncTimeHandler)
	http.HandleFunc(*listenBaseUrl+"api/sync/last/successful", ovpnAdmin.lastSuccessfulSyncTimeHandler)
	http.HandleFunc(*listenBaseUrl+downloadCertsApiUrl, ovpnAdmin.downloadCertsHandler)
	http.HandleFunc(*listenBaseUrl+downloadCcdApiUrl, ovpnAdmin.downloadCcdHandler)

	http.Handle(*metricsPath, promhttp.HandlerFor(ovpnAdmin.promRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc(*listenBaseUrl+"ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong")
	})

	log.Printf("Bind: http://%s:%s%s", *listenHost, *listenPort, *listenBaseUrl)
	log.Fatal(http.ListenAndServe(*listenHost+":"+*listenPort, nil))
}

func CacheControlWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
		h.ServeHTTP(w, r)
	})
}

func (oAdmin *OvpnAdmin) registerMetrics() {
	oAdmin.promRegistry.MustRegister(ovpnServerCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnServerCaCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientsTotal)
	oAdmin.promRegistry.MustRegister(ovpnClientsRevoked)
	oAdmin.promRegistry.MustRegister(ovpnClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnUniqClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnClientsExpired)
	oAdmin.promRegistry.MustRegister(ovpnClientCertificateExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionInfo)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionFrom)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesReceived)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesSent)
}

func (oAdmin *OvpnAdmin) getClients() []OpenvpnClient {
	oAdmin.clientsMutex.RLock()
	defer oAdmin.clientsMutex.RUnlock()
	return oAdmin.clients
}

func (oAdmin *OvpnAdmin) setClients(clients []OpenvpnClient) {
	oAdmin.clientsMutex.Lock()
	defer oAdmin.clientsMutex.Unlock()
	oAdmin.clients = clients
}

func (oAdmin *OvpnAdmin) getActiveClients() []clientStatus {
	oAdmin.clientsMutex.RLock()
	defer oAdmin.clientsMutex.RUnlock()
	return oAdmin.activeClients
}

func (oAdmin *OvpnAdmin) setActiveClients(activeClients []clientStatus) {
	oAdmin.clientsMutex.Lock()
	defer oAdmin.clientsMutex.Unlock()
	oAdmin.activeClients = activeClients
}

// getSyncTimes returns the last sync attempt and the last successful sync.
func (oAdmin *OvpnAdmin) getSyncTimes() (lastTry, lastSuccessful string) {
	oAdmin.syncTimesMutex.RLock()
	defer oAdmin.syncTimesMutex.RUnlock()
	return oAdmin.lastSyncTime, oAdmin.lastSuccessfulSyncTime
}

func (oAdmin *OvpnAdmin) markSyncAttempt(at string, successful bool) {
	oAdmin.syncTimesMutex.Lock()
	defer oAdmin.syncTimesMutex.Unlock()
	oAdmin.lastSyncTime = at
	if successful {
		oAdmin.lastSuccessfulSyncTime = at
	}
}

func (oAdmin *OvpnAdmin) setState() {
	oAdmin.setActiveClients(oAdmin.mgmtGetActiveClients())
	oAdmin.setClients(oAdmin.usersList())

	ovpnServerCaCertExpire.Set(float64((getOvpnCaCertExpireDate().Unix() - time.Now().Unix()) / 3600 / 24))
}

func (oAdmin *OvpnAdmin) updateState() {
	for {
		time.Sleep(time.Duration(28) * time.Second)
		ovpnClientBytesSent.Reset()
		ovpnClientBytesReceived.Reset()
		ovpnClientConnectionFrom.Reset()
		ovpnClientConnectionInfo.Reset()
		ovpnClientCertificateExpire.Reset()
		// Run the sweep inline: the next tick starts 28s after this one
		// finishes, so slow management sockets cannot pile sweeps on top of
		// each other the way a per-tick goroutine did.
		func() {
			// A panic here would take down the whole daemon, and nothing
			// restarts this goroutine. Log it and let the next tick retry.
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("updateState: background sync panicked: %v", r)
				}
			}()
			oAdmin.setState()
		}()
	}
}

func indexTxtParser(txt string) []indexTxtLine {
	var indexTxt []indexTxtLine

	txtLinesArray := strings.Split(txt, "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			// case strings.HasPrefix(str[0], "E"):
			case strings.HasPrefix(str[0], "V"):
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], SerialNumber: str[2], Filename: str[3], DistinguishedName: str[4], Identity: str[4][strings.Index(str[4], "=")+1:]})
			case strings.HasPrefix(str[0], "R"):
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], RevocationDate: str[2], SerialNumber: str[3], Filename: str[4], DistinguishedName: str[5], Identity: str[5][strings.Index(str[5], "=")+1:]})
			}
		}
	}

	return indexTxt
}

func renderIndexTxt(data []indexTxtLine) string {
	indexTxt := ""
	for _, line := range data {
		switch {
		case line.Flag == "V":
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
		case line.Flag == "R":
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.RevocationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
			// case line.flag == "E":
		}
	}
	return indexTxt
}

func (oAdmin *OvpnAdmin) getClientConfigTemplate() *texttemplate.Template {
	if *clientConfigTemplatePath != "" {
		return texttemplate.Must(texttemplate.ParseFiles(*clientConfigTemplatePath))
	} else {
		clientConfigTpl, clientConfigTplErr := templatesFS.ReadFile("templates/client.conf.tpl")
		if clientConfigTplErr != nil {
			log.Error("clientConfigTpl not found in templates: ", clientConfigTplErr)
		}
		return texttemplate.Must(texttemplate.New("client-config").Parse(string(clientConfigTpl)))
	}
}

func (oAdmin *OvpnAdmin) renderClientConfig(username string) string {
	if checkUserExist(username) {
		var hosts []OpenvpnServer

		for _, server := range *openvpnServer {
			parts := strings.SplitN(server, ":", 3)
			if len(parts) < 3 {
				// A config mistake must not panic the handler on every request.
				log.Warnf("skipping malformed --ovpn.server value %q, expected HOST:PORT:PROTOCOL", server)
				continue
			}
			hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1], Protocol: parts[2]})
		}

		if *openvpnServerBehindLB {
			var err error
			hosts, err = getOvpnServerHostsFromKubeApi()
			if err != nil {
				log.Error(err)
			}
		}

		log.Tracef("hosts for %s\n %v", username, hosts)

		conf := openvpnClientConfig{}
		conf.Hosts = hosts
		conf.CA = fRead(*easyrsaDirPath + "/pki/ca.crt")
		conf.TLS = fRead(*easyrsaDirPath + "/pki/ta.key")

		if *storageBackend == "kubernetes.secrets" {
			conf.Cert, conf.Key = app.easyrsaGetClientCert(username)
		} else {
			conf.Cert = fRead(*easyrsaDirPath + "/pki/issued/" + username + ".crt")
			conf.Key = fRead(*easyrsaDirPath + "/pki/private/" + username + ".key")
		}

		conf.PasswdAuth = *authByPassword

		t := oAdmin.getClientConfigTemplate()

		var tmp bytes.Buffer
		err := t.Execute(&tmp, conf)
		if err != nil {
			log.Errorf("something goes wrong during rendering config for %s", username)
			log.Debugf("rendering config for %s failed with error %v", username, err)
		}

		hosts = nil

		log.Tracef("Rendered config for user %s: %+v", username, tmp.String())

		return fmt.Sprintf("%+v", tmp.String())
	}
	log.Warnf("user \"%s\" not found", username)
	return fmt.Sprintf("user \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) getCcdTemplate() *texttemplate.Template {
	if *ccdTemplatePath != "" {
		return texttemplate.Must(texttemplate.ParseFiles(*ccdTemplatePath))
	} else {
		ccdTpl, ccdTplErr := templatesFS.ReadFile("templates/ccd.tpl")
		if ccdTplErr != nil {
			log.Errorf("ccdTpl not found in templates: %v", ccdTplErr)
		}
		return texttemplate.Must(texttemplate.New("ccd").Parse(string(ccdTpl)))
	}
}

func (oAdmin *OvpnAdmin) parseCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	var txtLinesArray []string
	if *storageBackend == "kubernetes.secrets" {
		txtLinesArray = strings.Split(app.secretGetCcd(ccd.User), "\n")
	} else {
		if fExist(*ccdDir + "/" + username) {
			txtLinesArray = strings.Split(fRead(*ccdDir+"/"+username), "\n")
		}
	}

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			case strings.HasPrefix(str[0], "ifconfig-push"):
				ccd.ClientAddress = str[1]
			case strings.HasPrefix(str[0], "push"):
				ccd.CustomRoutes = append(ccd.CustomRoutes, ccdRoute{Address: strings.Trim(str[2], "\""), Mask: strings.Trim(str[3], "\""), Description: strings.Trim(strings.Join(str[4:], ""), "#")})
			}
		}
	}

	return ccd
}

func (oAdmin *OvpnAdmin) modifyCcd(ccd Ccd) (bool, string) {
	ccdValid, err := validateCcd(ccd)
	if err != "" {
		return false, err
	}

	if ccdValid {
		t := oAdmin.getCcdTemplate()
		var tmp bytes.Buffer
		err := t.Execute(&tmp, ccd)
		if err != nil {
			log.Error(err)
		}
		if *storageBackend == "kubernetes.secrets" {
			app.secretUpdateCcd(ccd.User, tmp.Bytes())
		} else {
			err = fWrite(*ccdDir+"/"+ccd.User, tmp.String())
			if err != nil {
				log.Errorf("modifyCcd: fWrite(): %v", err)
			}
		}

		return true, "ccd updated successfully"
	}

	return false, "something goes wrong"
}

func validateCcd(ccd Ccd) (bool, string) {

	ccdErr := ""

	if ccd.ClientAddress != "dynamic" {
		_, ovpnNet, err := net.ParseCIDR(*openvpnNetwork)
		if err != nil {
			log.Error(err)
		}

		if !checkStaticAddressIsFree(ccd.ClientAddress, ccd.User) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" already assigned to another user", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if net.ParseIP(ccd.ClientAddress) == nil {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not a valid IP address", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if !ovpnNet.Contains(net.ParseIP(ccd.ClientAddress)) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not belongs to openvpn server network", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}
	}

	for _, route := range ccd.CustomRoutes {
		if net.ParseIP(route.Address) == nil {
			ccdErr = fmt.Sprintf("CustomRoute.Address \"%s\" must be a valid IP address", route.Address)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if net.ParseIP(route.Mask) == nil {
			ccdErr = fmt.Sprintf("CustomRoute.Mask \"%s\" must be a valid IP address", route.Mask)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}
	}

	return true, ccdErr
}

func (oAdmin *OvpnAdmin) getCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	ccd = oAdmin.parseCcd(username)

	return ccd
}

func checkStaticAddressIsFree(staticAddress string, username string) bool {

	if *storageBackend == "kubernetes.secrets" {

		log.Infof("Static address: %s", staticAddress)

		labelSelector := fmt.Sprintf("%s=%s,%s=%s",
			labelKeyType, labelValueClientAuth,
			labelKeyManagedBy, labelValueManagedByApp)

		secrets, err := app.secretsGetByLabels(labelSelector)
		if err != nil {
			log.Error(err)
		}

		for _, secret := range secrets.Items {
			otherUser := secret.Labels["name"]
			if otherUser == username {
				continue
			}

			dataCCD, ok := secret.Data["ccd"]
			if !ok {
				continue
			}

			lines := strings.Split(string(dataCCD), "\n")

			for _, line := range lines {
				if strings.HasPrefix(line, prefixStaticRoute) {
					fields := strings.Fields(line)
					if len(fields) >= 2 && fields[1] == staticAddress {
						log.Warnf("IP %s already assigned to user %s", staticAddress, otherUser)
						return false
					}
				}
			}
		}

		return true
	}

	// Previously: grep -rl ' <addr> ' <ccdDir> | grep -vx <ccdDir>/<user> | wc -l
	// Done in Go so that staticAddress cannot reach a shell: validateCcd calls this
	// before it has checked that the value is a valid IP address.
	needle := " " + staticAddress + " "
	inUse := false

	err := filepath.Walk(*ccdDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || path == filepath.Join(*ccdDir, username) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			log.Warnf("checkStaticAddressIsFree: %v", err)
			return nil
		}
		if strings.Contains(string(content), needle) {
			log.Warnf("IP %s already assigned in %s", staticAddress, path)
			inUse = true
		}
		return nil
	})
	if err != nil {
		log.Errorf("checkStaticAddressIsFree: walk %s: %v", *ccdDir, err)
	}

	return !inUse
}

func validateUsername(username string) error {
	var validUsername = regexp.MustCompile(usernameRegexp)
	if !validUsername.MatchString(username) {
		return userInputError{fmt.Sprintf("Username can only contains %s", usernameRegexp)}
	}

	// A CN longer than this is not valid in an X.509 subject.
	if utf8.RuneCountInString(username) > usernameMaxLength {
		return userInputError{fmt.Sprintf("Username too long, must be at most %d characters", usernameMaxLength)}
	}

	// easyrsa and openvpn-user read a leading dash as the start of a flag. Commands are
	// built with exec.Command, which stops shell injection but passes the argument
	// through verbatim, so argument injection has to be rejected here.
	if strings.HasPrefix(username, "-") {
		return userInputError{`Username cannot start with "-"`}
	}

	if username == "." || username == ".." {
		return userInputError{`Username cannot be "." or ".."`}
	}

	// usersList hides the server certificate and anything marked revoked, so a user
	// with either name would be created but never appear in the UI. "server" would
	// also be mistaken for the server certificate when reporting expiry.
	if username == "server" {
		return userInputError{`"server" is reserved`}
	}
	if strings.Contains(username, "REVOKED") {
		return userInputError{`Username cannot contain "REVOKED"`}
	}

	return nil
}

func validatePassword(password string) error {
	length := utf8.RuneCountInString(password)
	if length < passwordMinLength {
		return userInputError{fmt.Sprintf("Password too short, password length must be greater or equal %d", passwordMinLength)}
	}
	if length > passwordMaxLength {
		return userInputError{fmt.Sprintf("Password too long, must be at most %d characters", passwordMaxLength)}
	}
	return nil
}

func checkUserExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN=" + username) {
			return true
		}
	}
	return false
}

func (oAdmin *OvpnAdmin) usersList() []OpenvpnClient {
	var users []OpenvpnClient

	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()
	thirtyDaysFromNow := time.Now().AddDate(0, 0, 30).Unix()
	activeClients := oAdmin.getActiveClients()
	logins := authLoginStats(*authLogPath)

	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if line.Identity != "server" && !strings.Contains(line.Identity, "REVOKED") {
			totalCerts += 1
			ovpnClient := OpenvpnClient{Identity: line.Identity, ExpirationDate: parseDateToString(indexTxtDateLayout, line.ExpirationDate, stringDateFormat)}
			switch {
			case line.Flag == "V":
				ovpnClient.AccountStatus = "Active"
				validCerts += 1
			case line.Flag == "R":
				ovpnClient.AccountStatus = "Revoked"
				ovpnClient.RevocationDate = parseDateToString(indexTxtDateLayout, line.RevocationDate, stringDateFormat)
				revokedCerts += 1
			case line.Flag == "E":
				ovpnClient.AccountStatus = "Expired"
				expiredCerts += 1
			}

			expirationUnix := parseDateToUnix(indexTxtDateLayout, line.ExpirationDate)
			ovpnClient.expirationUnix = expirationUnix
			if created, ok := certCreationTime(line.Identity, line.SerialNumber); ok {
				ovpnClient.CreationDate = created.UTC().Format(stringDateFormat)
				ovpnClient.createdUnix = created.Unix()
			}
			ovpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((expirationUnix - apochNow) / 3600 / 24))

			if (expirationUnix - apochNow) < 0 {
				ovpnClient.AccountStatus = "Expired"
			}

			// Check if certificate expires within 30 days
			if ovpnClient.AccountStatus == "Active" && expirationUnix > apochNow && expirationUnix < thirtyDaysFromNow {
				ovpnClient.ExpiringSoon = true
			}

			ovpnClient.Connections = 0

			if s, found := logins[line.Identity]; found {
				ovpnClient.LastLogin = s.LastLogin
				ovpnClient.FailedLogins = s.FailedLogins
			}

			userConnected, userConnectedTo := isUserConnected(line.Identity, activeClients)
			if userConnected {
				ovpnClient.ConnectionStatus = "Connected"
				for range userConnectedTo {
					ovpnClient.Connections += 1
					totalActiveConnections += 1
				}
				connectedUniqUsers += 1
			}

			users = append(users, ovpnClient)

		} else if line.Identity == "server" {
			// Only the server certificate itself: this branch also catches the
			// REVOKED-* entries deletes leave behind, and letting those write the
			// gauge reported some deleted user's expiry as the server's.
			ovpnServerCertExpire.Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
		}
	}

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Warnf("there are %d otherCerts", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(totalActiveConnections))
	ovpnUniqClientsConnected.Set(float64(connectedUniqUsers))

	return users
}

func (oAdmin *OvpnAdmin) userCreate(username, password string) (bool, string, error) {
	ucErr := fmt.Sprintf("User \"%s\" created", username)

	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()

	if err := validateUsername(username); err != nil {
		log.Debugf("userCreate: validateUsername(): %s", err.Error())
		return false, err.Error(), err
	}

	if checkUserExist(username) {
		ucErr = fmt.Sprintf("User \"%s\" already exists\n", username)
		log.Debugf("userCreate: checkUserExist():  %s", ucErr)
		return false, ucErr, userInputError{ucErr}
	}

	if *authByPassword {
		if err := validatePassword(password); err != nil {
			log.Debugf("userCreate: authByPassword(): %s", err.Error())
			return false, err.Error(), err
		}
	}

	if *storageBackend == "kubernetes.secrets" {
		if err := app.easyrsaBuildClient(username); err != nil {
			log.Errorf("userCreate: easyrsaBuildClient(%s): %v", username, err)
			return false, fmt.Sprintf("Could not create certificate for user %q: %s", username, err), err
		}
	} else {
		// Deletes made before archiving existed renamed the index entry but left
		// the certificate files under the name, which makes easyrsa refuse to
		// issue for it. The name is free per the index (checked above), so any
		// files still carrying it belong to a former certificate.
		archiveOrphanedUserPkiFiles(username)

		out, err := runCmdDir(*easyrsaDirPath, *easyrsaBinPath, "--batch", "build-client-full", username, "nopass")
		if err != nil {
			log.Errorf("userCreate: build-client-full(%s): %v", username, err)
			return false, fmt.Sprintf("Could not create certificate for user %q: %s", username, firstLine(out, err)), err
		}
		log.Debug(out)
	}

	if *authByPassword {
		out, err := runCmd("openvpn-user", "create", "--db.path", *authDatabase, "--user", username, "--password", password)
		if err != nil {
			// The certificate exists but the account has no password, so it could never
			// authenticate. Roll the certificate back rather than leave a half-created user.
			log.Errorf("userCreate: openvpn-user create(%s): %v", username, err)
			// The fresh certificate reads Active, which userDelete refuses, so it
			// must be revoked first. Both steps are best effort: the password
			// record may never have been written, so a failure to purge it is not
			// necessarily a problem.
			if _, rbErr := oAdmin.userRevoke(username); rbErr != nil {
				log.Warnf("userCreate: rollback revoke of %s reported: %v", username, rbErr)
			}
			if _, rbErr := oAdmin.userDelete(username); rbErr != nil {
				log.Warnf("userCreate: rollback of %s reported: %v", username, rbErr)
			}
			return false, fmt.Sprintf("Could not set password for user %q: %s", username, firstLine(out, err)), err
		}
		log.Debug(out)
	}

	log.Infof("Certificate for user %s issued", username)

	return true, ucErr, nil
}

// hxToast builds the HX-Trigger payload sent after a successful mutation: the toast to
// show, plus a `refreshStats` event for the summary cards (bound to
// `refreshStats from:body`), which nothing else fires now that the 15s poll is gone.
// The event is deliberately NOT the row list's `refresh`: it dispatches on the button
// that made the request and bubbles up through the tbody, so using `refresh` made every
// row action fire a second GET /users whose swap raced the mutation's own response.
// The payload is JSON-encoded rather than concatenated: usernames and command output
// can contain quotes or backslashes, which would otherwise break out of the string.
func hxToast(message, level string) string {
	payload := map[string]interface{}{
		"showToast": map[string]string{
			"message": message,
			"type":    level,
		},
		"refreshStats": true,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("hxToast: %v", err)
		return ""
	}
	return string(encoded)
}

// Domain error classes, so handlers can choose an HTTP status without matching on
// error strings.

// userInputError marks a failure caused by what the caller submitted, not a server fault.
type userInputError struct{ msg string }

func (e userInputError) Error() string { return e.msg }

// notFoundError marks an operation against a user that does not exist.
type notFoundError struct{ user string }

func (e notFoundError) Error() string { return fmt.Sprintf("user %q not found", e.user) }

// httpStatusFor maps a domain error onto a response status. Anything unrecognised is a
// server fault, since it means a command or a file operation failed unexpectedly.
func httpStatusFor(err error) int {
	var inputErr userInputError
	var missing notFoundError
	switch {
	case errors.As(err, &inputErr):
		return http.StatusUnprocessableEntity
	case errors.As(err, &missing):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// firstLine reduces command output to something fit for an HTTP response: the first
// non-empty line of stdout/stderr, falling back to the error itself when the command
// printed nothing.
func firstLine(out string, err error) string {
	for _, line := range strings.Split(out, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	if err != nil {
		return err.Error()
	}
	return "unknown error"
}

// easyrsaGenCrl regenerates the CRL. Replaces "cd <dir> && easyrsa gen-crl".
func easyrsaGenCrl() error {
	out, err := runCmdDir(*easyrsaDirPath, *easyrsaBinPath, "gen-crl")
	if err != nil {
		log.Errorf("easyrsaGenCrl: %v", err)
		return fmt.Errorf("gen-crl: %s", firstLine(out, err))
	}
	log.Debug(out)
	return nil
}

// openvpnUserHasRecord reports whether the password database already holds a row for
// username. Previously: openvpn-user check ... | grep <user> | wc -l, compared to "0".
// On error the user is assumed to exist, matching the previous behaviour (the old
// pipeline returned error text, which never equalled "0").
func openvpnUserHasRecord(username string) bool {
	out, err := runCmd("openvpn-user", "check", "--db.path", *authDatabase, "--user", username)
	if err != nil {
		log.Errorf("openvpnUserHasRecord: %v", err)
		return true
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, username) {
			return true
		}
	}
	return false
}

func (oAdmin *OvpnAdmin) userChangePassword(username, password string) (string, error) {

	if checkUserExist(username) {
		if err := validatePassword(password); err != nil {
			log.Warningf("userChangePassword: %s", err.Error())
			return err.Error(), err
		}

		if !openvpnUserHasRecord(username) {
			out, err := runCmd("openvpn-user", "create", "--db.path", *authDatabase, "--user", username, "--password", password)
			if err != nil {
				log.Errorf("userChangePassword: openvpn-user create(%s): %v", username, err)
				return fmt.Sprintf("Could not create password record for user %q: %s", username, firstLine(out, err)), err
			}
			log.Debug(out)
		}

		out, err := runCmd("openvpn-user", "change-password", "--db.path", *authDatabase, "--user", username, "--password", password)
		if err != nil {
			log.Errorf("userChangePassword: openvpn-user change-password(%s): %v", username, err)
			return fmt.Sprintf("Could not change password for user %q: %s", username, firstLine(out, err)), err
		}
		log.Debug(out)

		log.Infof("Password for user %s was changed", username)

		return "Password changed", nil
	}

	return fmt.Sprintf("User %q not found", username), notFoundError{username}
}

func (oAdmin *OvpnAdmin) getUserStatistic(username string) []clientStatus {
	var userStatistic []clientStatus
	for _, u := range oAdmin.getActiveClients() {
		if u.CommonName == username {
			userStatistic = append(userStatistic, u)
		}
	}
	return userStatistic
}

func (oAdmin *OvpnAdmin) userRevoke(username string) (string, error) {
	log.Infof("Revoke certificate for user %s", username)
	if checkUserExist(username) {
		// check certificate valid flag 'V'
		if *storageBackend == "kubernetes.secrets" {
			if err := app.easyrsaRevoke(username); err != nil {
				log.Errorf("userRevoke: easyrsaRevoke(%s): %v", username, err)
				return fmt.Sprintf("Could not revoke certificate for user %q: %s", username, err), err
			}
		} else {
			out, err := runCmdInput(*easyrsaDirPath, "yes\n", *easyrsaBinPath, "revoke", username)
			if err != nil {
				log.Errorf("userRevoke: revoke(%s): %v", username, err)
				return fmt.Sprintf("Could not revoke certificate for user %q: %s", username, firstLine(out, err)), err
			}
			log.Debugln(out)
			if err := easyrsaGenCrl(); err != nil {
				return fmt.Sprintf("Certificate for %q was revoked but the CRL could not be regenerated: %s", username, err), err
			}
		}

		if *authByPassword {
			if out, err := runCmd("openvpn-user", "revoke", "--db.path", *authDatabase, "--user", username); err != nil {
				log.Errorf("userRevoke: openvpn-user revoke(%s): %v", username, err)
				return fmt.Sprintf("Certificate for %q was revoked but its password record was not: %s", username, firstLine(out, err)), err
			}
		}

		crlFix()
		userConnected, userConnectedTo := isUserConnected(username, oAdmin.getActiveClients())
		log.Tracef("User %s connected: %t", username, userConnected)
		if userConnected {
			for _, connection := range userConnectedTo {
				oAdmin.mgmtKillUserConnection(username, connection)
				log.Infof("Session for user \"%s\" killed", username)
			}
		}

		oAdmin.setState()
		return fmt.Sprintf("user \"%s\" revoked", username), nil
	}
	log.Infof("user \"%s\" not found", username)
	return fmt.Sprintf("User %q not found", username), notFoundError{username}
}

func (oAdmin *OvpnAdmin) userUnrevoke(username string) (string, error) {
	// Set when the certificate is restored but a dependent step fails, so the caller
	// learns the account is only partially usable.
	var unrevokeErr error

	if checkUserExist(username) {
		if *storageBackend == "kubernetes.secrets" {
			if err := app.easyrsaUnrevoke(username); err != nil {
				log.Errorf("userUnrevoke: easyrsaUnrevoke(%s): %v", username, err)
				return fmt.Sprintf("Could not restore certificate for user %q: %s", username, err), err
			}
		} else {
			// check certificate revoked flag 'R'
			usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					if usersFromIndexTxt[i].Flag == "R" {

						usersFromIndexTxt[i].Flag = "V"
						usersFromIndexTxt[i].RevocationDate = ""

						// revoke leaves one archived certificate, but it has to come back
						// to two places - issued/<name>.crt and certs_by_serial/<serial>.pem
						// - so the first restore is a copy and only the second consumes it.
						revokedCrt := fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber)
						err := fCopy(revokedCrt, fmt.Sprintf("%s/pki/issued/%s.crt", *easyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fMove(revokedCrt, fmt.Sprintf("%s/pki/certs_by_serial/%s.pem", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/private_by_serial/%s.key", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/private/%s.key", *easyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/reqs_by_serial/%s.req", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/reqs/%s.req", *easyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						if err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
							log.Errorf("userUnrevoke: write index.txt: %v", err)
							return fmt.Sprintf("Could not update the certificate index for user %q: %s", username, err), err
						}

						if crlErr := easyrsaGenCrl(); crlErr != nil {
							log.Errorf("userUnrevoke: %v", crlErr)
						}

						if *authByPassword {
							if out, rErr := runCmd("openvpn-user", "restore", "--db.path", *authDatabase, "--user", username); rErr != nil {
								log.Errorf("userUnrevoke: openvpn-user restore(%s): %v", username, rErr)
								unrevokeErr = fmt.Errorf("certificate for %q was restored, but its password record was not: %s", username, firstLine(out, rErr))
							}
						}

						crlFix()

						break
					}
				}
			}
			if err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
				log.Errorf("userUnrevoke: write index.txt: %v", err)
				return fmt.Sprintf("Could not update the certificate index for user %q: %s", username, err), err
			}
		}
		crlFix()
		oAdmin.setClients(oAdmin.usersList())
		if unrevokeErr != nil {
			return fmt.Sprintf("User %q partially unrevoked", username), unrevokeErr
		}
		return fmt.Sprintf("User %q successfully unrevoked", username), nil
	}
	return fmt.Sprintf("User %q not found", username), notFoundError{username}
}

func (oAdmin *OvpnAdmin) userRotate(username, newPassword string) (string, error) {
	if checkUserExist(username) {
		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaRotate(username, newPassword)
			if err != nil {
				log.Error(err)
			}
		} else {

			var oldUserIndex, newUserIndex int
			var oldUserSerial string

			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)

			usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					oldUserSerial = usersFromIndexTxt[i].SerialNumber
					usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + username + "-" + uniqHash
					oldUserIndex = i
					break
				}
			}
			err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}

			// The old certificate is still filed under this name, and easyrsa
			// refuses build-client-full while those files exist - the rename
			// above only freed the name inside the index.
			archiveUserPkiFiles(username, oldUserSerial)

			if *authByPassword {
				logCmd("openvpn-user", "delete", "--force", "--db.path", *authDatabase, "--user", username)
			}

			userCreated, userCreateMessage, userCreateErr := oAdmin.userCreate(username, newPassword)
			if !userCreated {
				restoreUserPkiFiles(username, oldUserSerial)
				usersFromIndexTxt = indexTxtParser(fRead(*indexTxtPath))
				for i := range usersFromIndexTxt {
					if usersFromIndexTxt[i].SerialNumber == oldUserSerial {
						usersFromIndexTxt[i].DistinguishedName = "/CN=" + username
						break
					}
				}
				err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
				if err != nil {
					log.Error(err)
				}
				// Propagated so a validation failure during rotate is still classified
				// as caller error rather than a server fault.
				return userCreateMessage, fmt.Errorf("error rotating user %q: %w", username, userCreateErr)
			}

			usersFromIndexTxt = indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					newUserIndex = i
				}
				if usersFromIndexTxt[i].SerialNumber == oldUserSerial {
					oldUserIndex = i
				}
			}
			usersFromIndexTxt[oldUserIndex], usersFromIndexTxt[newUserIndex] = usersFromIndexTxt[newUserIndex], usersFromIndexTxt[oldUserIndex]

			if err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
				log.Errorf("userRotate: write index.txt: %v", err)
				return fmt.Sprintf("Could not update the certificate index for user %q: %s", username, err), err
			}

			if err := easyrsaGenCrl(); err != nil {
				return fmt.Sprintf("User %q rotated, CRL not regenerated", username),
					fmt.Errorf("user %q was rotated but the CRL could not be regenerated: %s", username, err)
			}
		}
		crlFix()
		oAdmin.setClients(oAdmin.usersList())
		return fmt.Sprintf("User %q successfully rotated", username), nil
	}
	return fmt.Sprintf("User %q not found", username), notFoundError{username}
}

// authAttempt is one line of the login log that setup/auth.sh appends to on the
// OpenVPN host: every password-auth attempt with its outcome, never the password.
type authAttempt struct {
	Timestamp  string
	Outcome    string // success, bad-password, cn-mismatch, empty-creds
	Username   string
	CommonName string
	Source     string // ip:port the attempt came from
}

// parseAuthLog reads the attempt log newest first, capped at limit entries. The
// rotated generation (auth.log.1) is read too, so history does not collapse to
// near-nothing right after auth.sh rolls the file over.
// Lines that do not parse are skipped: the file is written by a shell script on
// another container, so a torn or foreign line must never take the page down.
// A missing file is normal - password auth may be off, or nobody has ever
// tried to log in.
func parseAuthLog(path string, limit int) []authAttempt {
	if path == "" {
		return nil
	}
	// Older generation first so the combined slice runs oldest to newest.
	// Checked rather than letting fRead warn: a missing file is the normal
	// state here, and this runs per render.
	var content string
	for _, p := range []string{path + ".1", path} {
		if fExist(p) {
			content += fRead(p)
		}
	}
	if content == "" {
		return nil
	}
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	attempts := make([]authAttempt, 0, min(limit, len(lines)))
	for i := len(lines) - 1; i >= 0 && len(attempts) < limit; i-- {
		fields := strings.Split(lines[i], "\t")
		if len(fields) < 5 || fields[0] == "" || fields[1] == "" {
			continue
		}
		attempts = append(attempts, authAttempt{
			Timestamp:  fields[0],
			Outcome:    fields[1],
			Username:   fields[2],
			CommonName: fields[3],
			Source:     fields[4],
		})
	}
	return attempts
}

// authLoginStats condenses the attempt log per certificate CN: when the user
// last logged in, and how many attempts have failed since then. The count keys
// on the certificate's CN rather than the typed username, so a cn-mismatch
// probe lands on the account whose certificate was used.
type loginStats struct {
	LastLogin    string
	FailedLogins int
}

func authLoginStats(path string) map[string]loginStats {
	// Oldest first: iterate chronologically so a success resets the counter.
	attempts := parseAuthLog(path, authLogParseLimit)
	stats := make(map[string]loginStats)
	for i := len(attempts) - 1; i >= 0; i-- {
		a := attempts[i]
		name := a.CommonName
		if name == "" {
			name = a.Username
		}
		if name == "" {
			continue
		}
		s := stats[name]
		if a.Outcome == "success" {
			s.LastLogin = a.Timestamp
			s.FailedLogins = 0
		} else {
			s.FailedLogins++
		}
		stats[name] = s
	}
	return stats
}

// pkiArchiveFilePairs maps the per-name files easyrsa keeps for username onto
// the by-serial locations under pki/revoked - the same layout `easyrsa revoke`
// uses when it moves a revoked certificate aside.
func pkiArchiveFilePairs(username, serial string) [][2]string {
	pki := *easyrsaDirPath + "/pki"
	return [][2]string{
		{pki + "/issued/" + username + ".crt", pki + "/revoked/certs_by_serial/" + serial + ".crt"},
		{pki + "/private/" + username + ".key", pki + "/revoked/private_by_serial/" + serial + ".key"},
		{pki + "/reqs/" + username + ".req", pki + "/revoked/reqs_by_serial/" + serial + ".req"},
	}
}

// archiveUserPkiFiles moves any files still stored under username's name out of
// the way. easyrsa refuses build-client-full for a name whose request file
// exists, and only `easyrsa revoke` relocates these files itself; an expired
// certificate never went through revoke, so deleting one would otherwise block
// the username from ever being created again.
func archiveUserPkiFiles(username, serial string) {
	for _, pair := range pkiArchiveFilePairs(username, serial) {
		if !fExist(pair[0]) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(pair[1]), 0o700); err != nil {
			log.Warnf("archiveUserPkiFiles: %v - recreating user %q may fail until %s is removed", err, username, pair[0])
			continue
		}
		if err := fMove(pair[0], pair[1]); err != nil {
			log.Warnf("archiveUserPkiFiles: %v - recreating user %q may fail until %s is removed", err, username, pair[0])
		}
	}
}

// archiveOrphanedUserPkiFiles clears certificate files stranded under a name
// whose index entry is gone. Callers must have already established that no
// /CN=<username> entry exists. The serial comes from the newest
// REVOKED-<username>-* entry - the rename a delete leaves behind - so the
// files land where a delete today would have put them; a name with no such
// entry (index rebuilt, out-of-band cleanup) gets a generated one.
func archiveOrphanedUserPkiFiles(username string) {
	leftover := false
	for _, pair := range pkiArchiveFilePairs(username, "") {
		if fExist(pair[0]) {
			leftover = true
			break
		}
	}
	if !leftover {
		return
	}

	serial := ""
	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if strings.HasPrefix(line.DistinguishedName, "/CN=REVOKED-"+username+"-") {
			// Entries are appended in issue order, so the last match belongs to
			// the most recently deleted certificate - the one the files are from.
			serial = line.SerialNumber
		}
	}
	if serial == "" {
		serial = "orphan-" + strings.Replace(uuid.New().String(), "-", "", -1)
	}

	log.Warnf("found certificate files for %q left behind by an earlier delete, archiving them under serial %s", username, serial)
	archiveUserPkiFiles(username, serial)
}

// restoreUserPkiFiles is the inverse of archiveUserPkiFiles, for a rotate whose
// replacement certificate could not be created. A file only moves back when
// nothing new has been written over the original name in the meantime.
func restoreUserPkiFiles(username, serial string) {
	for _, pair := range pkiArchiveFilePairs(username, serial) {
		if fExist(pair[1]) && !fExist(pair[0]) {
			if err := fMove(pair[1], pair[0]); err != nil {
				log.Warnf("restoreUserPkiFiles: %v", err)
			}
		}
	}
}

func (oAdmin *OvpnAdmin) userDelete(username string) (string, error) {
	if checkUserExist(username) {
		// Deleting only renames the index entry, it does not flip the certificate to
		// revoked. Removing an active user would therefore leave a valid certificate
		// that never enters the CRL, so the holder could keep connecting. Require the
		// certificate to be revoked or expired first, which is what the per-row buttons
		// have always offered.
		if oAdmin.userAccountStatus(username) == "Active" {
			return fmt.Sprintf("User %q is still active - revoke the certificate before deleting it", username),
				userInputError{fmt.Sprintf("user %q is still active", username)}
		}

		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaDelete(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
			var deletedSerial string
			usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					deletedSerial = usersFromIndexTxt[i].SerialNumber
					usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + username + "-" + uniqHash
					break
				}
			}
			// Write the index first: it is the record that decides whether the user
			// exists. If it fails nothing else should be touched.
			if err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
				log.Errorf("userDelete: write index.txt: %v", err)
				return fmt.Sprintf("Could not update the certificate index for user %q: %s", username, err), err
			}

			// The index no longer lists the name, but easyrsa still refuses to issue
			// for it while these files exist. A revoked certificate had them moved by
			// `easyrsa revoke` already; an expired one did not.
			archiveUserPkiFiles(username, deletedSerial)

			if *authByPassword {
				if out, err := runCmd("openvpn-user", "delete", "--force", "--db.path", *authDatabase, "--user", username); err != nil {
					log.Errorf("userDelete: openvpn-user delete(%s): %v", username, err)
					return fmt.Sprintf("User %q partially deleted", username),
						fmt.Errorf("user %q was removed from the certificate index, but its password record could not be deleted: %s", username, firstLine(out, err))
				}
			}

			if err := easyrsaGenCrl(); err != nil {
				return fmt.Sprintf("User %q deleted, CRL not regenerated", username),
					fmt.Errorf("user %q was deleted but the CRL could not be regenerated: %s", username, err)
			}
		}
		crlFix()
		oAdmin.setClients(oAdmin.usersList())
		return fmt.Sprintf("User %q successfully deleted", username), nil
	}
	return fmt.Sprintf("User %q not found", username), notFoundError{username}
}

// mgmtRead drains one management-interface reply. The deadline moves forward
// before every read, so a large status report that streams in over several
// seconds is not cut off mid-line; the read ends early only when the socket
// goes quiet for mgmtReadTimeout or the whole reply exceeds
// mgmtReadOverallTimeout. An early end is logged, because a truncated status
// reply understates who is connected.
func (oAdmin *OvpnAdmin) mgmtRead(conn net.Conn) string {
	recvData := make([]byte, 32768)
	var out string
	overall := time.Now().Add(mgmtReadOverallTimeout)
	for {
		idle := time.Now().Add(mgmtReadTimeout)
		if idle.After(overall) {
			idle = overall
		}
		if err := conn.SetReadDeadline(idle); err != nil {
			log.Warnf("mgmtRead: could not set read deadline: %v", err)
		}
		n, err := conn.Read(recvData)
		if n > 0 {
			out += string(recvData[:n])
			if strings.Contains(out, "type 'help' for more info") || strings.Contains(out, "END") || strings.Contains(out, "SUCCESS:") || strings.Contains(out, "ERROR:") {
				break
			}
		}
		if err != nil || n <= 0 {
			log.Warnf("mgmtRead: reply from %s ended after %d bytes without a recognised terminator: %v", conn.RemoteAddr(), len(out), err)
			break
		}
	}
	return out
}

func (oAdmin *OvpnAdmin) mgmtConnectedUsersParser(text, serverName string) []clientStatus {
	var u []clientStatus
	isClientList := false
	isRouteTable := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		txt := scanner.Text()
		if txt == "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since" {
			isClientList = true
			continue
		}
		if txt == "ROUTING TABLE" {
			isClientList = false
			continue
		}
		if txt == "Virtual Address,Common Name,Real Address,Last Ref" {
			isRouteTable = true
			continue
		}
		if txt == "GLOBAL STATS" {
			break
		}
		if isClientList {
			user := strings.Split(txt, ",")
			// A reply can end mid-line when mgmtRead hits its deadline, and this
			// parser also runs in the background updateState goroutine, where an
			// index-out-of-range panic would kill the whole process.
			if len(user) < 5 {
				log.Warnf("mgmtConnectedUsersParser: skipping malformed client line from %s: %q", serverName, txt)
				continue
			}

			userName := user[0]
			userAddress := user[1]
			userBytesReceived := user[2]
			userBytesSent := user[3]
			userConnectedSince := user[4]

			userStatus := clientStatus{CommonName: userName, RealAddress: userAddress, BytesReceived: userBytesReceived, BytesSent: userBytesSent, ConnectedSince: userConnectedSince, ConnectedTo: serverName}
			u = append(u, userStatus)
			bytesSent, _ := strconv.Atoi(userBytesSent)
			bytesReceive, _ := strconv.Atoi(userBytesReceived)
			ovpnClientConnectionFrom.WithLabelValues(userName, userAddress).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, userConnectedSince)))
			ovpnClientBytesSent.WithLabelValues(userName).Set(float64(bytesSent))
			ovpnClientBytesReceived.WithLabelValues(userName).Set(float64(bytesReceive))
		}
		if isRouteTable {
			user := strings.Split(txt, ",")
			if len(user) < 4 {
				log.Warnf("mgmtConnectedUsersParser: skipping malformed route line from %s: %q", serverName, txt)
				continue
			}
			for i := range u {
				if u[i].CommonName == user[1] {
					u[i].VirtualAddress = user[0]
					u[i].LastRef = user[3]
					ovpnClientConnectionInfo.WithLabelValues(user[1], user[0]).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, user[3])))
					break
				}
			}
		}
	}
	return u
}

func (oAdmin *OvpnAdmin) mgmtKillUserConnection(username, serverName string) {
	conn, err := net.DialTimeout("tcp", oAdmin.mgmtInterfaces[serverName], mgmtDialTimeout)
	if err != nil {
		log.Errorf("openvpn mgmt interface for %s is not reachable by addr %s", serverName, oAdmin.mgmtInterfaces[serverName])
		return
	}
	oAdmin.mgmtRead(conn) // read welcome message
	if _, err := conn.Write([]byte(fmt.Sprintf("kill %s\n", username))); err != nil {
		log.Warnf("mgmtKillUserConnection: write to %s: %v", serverName, err)
	}
	log.Debugf("mgmtKillUserConnection: %s", oAdmin.mgmtRead(conn))
	conn.Close()
}

func (oAdmin *OvpnAdmin) mgmtGetActiveClients() []clientStatus {
	var activeClients []clientStatus

	for srv, addr := range oAdmin.mgmtInterfaces {
		conn, err := net.DialTimeout("tcp", addr, mgmtDialTimeout)
		if err != nil {
			log.Warnf("openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			// Skip this server, do not abandon the rest: mgmtInterfaces is a map, so
			// `break` dropped a random subset of the remaining servers' clients.
			continue
		}
		oAdmin.mgmtRead(conn) // read welcome message
		conn.Write([]byte("status 1\n"))
		activeClients = append(activeClients, oAdmin.mgmtConnectedUsersParser(oAdmin.mgmtRead(conn), srv)...)
		conn.Close()
	}
	return activeClients
}

func (oAdmin *OvpnAdmin) mgmtSetTimeFormat() {
	// time format for version 2.5 and may be newer
	oAdmin.mgmtStatusTimeFormat = "2006-01-02 15:04:05"
	log.Debugf("mgmtStatusTimeFormat: %s", oAdmin.mgmtStatusTimeFormat)

	type serverVersion struct {
		name    string
		version string
	}

	var serverVersions []serverVersion

	for srv, addr := range oAdmin.mgmtInterfaces {

		var conn net.Conn
		var err error
		for connAttempt := 0; connAttempt < mgmtConnectRetries; connAttempt++ {
			conn, err = net.DialTimeout("tcp", addr, mgmtDialTimeout)
			if err == nil {
				log.Debugf("mgmtSetTimeFormat: successful connection to %s/%s", srv, addr)
				break
			}
			log.Warnf("mgmtSetTimeFormat: openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			time.Sleep(mgmtConnectRetrySleep)
		}
		if err != nil {
			// Skip this server, do not abandon the rest: mgmtInterfaces is a map,
			// so `break` dropped a random subset of the remaining servers.
			continue
		}

		oAdmin.mgmtRead(conn) // read welcome message
		conn.Write([]byte("version\n"))
		out := oAdmin.mgmtRead(conn)
		conn.Close()

		log.Trace(out)

		for _, s := range strings.Split(out, "\n") {
			if strings.Contains(s, "OpenVPN Version:") {
				serverVersions = append(serverVersions, serverVersion{srv, strings.Split(s, " ")[3]})
				break
			}
		}
	}

	if len(serverVersions) == 0 {
		return
	}

	firstVersion := serverVersions[0].version

	if strings.HasPrefix(firstVersion, "2.4") {
		oAdmin.mgmtStatusTimeFormat = time.ANSIC
		log.Debugf("mgmtStatusTimeFormat changed: %s", oAdmin.mgmtStatusTimeFormat)
	}

	warn := ""
	for _, v := range serverVersions {
		if firstVersion != v.version {
			warn = "mgmtSetTimeFormat: servers have different versions of openvpn, user connection status may not work"
			log.Warn(warn)
			break
		}
	}

	if warn != "" {
		for _, v := range serverVersions {
			log.Infof("server name: %s, version: %s", v.name, v.version)
		}
	}
}

func isUserConnected(username string, connectedUsers []clientStatus) (bool, []string) {
	var connections []string
	var connected = false

	for _, connectedUser := range connectedUsers {
		if connectedUser.CommonName == username {
			connected = true
			connections = append(connections, connectedUser.ConnectedTo)
		}
	}
	return connected, connections
}

func (oAdmin *OvpnAdmin) downloadCerts() bool {
	if fExist(certsArchivePath) {
		err := fDelete(certsArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(certsArchivePath, *masterHost+*listenBaseUrl+downloadCertsApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (oAdmin *OvpnAdmin) downloadCcd() bool {
	if fExist(ccdArchivePath) {
		err := fDelete(ccdArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(ccdArchivePath, *masterHost+*listenBaseUrl+downloadCcdApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func archiveCerts() {
	err := createArchiveFromDir(*easyrsaDirPath+"/pki", certsArchivePath)
	if err != nil {
		log.Warnf("archiveCerts(): %s", err)
	}
}

func archiveCcd() {
	err := createArchiveFromDir(*ccdDir, ccdArchivePath)
	if err != nil {
		log.Warnf("archiveCcd(): %s", err)
	}
}

func unArchiveCerts() error {
	if err := os.MkdirAll(*easyrsaDirPath+"/pki", 0755); err != nil {
		return fmt.Errorf("unArchiveCerts: %w", err)
	}
	if err := extractFromArchive(certsArchivePath, *easyrsaDirPath+"/pki"); err != nil {
		return fmt.Errorf("unArchiveCerts: %w", err)
	}
	return nil
}

func unArchiveCcd() error {
	if err := os.MkdirAll(*ccdDir, 0755); err != nil {
		return fmt.Errorf("unArchiveCcd: %w", err)
	}
	if err := extractFromArchive(ccdArchivePath, *ccdDir); err != nil {
		return fmt.Errorf("unArchiveCcd: %w", err)
	}
	return nil
}

func ovpnUserInitDb() {
	if fi, err := os.Stat(*authDatabase); errors.Is(err, os.ErrNotExist) || fi.Size() == 0 {
		if out, err := runCmd("openvpn-user", "--db.path", *authDatabase, "db-init"); err != nil {
			log.Errorf("ovpnUserInitDb: db-init: %v", err)
			return
		} else {
			log.Debug(out)
		}
		logCmd("openvpn-user", "--db.path", *authDatabase, "db-migrate")
	}
}

func (oAdmin *OvpnAdmin) syncDataFromMaster() {
	retryCountMax := 3
	certsDownloadFailed := true
	ccdDownloadFailed := true

	// A round only counts as successful when the archive both downloaded and
	// extracted: a corrupt or truncated download is retried like a failed one.
	for certsDownloadRetries := 0; certsDownloadRetries < retryCountMax; certsDownloadRetries++ {
		log.Infof("Downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		if !oAdmin.downloadCerts() {
			log.Warnf("Something goes wrong during downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
			continue
		}
		log.Info("Decompressing archive with certificates from master")
		if err := unArchiveCerts(); err != nil {
			log.Warnf("Could not decompress archive with certificates from master: %v. Attempt %d", err, certsDownloadRetries)
			continue
		}
		certsDownloadFailed = false
		log.Info("Decompression archive with certificates from master completed")
		break
	}

	for ccdDownloadRetries := 0; ccdDownloadRetries < retryCountMax; ccdDownloadRetries++ {
		log.Infof("Downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		if !oAdmin.downloadCcd() {
			log.Warnf("Something goes wrong during downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
			continue
		}
		log.Info("Decompressing archive with ccd from master")
		if err := unArchiveCcd(); err != nil {
			log.Warnf("Could not decompress archive with ccd from master: %v. Attempt %d", err, ccdDownloadRetries)
			continue
		}
		ccdDownloadFailed = false
		log.Info("Decompression archive with ccd from master completed")
		break
	}

	oAdmin.markSyncAttempt(time.Now().Format(stringDateFormat), !ccdDownloadFailed && !certsDownloadFailed)
}

func (oAdmin *OvpnAdmin) syncWithMaster() {
	for {
		time.Sleep(time.Duration(*masterSyncFrequency) * time.Second)
		oAdmin.syncDataFromMaster()
	}
}

func getOvpnServerHostsFromKubeApi() ([]OpenvpnServer, error) {
	var hosts []OpenvpnServer
	var lbHost string

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	for _, serviceName := range *openvpnServiceName {
		service, err := clientset.CoreV1().Services(fRead(kubeNamespaceFilePath)).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			log.Error(err)
		}

		log.Tracef("service from kube api %v", service)
		log.Tracef("service.Status from kube api %v", service.Status)
		log.Tracef("service.Status.LoadBalancer from kube api %v", service.Status.LoadBalancer)

		lbIngress := service.Status.LoadBalancer.Ingress
		if len(lbIngress) > 0 {
			if lbIngress[0].Hostname != "" {
				lbHost = lbIngress[0].Hostname
			}

			if lbIngress[0].IP != "" {
				lbHost = lbIngress[0].IP
			}
		}

		hosts = append(hosts, OpenvpnServer{lbHost, strconv.Itoa(int(service.Spec.Ports[0].Port)), strings.ToLower(string(service.Spec.Ports[0].Protocol))})
	}

	if len(hosts) == 0 {
		return []OpenvpnServer{{Host: "kubernetes services not found"}}, err
	}

	return hosts, nil
}

func getOvpnCaCertExpireDate() time.Time {
	caCertPath := *easyrsaDirPath + "/pki/ca.crt"
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("error read file %s: %s", caCertPath, err.Error())
		return time.Now()
	}

	certPem, _ := pem.Decode(caCert)
	if certPem == nil {
		// This runs at startup via setState, so a missing or garbled CA file
		// must degrade to a bogus expiry, not a nil-dereference panic.
		log.Errorf("no PEM certificate found in %s", caCertPath)
		return time.Now()
	}

	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		log.Errorf("error parse certificate ca.crt: %s", err.Error())
		return time.Now()
	}

	return cert.NotAfter
}

// https://community.openvpn.net/openvpn/ticket/623
func crlFix() {
	err := os.Chmod(*easyrsaDirPath+"/pki", 0755)
	if err != nil {
		log.Error(err)
	}
	err = os.Chmod(*easyrsaDirPath+"/pki/crl.pem", 0644)
	if err != nil {
		log.Error(err)
	}
}

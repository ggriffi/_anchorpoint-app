package main

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"anchorpoint-it.com/webapp/internal/network"
	"anchorpoint-it.com/webapp/internal/system"
	_ "github.com/mattn/go-sqlite3" // Ensure you've run 'go get github.com/mattn/go-sqlite3'
)

type templateData struct {
	GatewayStatus    string
	MemoryUsage      string
	DockerContainers string
	ClientIP         string
	ServerPublicIP   string
	PingResult       string
	TraceResult      string
	MTRResult        string
	SpeedtestResult  string
	IperfResult      string
}

type HopGeo struct {
	IP  string  `json:"ip"`
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type DiagResponse struct {
	Output string   `json:"output"`
	Coords []HopGeo `json:"coords"`
}

type application struct {
	errorLog *log.Logger
	infoLog  *log.Logger
	db       *sql.DB
}

func main() {
	logPath := "/app/info.log"
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	infoLog := log.New(f, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(f, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	// 1. Initialize Database BEFORE server start
	db, err := sql.Open("sqlite3", "./anchorpoint.db")
	if err != nil {
		errorLog.Fatal(err)
	}
	defer db.Close()

	// Ensure users table exists
	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
	statement.Exec()

	app := &application{
		errorLog: errorLog,
		infoLog:  infoLog,
		db:       db,
	}

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "4000"
	}

	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/login", app.login)

	// Protected routes
	mux.Handle("/", app.requireAuthentication(http.HandlerFunc(app.home)))

	standardMiddleware := app.recoverPanic(app.logRequest(mux))

	srv := &http.Server{
		Addr:         ":" + port,
		ErrorLog:     errorLog,
		Handler:      standardMiddleware,
		IdleTimeout:  2 * time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 2 * time.Minute,
	}

	app.infoLog.Printf("Starting Anchorpoint-IT on %s", srv.Addr)
	err = srv.ListenAndServe()
	errorLog.Fatal(err)
}

func (app *application) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if refreshType := r.URL.Query().Get("refresh"); refreshType != "" {
		switch refreshType {
		case "docker":
			w.Write([]byte(system.GetDockerContainers()))
		case "logs":
			w.Write([]byte(app.getLogs()))
		case "stats":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]float64{
				"memPercent": system.GetMemPercent(),
			})
		default:
			http.Error(w, "Unknown refresh type", http.StatusBadRequest)
		}
		return
	}

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if proxyIP := r.Header.Get("X-Forwarded-For"); proxyIP != "" {
		clientIP = proxyIP
	}

	data := &templateData{
		GatewayStatus:    "Online",
		MemoryUsage:      system.GetMemStats(),
		DockerContainers: system.GetDockerContainers(),
		ClientIP:         clientIP,
		ServerPublicIP:   network.GetPublicIP(),
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		var currentResult string

		if ip := r.PostForm.Get("ping_ip"); ip != "" {
			if network.Ping(ip) {
				currentResult = ip + " is reachable."
			} else {
				currentResult = ip + " is unreachable."
			}
		} else if ip := r.PostForm.Get("trace_ip"); ip != "" {
			res, _ := network.Traceroute(ip)
			currentResult = res
		} else if ip := r.PostForm.Get("mtr_ip"); ip != "" {
			res, _ := network.MTR(ip)
			currentResult = res
		} else if r.PostForm.Has("speedtest_run") {
			res, _ := network.RunSpeedtest()
			currentResult = res
		} else if ip := r.PostForm.Get("iperf_ip"); ip != "" {
			res, _ := network.RunIperf(ip)
			currentResult = res
		}

		if r.Header.Get("Accept") == "application/json" {
			ips := extractIPs(currentResult)
			var coords []HopGeo
			for _, ip := range ips {
				if ip != "127.0.0.1" && ip != "0.0.0.0" {
					geo := getGeo(ip)
					if geo.Lat != 0 || geo.Lon != 0 {
						coords = append(coords, geo)
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(DiagResponse{Output: currentResult, Coords: coords})
			return
		}
	}

	ts, _ := template.ParseFiles("./web/html/home.page.tmpl", "./web/html/base.layout.tmpl")
	ts.Execute(w, data)
}

func (app *application) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 1. Define files
		files := []string{
			"./web/html/login.page.tmpl",
			"./web/html/base.layout.tmpl",
		}

		// 2. Parse and CHECK FOR ERRORS
		ts, err := template.ParseFiles(files...)
		if err != nil {
			app.errorLog.Printf("Template Error: %v", err)
			http.Error(w, "Internal Server Error - Missing Templates", 500)
			return
		}

		// 3. Execute
		ts.Execute(w, nil)
		return
	}

	r.ParseForm()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *application) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !app.isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (app *application) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("authenticated")
	if err != nil {
		return false // No cookie, not authenticated
	}
	return cookie.Value == "true"
}

func (app *application) getLogs() string {
	content, err := os.ReadFile("/app/info.log")
	if err != nil {
		return "Log Error: " + err.Error()
	}
	lines := strings.Split(string(content), "\n")
	var cleanLines []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			cleanLines = append(cleanLines, line)
		}
	}
	if len(cleanLines) > 20 {
		cleanLines = cleanLines[len(cleanLines)-20:]
	}
	return strings.Join(cleanLines, "\n")
}

func (app *application) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.infoLog.Printf("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connection", "close")
				app.errorLog.Printf("%s", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func getGeo(ip string) HopGeo {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return HopGeo{IP: ip}
	}
	defer resp.Body.Close()
	var geo HopGeo
	json.NewDecoder(resp.Body).Decode(&geo)
	return geo
}

func extractIPs(text string) []string {
	re := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	return re.FindAllString(text, -1)
}

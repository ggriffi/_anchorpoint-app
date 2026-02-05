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
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
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

type settingsData struct {
	Usernames        []string
	ServerPublicIP   string
	ClientIP         string
	MemoryUsage      string
	DockerContainers string
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

	// 1. Initialize Database
	db, err := sql.Open("sqlite3", "./anchorpoint.db")
	if err != nil {
		errorLog.Fatal(err)
	}
	defer db.Close()

	// 2. Ensure users table exists
	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
	statement.Exec()

	app := &application{
		errorLog: errorLog,
		infoLog:  infoLog,
		db:       db,
	}

	// 3. Bootstrap the root user
	app.bootstrapRootUser()

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "4000"
	}

	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/login", app.login)

	// Protected routes
	mux.Handle("/", app.requireAuthentication(http.HandlerFunc(app.home)))
	mux.Handle("/settings", app.requireAuthentication(http.HandlerFunc(app.createUser)))
	mux.Handle("/system", app.requireAuthentication(http.HandlerFunc(app.systemMonitor)))

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

		// Use a tagged switch for cleaner diagnostic routing
		switch {
		case r.PostForm.Get("ping_ip") != "":
			ip := r.PostForm.Get("ping_ip")
			if network.Ping(ip) {
				currentResult = ip + " is reachable."
			} else {
				currentResult = ip + " is unreachable."
			}

		case r.PostForm.Get("trace_ip") != "":
			currentResult, _ = network.Traceroute(r.PostForm.Get("trace_ip"))

		case r.PostForm.Get("mtr_ip") != "":
			currentResult, _ = network.MTR(r.PostForm.Get("mtr_ip"))

		case r.PostForm.Has("speedtest_run"):
			currentResult, _ = network.RunSpeedtest()

		case r.PostForm.Get("iperf_ip") != "":
			// Executes Client Mode
			currentResult, _ = network.RunIperfClient(r.PostForm.Get("iperf_ip"))

		case r.PostForm.Has("iperf_server_run"):
			// Executes Server Mode (Listening on port 5201)
			currentResult, _ = network.RunIperfServer()
		}

		// Handle JSON response for the AJAX frontend
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
		files := []string{
			"./web/html/login.page.tmpl",
			"./web/html/base.layout.tmpl",
		}

		ts, err := template.ParseFiles(files...)
		if err != nil {
			app.errorLog.Printf("Template Error: %v", err)
			http.Error(w, "Internal Server Error - Missing Templates", 500)
			return
		}

		ts.Execute(w, nil)
		return
	}

	r.ParseForm()
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	var hashedPassword string
	err := app.db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)

	if err == nil {
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err == nil {
			cookie := &http.Cookie{
				Name:     "authenticated",
				Value:    "true",
				Path:     "/",
				HttpOnly: true,
				MaxAge:   86400,
			}
			http.SetCookie(w, cookie)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	app.infoLog.Printf("Failed login attempt for user: %s", username)
	http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
}

func (app *application) createUser(w http.ResponseWriter, r *http.Request) {
	// Helper to ensure we always have a slice, even if empty
	getUsers := func() []string {
		rows, err := app.db.Query("SELECT username FROM users ORDER BY username ASC")
		if err != nil {
			app.errorLog.Printf("DB Error fetching users: %v", err)
			return []string{}
		}
		defer rows.Close()

		usernames := []string{}
		for rows.Next() {
			var uname string
			if err := rows.Scan(&uname); err == nil {
				usernames = append(usernames, uname)
			}
		}
		return usernames
	}

	if r.Method == http.MethodGet {
		ts, err := template.ParseFiles("./web/html/settings.page.tmpl", "./web/html/base.layout.tmpl")
		if err != nil {
			app.errorLog.Printf("Template Parsing Error: %v", err)
			http.Error(w, "Internal Server Error", 500)
			return
		}

		// 1. Capture Client IP
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if proxyIP := r.Header.Get("X-Forwarded-For"); proxyIP != "" {
			clientIP = proxyIP
		}

		// 2. Wrap all data required by the templates (Matches templateData structure)
		data := &settingsData{
			Usernames:        getUsers(),
			ServerPublicIP:   network.GetPublicIP(),
			ClientIP:         clientIP,
			MemoryUsage:      system.GetMemStats(),         // Fixes current error
			DockerContainers: system.GetDockerContainers(), // Fixes potential next error
		}

		// 3. Execute template
		err = ts.Execute(w, data)
		if err != nil {
			app.errorLog.Printf("Template Execution Error: %v", err)
		}
		return
	}

	// POST logic
	r.ParseForm()
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		app.errorLog.Println(err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	_, err = app.db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(hashedPassword))
	if err != nil {
		app.errorLog.Println(err)
		http.Redirect(w, r, "/settings?error=duplicate", http.StatusSeeOther)
		return
	}

	app.infoLog.Printf("New user created: %s", username)
	http.Redirect(w, r, "/settings?success=1", http.StatusSeeOther)
}

func (app *application) bootstrapRootUser() {
	var exists bool
	err := app.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username='admin')").Scan(&exists)
	if err != nil {
		app.errorLog.Println("Bootstrap check failed:", err)
		return
	}

	if !exists {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("changeme123"), 12)
		if err != nil {
			app.errorLog.Println("Failed to hash bootstrap password:", err)
			return
		}

		_, err = app.db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", "admin", string(hashedPassword))
		if err != nil {
			app.errorLog.Println("Failed to create root user:", err)
		} else {
			app.infoLog.Println("Hashed root user 'admin' created successfully.")
		}
	}
}

func (app *application) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow login, static files, and favicon to bypass auth
		if r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/favicon.ico" {
			next.ServeHTTP(w, r)
			return
		}

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
		// This log will now show up in your dashboard's log view
		app.infoLog.Printf("Auth Check: No cookie found for path %s", r.URL.Path)
		return false
	}

	if cookie.Value != "true" {
		app.infoLog.Printf("Auth Check: Invalid cookie value: %s", cookie.Value)
		return false
	}

	return true
}

func (app *application) getLogs() string {
	content, err := os.ReadFile("/app/info.log")
	if err != nil {
		return "Log Error: " + err.Error()
	}

	lines := strings.Split(string(content), "\n")
	var cleanLines []string

	// Define patterns to ignore
	ignorePatterns := []string{
		"GET /?refresh=",
		"GET /static/",
		"GET /favicon.ico",
		"Auth Check: No cookie found for path /login",
	}

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		skip := false
		for _, pattern := range ignorePatterns {
			if strings.Contains(line, pattern) {
				skip = true
				break
			}
		}

		if !skip {
			cleanLines = append(cleanLines, line)
		}
	}

	// Now we can show more lines since they are "real" info
	limit := 50
	if len(cleanLines) > limit {
		cleanLines = cleanLines[len(cleanLines)-limit:]
	}

	return strings.Join(cleanLines, "\n")
}

func (app *application) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csp := []string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com https://static.cloudflareinsights.com",
			"style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com",
			"font-src 'self' https://fonts.gstatic.com",
			"img-src 'self' data: https://unpkg.com https://*.tile.openstreetmap.org https://anchorpoint-it.com",
			"connect-src 'self' https://static.cloudflareinsights.com https://cdn.jsdelivr.net https://unpkg.com",
		}
		w.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))
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

func (app *application) systemMonitor(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if proxyIP := r.Header.Get("X-Forwarded-For"); proxyIP != "" {
		clientIP = proxyIP
	}

	data := &templateData{
		MemoryUsage:      system.GetMemStats(),
		DockerContainers: system.GetDockerContainers(),
		ClientIP:         clientIP,
		ServerPublicIP:   network.GetPublicIP(),
	}

	ts, _ := template.ParseFiles("./web/html/system.page.tmpl", "./web/html/base.layout.tmpl")
	ts.Execute(w, data)
}

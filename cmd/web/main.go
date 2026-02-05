package main

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
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

type settingsData struct {
	Usernames        []string
	ServerPublicIP   string
	ClientIP         string
	MemoryUsage      string
	DockerContainers string
}

type application struct {
	errorLog *log.Logger
	infoLog  *log.Logger
	db       *sql.DB
}

func main() {
	f, _ := os.OpenFile("/app/info.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	defer f.Close()

	app := &application{
		infoLog:  log.New(f, "INFO\t", log.Ldate|log.Ltime),
		errorLog: log.New(f, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile),
	}

	db, _ := sql.Open("sqlite3", "./anchorpoint.db")
	app.db = db
	app.db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
	app.bootstrapRootUser()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", app.login)
	mux.Handle("/", app.requireAuthentication(http.HandlerFunc(app.home)))
	mux.Handle("/settings", app.requireAuthentication(http.HandlerFunc(app.createUser)))
	mux.Handle("/system", app.requireAuthentication(http.HandlerFunc(app.systemMonitor)))

	srv := &http.Server{
		Addr:    ":4000",
		Handler: app.recoverPanic(app.logRequest(mux)),
	}
	app.infoLog.Printf("Starting Anchorpoint-IT on %s", srv.Addr)
	srv.ListenAndServe()
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
			json.NewEncoder(w).Encode(map[string]float64{"memPercent": system.GetMemPercent()})
		}
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		var currentResult string

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
		case r.PostForm.Get("dns_ip") != "":
			out, _ := exec.Command("host", r.PostForm.Get("dns_ip")).CombinedOutput()
			currentResult = string(out)
		case r.PostForm.Get("whois_ip") != "":
			out, _ := exec.Command("whois", r.PostForm.Get("whois_ip")).CombinedOutput()
			currentResult = string(out)
		case r.PostForm.Has("speedtest_run"):
			currentResult, _ = network.RunSpeedtest()
		case r.PostForm.Get("iperf_ip") != "":
			currentResult, _ = network.RunIperfClient(r.PostForm.Get("iperf_ip"))
		case r.PostForm.Has("iperf_server_run"):
			currentResult, _ = network.RunIperfServer()
		case r.PostForm.Has("iperf_reset"):
			// Using sh -c allows us to use shell features for a cleaner kill
			cmd := exec.Command("sh", "-c", "fuser -k 5201/tcp || pkill iperf3")
			err := cmd.Run()

			if err != nil {
				app.errorLog.Printf("Manual reset failed: %v", err)
				currentResult = "Reset failed. Check VPS logs for 'Operation not permitted'."
			} else {
				app.infoLog.Println("iPerf3 Reset: Port 5201 cleared.")
				currentResult = "SUCCESS: Port 5201 forcefully cleared."
			}
		}

		if r.Header.Get("Accept") == "application/json" {
			ips := extractIPs(currentResult)
			var coords []HopGeo
			// 1. Add the Client's public IP as the starting point
			clientGeo := getGeo(app.getRemoteIP(r))
			if clientGeo.Lat != 0 {
				coords = append(coords, clientGeo)
			}
			for _, ip := range ips {
				if !isPrivateIP(ip) {
					geo := getGeo(ip)
					if geo.Lat != 0 {
						coords = append(coords, geo)
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(DiagResponse{Output: currentResult, Coords: coords})
			return
		}
	}

	clientIP := app.getRemoteIP(r) // Corrected to use helper
	data := &templateData{
		MemoryUsage:    system.GetMemStats(),
		ServerPublicIP: network.GetPublicIP(),
		ClientIP:       clientIP,
	}
	ts, _ := template.ParseFiles("./web/html/home.page.tmpl", "./web/html/base.layout.tmpl")
	ts.Execute(w, data)
}

func (app *application) systemMonitor(w http.ResponseWriter, r *http.Request) {
	clientIP := app.getRemoteIP(r) // Corrected to use helper
	data := &templateData{
		MemoryUsage:      system.GetMemStats(),
		DockerContainers: system.GetDockerContainers(),
		ClientIP:         clientIP,
		ServerPublicIP:   network.GetPublicIP(),
	}
	ts, _ := template.ParseFiles("./web/html/system.page.tmpl", "./web/html/base.layout.tmpl")
	ts.Execute(w, data)
}

func (app *application) getRemoteIP(r *http.Request) string {
	// Correctly identifies client behind proxy
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || (ip4[0] == 192 && ip4[1] == 168) || ip4[0] == 127 || (ip4[0] == 169 && ip4[1] == 254)
	}
	return false
}

func (app *application) getLogs() string {
	content, _ := os.ReadFile("/app/info.log")
	lines := strings.Split(string(content), "\n")
	var clean []string
	ignore := []string{"/?refresh=", "/static/", "Auth Check:"}
	for _, line := range lines {
		skip := false
		for _, p := range ignore {
			if strings.Contains(line, p) {
				skip = true
				break
			}
		}
		if !skip && strings.TrimSpace(line) != "" {
			clean = append(clean, line)
		}
	}
	if len(clean) > 10 {
		clean = clean[len(clean)-10:]
	}
	return strings.Join(clean, "\n")
}

func (app *application) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csp := []string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com",
			"style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com",
			"font-src 'self' https://fonts.gstatic.com",
			"img-src 'self' data: https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com https://anchorpoint-it.com",
			"connect-src 'self' https://cdn.jsdelivr.net https://unpkg.com",
		}
		w.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))
		next.ServeHTTP(w, r)
	})
}

func (app *application) bootstrapRootUser() {
	var exists bool
	app.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username='admin')").Scan(&exists)
	if !exists {
		hashed, _ := bcrypt.GenerateFromPassword([]byte("changeme123"), 12)
		app.db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", "admin", string(hashed))
	}
}

func (app *application) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		ts, _ := template.ParseFiles("./web/html/login.page.tmpl", "./web/html/base.layout.tmpl")
		ts.Execute(w, nil)
		return
	}
	r.ParseForm()
	var hashed string
	app.db.QueryRow("SELECT password FROM users WHERE username = ?", r.PostForm.Get("username")).Scan(&hashed)
	if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(r.PostForm.Get("password"))) == nil {
		http.SetCookie(w, &http.Cookie{Name: "authenticated", Value: "true", Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
}

func (app *application) createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		ts, _ := template.ParseFiles("./web/html/settings.page.tmpl", "./web/html/base.layout.tmpl")
		rows, _ := app.db.Query("SELECT username FROM users")
		var users []string
		for rows.Next() {
			var u string
			rows.Scan(&u)
			users = append(users, u)
		}
		clientIP := app.getRemoteIP(r)
		ts.Execute(w, &settingsData{
			Usernames:        users,
			ServerPublicIP:   network.GetPublicIP(),
			ClientIP:         clientIP,
			MemoryUsage:      system.GetMemStats(),
			DockerContainers: system.GetDockerContainers(),
		})
		return
	}
	r.ParseForm()
	h, _ := bcrypt.GenerateFromPassword([]byte(r.PostForm.Get("password")), 12)
	app.db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", r.PostForm.Get("username"), string(h))
	http.Redirect(w, r, "/settings?success=1", http.StatusSeeOther)
}

func (app *application) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("authenticated")
		if err == nil && cookie.Value == "true" {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func getGeo(ip string) HopGeo {
	// Added a small timeout for reliability
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
	re := regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
	return re.FindAllString(text, -1)
}

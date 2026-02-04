package main

import (
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
)

// templateData holds the initial state for the HTML dashboard
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

// HopGeo represents coordinates for a single network hop
type HopGeo struct {
	IP  string  `json:"ip"`
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// DiagResponse is the JSON payload sent back to the browser
type DiagResponse struct {
	Output string   `json:"output"`
	Coords []HopGeo `json:"coords"`
}

type application struct {
	errorLog *log.Logger
	infoLog  *log.Logger
}

func main() {
	// 1. Define the absolute path to match your volume mount
	logPath := "/app/info.log"

	// 2. Open the file using the absolute path
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	infoLog := log.New(f, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(f, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	app := &application{
		errorLog: errorLog,
		infoLog:  infoLog,
	}

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "4000"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.home)

	standardMiddleware := app.recoverPanic(app.logRequest(mux))

	srv := &http.Server{
		Addr:         ":" + port,
		ErrorLog:     errorLog,
		Handler:      standardMiddleware,
		IdleTimeout:  2 * time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 2 * time.Minute, // Sufficient for MTR cycles
	}

	app.infoLog.Printf("Starting AnchorPoint IT on %s", srv.Addr)
	err = srv.ListenAndServe()
	errorLog.Fatal(err)
}

func (app *application) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Handle AJAX refreshes for Docker, Logs, and more
	if refreshType := r.URL.Query().Get("refresh"); refreshType != "" {
		w.Header().Set("Content-Type", "text/plain")

		switch refreshType {
		case "docker":
			w.Write([]byte(system.GetDockerContainers()))
		case "logs":
			w.Write([]byte(app.getLogs()))
		case "stats": // ADD THIS CASE
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

	status := "Offline"
	if network.Ping("8.8.8.8") {
		status = "Online"
	}

	data := &templateData{
		GatewayStatus:    status,
		MemoryUsage:      system.GetMemStats(),
		DockerContainers: system.GetDockerContainers(),
		ClientIP:         clientIP,
		ServerPublicIP:   network.GetPublicIP(),
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Bad Request", 400)
			return
		}

		var currentResult string

		// 1. Logic for choosing which tool to run
		if ip := r.PostForm.Get("ping_ip"); ip != "" {
			if network.Ping(ip) {
				currentResult = ip + " is reachable."
			} else {
				currentResult = ip + " is unreachable."
			}
			data.PingResult = currentResult
		} else if ip := r.PostForm.Get("trace_ip"); ip != "" {
			res, err := network.Traceroute(ip)
			currentResult = res
			if err != nil {
				currentResult = err.Error()
			}
			data.TraceResult = currentResult
		} else if ip := r.PostForm.Get("mtr_ip"); ip != "" {
			res, err := network.MTR(ip)
			currentResult = res
			if err != nil {
				currentResult = err.Error()
			}
			data.MTRResult = currentResult
		} else if r.PostForm.Has("speedtest_run") {
			res, err := network.RunSpeedtest()
			currentResult = res
			if err != nil {
				currentResult = "Speedtest error: " + err.Error()
			}
			data.SpeedtestResult = currentResult
		} else if ip := r.PostForm.Get("iperf_ip"); ip != "" {
			res, err := network.RunIperf(ip)
			currentResult = res
			if err != nil {
				currentResult = "iPerf error: " + err.Error()
			}
			data.IperfResult = currentResult
		}

		// 2. AJAX Interceptor (Returns JSON for the spinner/map)
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

			resp := DiagResponse{
				Output: currentResult,
				Coords: coords,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return // Stop here for AJAX requests
		}
	}

	// 3. THE RENDERING LOGIC (Runs for initial GET requests)
	files := []string{
		"./web/html/home.page.tmpl",
		"./web/html/base.layout.tmpl",
	}

	ts, err := template.ParseFiles(files...)
	if err != nil {
		app.errorLog.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	err = ts.Execute(w, data)
	if err != nil {
		app.errorLog.Println(err.Error())
	}
}

// getGeo fetches coordinates for an IP with a 2-second timeout
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

// extractIPs parses network diagnostic text for IPv4 addresses
func extractIPs(text string) []string {
	re := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	return re.FindAllString(text, -1)
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

// This must be a method of the 'application' struct
func (app *application) getLogs() string {
	// os.ReadFile requires the "os" import
	content, err := os.ReadFile("/app/info.log")
	if err != nil {
		return "Log Error: " + err.Error()
	}

	// strings.Split requires the "strings" import
	lines := strings.Split(string(content), "\n")
	var cleanLines []string

	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			cleanLines = append(cleanLines, line)
		}
	}

	// Logic to prevent index out of bounds errors
	if len(cleanLines) > 20 {
		cleanLines = cleanLines[len(cleanLines)-20:]
	}

	return strings.Join(cleanLines, "\n")
}

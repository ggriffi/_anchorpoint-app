package main

import (
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"anchorpoint-it.com/webapp/internal/network"
	"anchorpoint-it.com/webapp/internal/system"
)

type templateData struct {
	GatewayStatus    string
	MemoryUsage      string
	DockerContainers string
	ClientIP         string // The user's IP
	ServerPublicIP   string // YOUR external IP
	PingResult       string
	TraceResult      string
	MTRResult        string
}

type application struct {
	errorLog *log.Logger
	infoLog  *log.Logger
}

func main() {
	// 1. Open the log file
	f, err := os.OpenFile("info.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// 2. Initialize loggers using the file
	infoLog := log.New(f, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(f, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	// 3. Initialize application struct
	app := &application{
		errorLog: errorLog,
		infoLog:  infoLog,
	}

	// 4. Get port from environment or default
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "4000"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.home)

	// 5. Wrap with middleware
	standardMiddleware := app.recoverPanic(app.logRequest(mux))

	srv := &http.Server{
		Addr:         ":" + port,
		ErrorLog:     errorLog,
		Handler:      standardMiddleware,
		IdleTimeout:  time.Minute,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second, // Bumped to 30s to allow MTR to finish
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

	// 1. Identify Client IP first
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if proxyIP := r.Header.Get("X-Forwarded-For"); proxyIP != "" {
		clientIP = proxyIP
	}

	// 2. Determine Gateway Status BEFORE creating the struct
	status := "Offline"
	if network.Ping("8.8.8.8") {
		status = "Online"
	}

	// 3. Initialize the data struct with all "guts" ready
	data := &templateData{
		GatewayStatus:    status, // Fixed: status is now defined
		MemoryUsage:      system.GetMemStats(),
		DockerContainers: system.GetDockerContainers(),
		ClientIP:         clientIP,
		ServerPublicIP:   network.GetPublicIP(),
	}

	// 4. Handle Form Submissions (updates 'data' if POST)
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Bad Request", 400)
			return
		}

		if ip := r.PostForm.Get("ping_ip"); ip != "" {
			if network.Ping(ip) {
				data.PingResult = ip + " is reachable."
			} else {
				data.PingResult = ip + " is unreachable."
			}
		}

		if ip := r.PostForm.Get("trace_ip"); ip != "" {
			res, err := network.Traceroute(ip)
			if err != nil {
				data.TraceResult = err.Error()
			} else {
				data.TraceResult = res
			}
		}

		if ip := r.PostForm.Get("mtr_ip"); ip != "" {
			res, err := network.MTR(ip)
			if err != nil {
				data.MTRResult = err.Error()
			} else {
				data.MTRResult = res
			}
		}
	}

	// 5. Render the page
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

package main

import (
    "context"
    "crypto/rand"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "io"

    "github.com/google/uuid"
    "github.com/wailsapp/wails/v2/pkg/runtime"
)

type FileTransfer struct {
    TransmissionID string
    Token         string
    Status        string
}

type RegisterRequest struct {
    Alias       string `json:"alias"`
    Version     string `json:"version"`
    DeviceModel string `json:"deviceModel"`
    DeviceType  string `json:"deviceType"`
    Fingerprint string `json:"fingerprint"`
    Port        int    `json:"port"`
    Protocol    string `json:"protocol"`
    Download    bool   `json:"download"`
}

type RegisterResponse struct {
    SessionID string `json:"sessionId"`
}

type App struct {
    ctx        context.Context
    server     *http.Server
    activePIN  string
    transfers  map[string]*FileTransfer
    uploadDir  string
    devices    map[string]*RegisterRequest // Track registered devices by sessionId
}

func NewApp() *App {
    // Create uploads directory
    uploadDir := filepath.Join(".", "uploads")
    os.MkdirAll(uploadDir, 0755)

    app := &App{
        uploadDir:  uploadDir,
        transfers:  make(map[string]*FileTransfer),
        devices:    make(map[string]*RegisterRequest),
    }
    app.generatePIN()
    return app
}

func (a *App) startup(ctx context.Context) {
    a.ctx = ctx
}

func (a *App) GetLocalIPs() []string {
    var ips []string
    
    interfaces, err := net.Interfaces()
    if err != nil {
        runtime.LogError(a.ctx, fmt.Sprintf("Failed to get network interfaces: %v", err))
        return ips
    }

    for _, iface := range interfaces {
        if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
            continue // interface down or loopback
        }

        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }

        for _, addr := range addrs {
            var ip net.IP
            switch v := addr.(type) {
            case *net.IPNet:
                ip = v.IP
            case *net.IPAddr:
                ip = v.IP
            }
            if ip == nil || ip.IsLoopback() {
                continue
            }
            ip = ip.To4()
            if ip == nil {
                continue // not an ipv4 address
            }
            ips = append(ips, ip.String())
        }
    }
    return ips
}

func (a *App) generatePIN() string {
    b := make([]byte, 6)
    _, err := rand.Read(b)
    if err != nil {
        a.activePIN = "123456"
        return a.activePIN
    }
    
    num := int(b[0])<<40 | int(b[1])<<32 | int(b[2])<<24 | int(b[3])<<16 | int(b[4])<<8 | int(b[5])
    pin := fmt.Sprintf("%06d", num%1000000)
    a.activePIN = pin
    return pin
}

func (a *App) GetCurrentPIN() string {
    return a.activePIN
}

func (a *App) StartServer(port int) error {
    mux := http.NewServeMux()
    
    // Root endpoint for web interface
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" {
            http.NotFound(w, r)
            return
        }
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, `<!DOCTYPE html>
        <html>
        <head>
            <title>LocalSend Test</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: system-ui; max-width: 800px; margin: 0 auto; padding: 20px; }
                .card { background: #f0f0f0; padding: 20px; border-radius: 8px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <h1>LocalSend Test Interface</h1>
            <div class="card">
                <h3>Connection Info</h3>
                <p>Server IP: <strong>%s</strong></p>
                <p>Current PIN: <strong>%s</strong></p>
            </div>
        </body>
        </html>`, a.GetLocalIPs()[0], a.activePIN)
    })

    // LocalSend Register Endpoint
    mux.HandleFunc("/api/localsend/v2/register", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            w.WriteHeader(http.StatusMethodNotAllowed)
            return
        }

        var regRequest RegisterRequest
        if err := json.NewDecoder(r.Body).Decode(&regRequest); err != nil {
            http.Error(w, "Invalid request body", http.StatusBadRequest)
            return
        }

        // Log registration info
        runtime.LogInfo(a.ctx, fmt.Sprintf("Device registration: %s (%s %s)", 
            regRequest.Alias, regRequest.DeviceModel, regRequest.DeviceType))

        sessionID := uuid.New().String()
        // Store device info
        a.devices[sessionID] = &regRequest

        response := RegisterResponse{
            SessionID: sessionID,
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    })

    // LocalSend prepare upload endpoint
    mux.HandleFunc("/api/localsend/v2/prepare-upload", func(w http.ResponseWriter, r *http.Request) {
        pin := r.URL.Query().Get("pin")
        if pin != a.activePIN {
            http.Error(w, "Invalid PIN", http.StatusUnauthorized)
            return
        }
        
        fileId := uuid.New().String()
        token := uuid.New().String()
        
        a.transfers[fileId] = &FileTransfer{
            TransmissionID: fileId,
            Token: token,
            Status: "preparing",
        }
        
        json.NewEncoder(w).Encode(map[string]string{
            "fileId": fileId,
            "token": token,
        })
    })

    // Upload endpoint
    mux.HandleFunc("/api/localsend/v2/upload", func(w http.ResponseWriter, r *http.Request) {
        fileId := r.URL.Query().Get("fileId")
        token := r.URL.Query().Get("token")
        
        transfer, exists := a.transfers[fileId]
        if !exists || transfer.Token != token {
            http.Error(w, "Invalid transfer", http.StatusBadRequest)
            return
        }
        
        file, handler, err := r.FormFile("file")
        if err != nil {
            http.Error(w, "Failed to get file", http.StatusBadRequest)
            return
        }
        defer file.Close()
        
        dst, err := os.Create(filepath.Join(a.uploadDir, handler.Filename))
        if err != nil {
            http.Error(w, "Failed to save file", http.StatusInternalServerError)
            return
        }
        defer dst.Close()
        
        io.Copy(dst, file)
        w.WriteHeader(http.StatusOK)
    })

    a.server = &http.Server{
        Addr:    fmt.Sprintf(":%d", port),
        Handler: mux,
    }

    go func() {
        if err := a.server.ListenAndServe(); err != http.ErrServerClosed {
            log.Printf("HTTP server error: %v\n", err)
            runtime.LogError(a.ctx, fmt.Sprintf("HTTP server error: %v", err))
        }
    }()

    runtime.LogInfo(a.ctx, fmt.Sprintf("LocalSend HTTP server started on port %d", port))
    return nil
}

func (a *App) Shutdown(ctx context.Context) {
    if a.server != nil {
        if err := a.server.Shutdown(ctx); err != nil {
            runtime.LogError(a.ctx, fmt.Sprintf("Error shutting down server: %v", err))
        }
        runtime.LogInfo(a.ctx, "Server stopped successfully")
    }
}
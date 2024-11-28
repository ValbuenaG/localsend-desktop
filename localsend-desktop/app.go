package main

import (
    "context"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
	"crypto/rsa"
    "encoding/pem"
    "fmt"
    "log"
    "math/big"
    "net"
    "net/http"
    "time"
    "io"
    "os"
    "path/filepath"
    "encoding/json"

    "github.com/google/uuid"
    "github.com/wailsapp/wails/v2/pkg/runtime"
)

type FileTransfer struct {
    TransmissionID string
    Token         string
    Status        string
}

type App struct {
    ctx        context.Context
    server     *http.Server
    activePIN  string
    transfers  map[string]*FileTransfer
    uploadDir  string
}

func NewApp() *App {
    // Create uploads directory
    uploadDir := filepath.Join(".", "uploads")
    os.MkdirAll(uploadDir, 0755)

    app := &App{
        uploadDir:  uploadDir,
        transfers:  make(map[string]*FileTransfer),
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

func (a *App) generateCertificate() (tls.Certificate, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return tls.Certificate{}, fmt.Errorf("failed to generate private key: %v", err)
    }

    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization: []string{"LocalSend Desktop"},
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(24 * time.Hour),
        KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{
            x509.ExtKeyUsageServerAuth,
        },
        BasicConstraintsValid: true,
    }

    ips := a.GetLocalIPs()
    for _, ip := range ips {
        if parsedIP := net.ParseIP(ip); parsedIP != nil {
            template.IPAddresses = append(template.IPAddresses, parsedIP)
        }
    }
    template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
    if err != nil {
        return tls.Certificate{}, fmt.Errorf("failed to create certificate: %v", err)
    }

    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: derBytes,
    })
    privKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    })

    tlsCert, err := tls.X509KeyPair(certPEM, privKeyPEM)
    if err != nil {
        return tls.Certificate{}, fmt.Errorf("failed to create TLS certificate: %v", err)
    }

    return tlsCert, nil
}

func (a *App) StartServer(port int) error {
    cert, err := a.generateCertificate()
    if err != nil {
        return fmt.Errorf("failed to generate certificate: %v", err)
    }

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

        sessionID := uuid.New().String()
        json.NewEncoder(w).Encode(map[string]string{
            "sessionId": sessionID,
        })
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
        TLSConfig: &tls.Config{
            Certificates: []tls.Certificate{cert},
        },
    }

    go func() {
        if err := a.server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
            log.Printf("HTTPS server error: %v\n", err)
            runtime.LogError(a.ctx, fmt.Sprintf("HTTPS server error: %v", err))
        }
    }()

    runtime.LogInfo(a.ctx, fmt.Sprintf("LocalSend HTTPS server started on port %d", port))
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
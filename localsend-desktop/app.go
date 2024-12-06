package main

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "log"
    "math/big"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "io"
    "bytes"
    "mime/multipart"
    "strings"
    "time"

    "github.com/google/uuid"
    "github.com/wailsapp/wails/v2/pkg/runtime"
)

type FileTransfer struct {
    TransmissionID string
    Token         string
    Status        string
    SessionId     string
    FileName      string
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
    currentSessionId string
}

func (a *App) getUploadsDirectory() string {
    // Get user's home directory
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return filepath.Join(".", "uploads")  // Fallback to local directory
    }
    
    // Create a directory in Documents
    uploadsDir := filepath.Join(homeDir, "Documents", "LocalSendUploads")
    os.MkdirAll(uploadsDir, 0755)
    return uploadsDir
}

// Add notification methods
func (a *App) ShowDeviceRegistered(deviceInfo string) {
    runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
        Type:    runtime.InfoDialog,
        Title:   "Device Registered",
        Message: "New device registered: " + deviceInfo,
    })
}

func (a *App) ShowFileReceived(fileName string) {
    runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
        Type:    runtime.InfoDialog,
        Title:   "File Received",
        Message: "Received file: " + fileName + "\nSaved in: " + a.uploadDir,
    })
}

func NewApp() *App {
    app := &App{
        transfers:  make(map[string]*FileTransfer),
        devices:    make(map[string]*RegisterRequest),
    }
    app.uploadDir = app.getUploadsDirectory()
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

func generateCert() ([]byte, []byte, error) {
    priv, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil, err
    }

    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization: []string{"LocalSend"},
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(365 * 24 * time.Hour),
        
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
        IPAddresses:          []net.IP{net.ParseIP("127.0.0.1")},
    }

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
    if err != nil {
        return nil, nil, err
    }

    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
    keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

    return certPEM, keyPEM, nil
}

func (a *App) StartServer(port int) error {
    mux := http.NewServeMux()

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
    
        // Store device info with fingerprint as key instead of sessionId
        a.devices[regRequest.Fingerprint] = &regRequest
        
        deviceInfo := fmt.Sprintf("%s (%s)", regRequest.Alias, regRequest.DeviceModel)
        go a.ShowDeviceRegistered(deviceInfo)
    
        w.Header().Set("Content-Type", "application/json")
        // Send empty response as per protocol
        json.NewEncoder(w).Encode(struct{}{})
    })

    // LocalSend prepare upload endpoint
    mux.HandleFunc("/api/localsend/v2/prepare-upload", func(w http.ResponseWriter, r *http.Request) {
        pin := r.URL.Query().Get("pin")
        
        // Validate PIN
        if pin != a.activePIN {
            http.Error(w, "Invalid PIN", http.StatusUnauthorized)
            return
        }
        
        var prepareRequest struct {
            Info struct {
                Alias string `json:"alias"`
            } `json:"info"`
            Files map[string]struct {
                ID       string `json:"id"`
                FileName string `json:"fileName"`
            } `json:"files"`
        }
        
        if err := json.NewDecoder(r.Body).Decode(&prepareRequest); err != nil {
            http.Error(w, "Invalid body", http.StatusBadRequest)
            return
        }
    
        sessionId := uuid.New().String()
        fileTokens := make(map[string]string)
        
        // Generate a token for each file in the request
        for fileId := range prepareRequest.Files {
            token := uuid.New().String()
            fileTokens[fileId] = token
            
            // Store the transfer info
            a.transfers[fileId] = &FileTransfer{
                TransmissionID: fileId,
                Token:         token,
                SessionId:     sessionId,
                Status:        "preparing",
                FileName:      prepareRequest.Files[fileId].FileName,
            }
        }
        
        json.NewEncoder(w).Encode(map[string]interface{}{
            "sessionId": sessionId,
            "files":    fileTokens,
        })
    })

    // Upload endpoint
    mux.HandleFunc("/api/localsend/v2/upload", func(w http.ResponseWriter, r *http.Request) {
        fileId := r.URL.Query().Get("fileId")
        token := r.URL.Query().Get("token")
        sessionId := r.URL.Query().Get("sessionId")
        
        // Log for debugging
        runtime.LogInfo(a.ctx, fmt.Sprintf("Upload attempt - FileId: %s, Token: %s, SessionId: %s", fileId, token, sessionId))
        
        transfer, exists := a.transfers[fileId]
        if !exists || transfer.Token != token || transfer.SessionId != sessionId {
            runtime.LogInfo(a.ctx, "Transfer validation failed")
            http.Error(w, "Invalid transfer", http.StatusBadRequest)
            return
        }
    
        var file io.Reader
        var filename string
    
        contentType := r.Header.Get("Content-Type")
        if strings.HasPrefix(contentType, "multipart/form-data") {
            // Handle multipart form data
            f, handler, err := r.FormFile("file")
            if err != nil {
                runtime.LogError(a.ctx, fmt.Sprintf("Failed to get form file: %v", err))
                http.Error(w, "Failed to get file", http.StatusBadRequest)
                return
            }
            defer f.Close()
            file = f
            filename = handler.Filename
        } else {
            // Handle direct binary data
            file = r.Body
            filename = transfer.FileName
        }
    
        // Create destination file
        dst, err := os.Create(filepath.Join(a.uploadDir, filename))
        if err != nil {
            runtime.LogError(a.ctx, fmt.Sprintf("Failed to create file: %v", err))
            http.Error(w, "Failed to save file", http.StatusInternalServerError)
            return
        }
        defer dst.Close()
        
        // Copy the file
        _, err = io.Copy(dst, file)
        if err != nil {
            runtime.LogError(a.ctx, fmt.Sprintf("Failed to save file data: %v", err))
            http.Error(w, "Failed to save file", http.StatusInternalServerError)
            return
        }
    
        go a.ShowFileReceived(filename)
        w.WriteHeader(http.StatusOK)
    })

    mux.HandleFunc("/api/localsend/v1/info", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            w.WriteHeader(http.StatusMethodNotAllowed)
            return
        }
    
        info := struct {
            Alias       string `json:"alias"`
            Version     string `json:"version"`
            DeviceModel string `json:"deviceModel"`
            DeviceType  string `json:"deviceType"`
            Fingerprint string `json:"fingerprint"`
            Download    bool   `json:"download"`
        }{
            Alias:       "WailsDesktop",
            Version:     "2.0",
            DeviceModel: "Desktop",
            DeviceType:  "desktop",
            Fingerprint: "test-fingerprint",
            Download:    true,
        }
    
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(info)
    })

    // self signed certificate
    certPEM, keyPEM, err := generateCert()
    if err != nil {
        return fmt.Errorf("failed to generate certificate: %v", err)
    }

    cert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        return fmt.Errorf("failed to load certificate: %v", err)
    }

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:  tls.VersionTLS12,
        MaxVersion:  tls.VersionTLS13,
    }

    a.server = &http.Server{
        Addr:    fmt.Sprintf(":%d", port),
        Handler: mux,
        TLSConfig: tlsConfig,
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

// client side methods

func (a *App) RegisterWithDevice(ip string, port int) error {
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
        },
    }

    regRequest := struct {
        Alias       string `json:"alias"`
        Version     string `json:"version"`
        DeviceModel string `json:"deviceModel"`
        DeviceType  string `json:"deviceType"`
        Fingerprint string `json:"fingerprint"`
        Port        int    `json:"port"`
        Protocol    string `json:"protocol"`
        Download    bool   `json:"download"`
    }{
        Alias:       "WailsDesktop",
        Version:     "2.0",
        DeviceModel: "Desktop",
        DeviceType:  "desktop",
        Fingerprint: "test-fingerprint",
        Port:        port,
        Protocol:    "http",
        Download:    true,
    }

    payload, err := json.Marshal(regRequest)
    if err != nil {
        return fmt.Errorf("failed to marshal registration request: %v", err)
    }
    runtime.LogInfo(a.ctx, fmt.Sprintf("Sending registration request to %s:%d", ip, port))
    resp, err := client.Post(
        fmt.Sprintf("https://%s:%d/api/localsend/v2/register", ip, port),
        "application/json",
        bytes.NewBuffer(payload),
    )
    if err != nil {
        return fmt.Errorf("failed to send registration request: %v", err)
    }
    defer resp.Body.Close()

    return nil
}

func (a *App) SendTestFile(ip string, port int, pin string) error {
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true, // For self-signed cert
            },
        },
    }
    
    // Step 1: Prepare upload
    prepareURL := fmt.Sprintf("https://%s:%d/api/localsend/v2/prepare-upload?pin=%s", ip, port, pin)
    runtime.LogInfo(a.ctx, fmt.Sprintf("Preparing upload with URL: %s", prepareURL))
    
    resp, err := client.Post(prepareURL, "application/json", nil)
    if err != nil {
        return fmt.Errorf("failed to prepare upload: %v", err)
    }
    
    var prepareResp struct {
        SessionId string            `json:"sessionId"`
        Files    map[string]string  `json:"files"`  // map[fileId]token
    }
    if err := json.NewDecoder(resp.Body).Decode(&prepareResp); err != nil {
        return fmt.Errorf("failed to decode prepare response: %v", err)
    }
    resp.Body.Close()

    // Get the first file ID and token from the map
    var fileId, token string
    for fid, tok := range prepareResp.Files {
        fileId = fid
        token = tok
        break
    }

    runtime.LogInfo(a.ctx, fmt.Sprintf("Got prepare response - SessionId: %s, FileId: %s, Token: %s", 
        prepareResp.SessionId, fileId, token))

    // Step 2: Upload file
    body := &bytes.Buffer{}
    writer := multipart.NewWriter(body)
    part, err := writer.CreateFormFile("file", "test.txt")
    if err != nil {
        return fmt.Errorf("failed to create form file: %v", err)
    }
    
    // Write test content
    if _, err := part.Write([]byte("sending from wails app")); err != nil {
        return fmt.Errorf("failed to write file content: %v", err)
    }
    writer.Close()

    uploadURL := fmt.Sprintf(
        "https://%s:%d/api/localsend/v2/upload?fileId=%s&token=%s&sessionId=%s",
        ip, port, fileId, token, prepareResp.SessionId,
    )
    runtime.LogInfo(a.ctx, fmt.Sprintf("Uploading file with URL: %s", uploadURL))

    req, err := http.NewRequest("POST", uploadURL, body)
    if err != nil {
        return fmt.Errorf("failed to create upload request: %v", err)
    }
    req.Header.Set("Content-Type", writer.FormDataContentType())

    resp, err = client.Do(req)
    if err != nil {
        return fmt.Errorf("failed to upload file: %v", err)
    }
    defer resp.Body.Close()

    // Read response body for error details
    responseBody, _ := io.ReadAll(resp.Body)
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("upload failed with status: %s, body: %s", resp.Status, string(responseBody))
    }

    runtime.LogInfo(a.ctx, fmt.Sprintf("File uploaded successfully. Response: %s", string(responseBody)))
    return nil
}
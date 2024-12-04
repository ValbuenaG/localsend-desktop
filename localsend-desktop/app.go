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
    "bytes"
    "mime/multipart"

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

        sessionID := uuid.New().String()
        // Store device info
        a.devices[sessionID] = &regRequest

        response := RegisterResponse{
            SessionID: sessionID,
        }
        
        deviceInfo := fmt.Sprintf("%s (%s)", regRequest.Alias, regRequest.DeviceModel)
        go a.ShowDeviceRegistered(deviceInfo)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    })

    // LocalSend prepare upload endpoint
    mux.HandleFunc("/api/localsend/v2/prepare-upload", func(w http.ResponseWriter, r *http.Request) {
        pin := r.URL.Query().Get("pin")
        
        // Validate PIN
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
        sessionId := r.URL.Query().Get("sessionId")
        
        // Validate sessionId first
        if _, deviceRegistered := a.devices[sessionId]; !deviceRegistered {
            http.Error(w, "Device not registered", http.StatusUnauthorized)
            return
        }
        
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
        go a.ShowFileReceived(handler.Filename)
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

// client side methods

func (a *App) RegisterWithDevice(ip string, port int) error {
    client := &http.Client{}
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
        fmt.Sprintf("http://%s:%d/api/localsend/v2/register", ip, port),
        "application/json",
        bytes.NewBuffer(payload),
    )
    if err != nil {
        return fmt.Errorf("failed to send registration request: %v", err)
    }
    defer resp.Body.Close()

    // Parse and store sessionId
    var registerResp struct {
        SessionID string `json:"sessionId"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&registerResp); err != nil {
        return fmt.Errorf("failed to decode register response: %v", err)
    }

    a.currentSessionId = registerResp.SessionID
    runtime.LogInfo(a.ctx, fmt.Sprintf("Successfully registered with sessionId: %s", a.currentSessionId))
    return nil
}

func (a *App) SendTestFile(ip string, port int, pin string) error {
    if a.currentSessionId == "" {
        return fmt.Errorf("must register before sending files")
    }

    client := &http.Client{}
    
    // Step 1: Prepare upload
    prepareURL := fmt.Sprintf("http://%s:%d/api/localsend/v2/prepare-upload?pin=%s", ip, port, pin)
    runtime.LogInfo(a.ctx, fmt.Sprintf("Preparing upload with URL: %s", prepareURL))
    
    resp, err := client.Post(prepareURL, "application/json", nil)
    if err != nil {
        return fmt.Errorf("failed to prepare upload: %v", err)
    }
    
    var prepareResp struct {
        FileId string `json:"fileId"`
        Token  string `json:"token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&prepareResp); err != nil {
        return fmt.Errorf("failed to decode prepare response: %v", err)
    }
    resp.Body.Close()

    runtime.LogInfo(a.ctx, fmt.Sprintf("Got prepare response - FileId: %s, Token: %s", 
        prepareResp.FileId, prepareResp.Token))

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
        "http://%s:%d/api/localsend/v2/upload?fileId=%s&token=%s&sessionId=%s",
        ip, port, prepareResp.FileId, prepareResp.Token, a.currentSessionId,
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
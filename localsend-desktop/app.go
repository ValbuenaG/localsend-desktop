//app.go
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/aes"
    "crypto/cipher"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
    "encoding/json"
	"sync"
    "crypto/sha256"

	"github.com/google/uuid"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type EncryptedPayload struct {
    EncryptedKey    []byte `json:"encryptedKey"`
    EncryptedData   []byte `json:"encryptedData"`
    Nonce          []byte `json:"nonce"`
}

// RegisterRequest represents the decrypted content of register request
type RegisterRequest struct {
    PIN           string `json:"pin"`
    SenderPubKey  []byte `json:"senderPublicKey"`
}

// RegisterResponse is what we'll encrypt and send back
type RegisterResponse struct {
    SessionID string `json:"sessionId"`
}

// Session stores active session information
type Session struct {
    ID            string
    SenderPubKey  []byte
    DerivedKey    []byte
    CreatedAt     time.Time
}

type PrepareUploadRequest struct {
    SessionID string `json:"sessionId"`
    Filename  string `json:"filename"`
    Size      int64  `json:"size"`
}

type PrepareUploadResponse struct {
    TransmissionID string `json:"transmissionId"`
}

type FileTransfer struct {
    TransmissionID string
    Filename      string
    Size          int64
    Status        string // "preparing", "uploading", "completed", "cancelled"
}

// App struct
type App struct {
    ctx            context.Context
    server         *http.Server
    activePIN      string
    serverKey      *rsa.PrivateKey
    sessions       map[string]*Session
    sessionMutex   sync.RWMutex
    transfers      map[string]*FileTransfer
    transferMutex  sync.RWMutex
    uploadDir      string
}

// NewApp creates a new App application struct
func NewApp() *App {
    // Generate server's keypair
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatal("Failed to generate server keypair:", err)
    }

    // Create uploads directory
    uploadDir := filepath.Join(".", "uploads")
    os.MkdirAll(uploadDir, 0755)

    app := &App{
        serverKey:  privateKey,
        sessions:   make(map[string]*Session),
        uploadDir:  uploadDir,
		transfers: make(map[string]*FileTransfer),
    }
    app.generatePIN() // Call it as a method
    return app
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// GetLocalIPs returns all local IPv4 addresses
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

// generatePIN generates a new 6-digit PIN
func (a *App) generatePIN() string {
	// Generate 6 random bytes
	b := make([]byte, 6)
	_, err := rand.Read(b)
	if err != nil {
		// If we can't generate random numbers, use a default PIN
		a.activePIN = "123456"
		return a.activePIN
	}
	
	// Convert to a 6-digit number
	num := int(b[0])<<40 | int(b[1])<<32 | int(b[2])<<24 | int(b[3])<<16 | int(b[4])<<8 | int(b[5])
	pin := fmt.Sprintf("%06d", num%1000000)
	a.activePIN = pin
	return pin
}

// generateCertificate creates a self-signed certificate for HTTPS
func (a *App) generateCertificate() (tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LocalSend Desktop"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour), // Valid for 24 hours
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	// Add local IP addresses to the certificate
	ips := a.GetLocalIPs()
	for _, ip := range ips {
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			template.IPAddresses = append(template.IPAddresses, parsedIP)
		}
	}
	// Add localhost
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode certificate and private key in PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Create TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create TLS certificate: %v", err)
	}

	return tlsCert, nil
}


// StartServer starts the HTTPS server for file transfers
func (a *App) StartServer(port int) error {
	// Generate certificate
	cert, err := a.generateCertificate()
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	mux := http.NewServeMux()
	
	// Serve HTML interface at root
	// this is just for testing purposes
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
			body { 
				font-family: system-ui; 
				max-width: 800px; 
				margin: 0 auto; 
				padding: 20px;
			}
			.card {
				background: #f0f0f0;
				padding: 20px;
				border-radius: 8px;
				margin: 20px 0;
			}
			button {
				background: #4CAF50;
				color: white;
				padding: 10px 20px;
				border: none;
				border-radius: 4px;
				cursor: pointer;
			}
			button:disabled {
				background: #ccc;
				cursor: not-allowed;
			}
			#status, #uploadStatus {
				margin: 20px 0;
				padding: 10px;
				border-radius: 4px;
			}
			.success { background: #dff0d8; color: #3c763d; }
			.error { background: #f2dede; color: #a94442; }
			.progress { background: #d9edf7; color: #31708f; }
			
			.progress-bar {
				width: 100%%;
				height: 20px;
				background-color: #f0f0f0;
				border-radius: 10px;
				overflow: hidden;
				margin-top: 10px;
				display: none;
			}
			.progress-bar-fill {
				height: 100%%;
				background-color: #4CAF50;
				width: 0%%;
				transition: width 0.3s ease;
			}
			input[type="file"] {
				margin: 10px 0;
				padding: 10px;
				width: 100%%;
				box-sizing: border-box;
			}
		</style>
	</head>
	<body>
		<h1>LocalSend Test Interface</h1>
		<div class="card">
			<h3>Connection Info</h3>
			<p>Server IP: <strong>%s</strong></p>
			<p>Current PIN: <strong>%s</strong></p>
		</div>
		<div class="card">
			<h3>File Transfer</h3>
			<input type="file" id="fileInput">
			<div class="progress-bar">
				<div class="progress-bar-fill"></div>
			</div>
			<button onclick="sendFile()" id="sendButton">Send File</button>
			<div id="uploadStatus"></div>
		</div>
	
		<script>
		async function sendFile() {
			const fileInput = document.getElementById('fileInput');
			const status = document.getElementById('uploadStatus');
			const sendButton = document.getElementById('sendButton');
			const progressBar = document.querySelector('.progress-bar');
			const progressBarFill = document.querySelector('.progress-bar-fill');
			
			const file = fileInput.files[0];
			
			if (!file) {
				status.textContent = 'Please select a file first';
				status.className = 'error';
				return;
			}
	
			try {
				sendButton.disabled = true;
				progressBar.style.display = 'block';
				status.textContent = 'Preparing upload...';
				status.className = 'progress';
	
				// Prepare upload
				const prepareResponse = await fetch('/api/v1/prepare-upload', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
					},
					body: JSON.stringify({
						filename: file.name,
						size: file.size,
					})
				});
	
				if (!prepareResponse.ok) throw new Error('Failed to prepare upload');
	
				// Send file with progress tracking
				const formData = new FormData();
				formData.append('file', file);
	
				const xhr = new XMLHttpRequest();
				xhr.open('POST', '/api/v1/upload', true);
	
				xhr.upload.onprogress = (e) => {
					if (e.lengthComputable) {
						const percentComplete = (e.loaded / e.total) * 100;
						progressBarFill.style.width = percentComplete + '%%';
						status.textContent = 'Uploading: ' + Math.round(percentComplete) + '%%';
					}
				};
	
				xhr.onload = function() {
					if (xhr.status === 200) {
						status.textContent = 'File uploaded successfully!';
						status.className = 'success';
					} else {
						throw new Error('Upload failed');
					}
				};
	
				xhr.onerror = function() {
					throw new Error('Upload failed');
				};
	
				xhr.send(formData);
	
			} catch (error) {
				status.textContent = 'Upload failed: ' + error.message;
				status.className = 'error';
			} finally {
				sendButton.disabled = false;
			}
		}
		</script>
	</body>
	</html>`, a.GetLocalIPs()[0], a.activePIN)
	})

	// Localsend Register Endpoint
	mux.HandleFunc("/api/v1/register", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            w.WriteHeader(http.StatusMethodNotAllowed)
            return
        }

        fmt.Printf("Received register request\n")

        // Read encrypted request body
        encryptedData, err := io.ReadAll(r.Body)
        if err != nil {
            fmt.Printf("Failed to read request: %v\n", err)
            http.Error(w, "Failed to read request", http.StatusBadRequest)
            return
        }

        // Decrypt and parse request
        req, err := a.decryptRegisterRequest(encryptedData)
        if err != nil {
            fmt.Printf("Failed to decrypt request: %v\n", err)
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        fmt.Printf("Decrypted request with PIN: %s\n", req.PIN)

        // Validate PIN
        if req.PIN != a.activePIN {
            fmt.Printf("Invalid PIN received: %s, expected: %s\n", req.PIN, a.activePIN)
            http.Error(w, "Invalid PIN", http.StatusUnauthorized)
            return
        }

        // Derive symmetric key
        derivedKey, err := a.deriveKey(req.SenderPubKey)
        if err != nil {
            fmt.Printf("Key derivation failed: %v\n", err)
            http.Error(w, "Key derivation failed", http.StatusInternalServerError)
            return
        }

        // Generate session
        sessionID := uuid.New().String()
        session := &Session{
            ID:           sessionID,
            SenderPubKey: req.SenderPubKey,
            DerivedKey:   derivedKey,
            CreatedAt:    time.Now(),
        }

		fmt.Printf("Derived key length: %d\n", len(derivedKey))

        // Store session
        a.sessionMutex.Lock()
        a.sessions[sessionID] = session
        fmt.Printf("Stored new session with ID: %s\n", sessionID)
        fmt.Printf("Current active sessions: %d\n", len(a.sessions))
        a.sessionMutex.Unlock()

        // Create and encrypt response
        response := &RegisterResponse{
            SessionID: sessionID,
        }

        fmt.Printf("Preparing response with session ID: %s\n", sessionID)

        encryptedResponse, err := encryptResponse(response, derivedKey)
        if err != nil {
            fmt.Printf("Failed to create response: %v\n", err)
            http.Error(w, "Failed to create response", http.StatusInternalServerError)
            return
        }

        // Send response
        w.Header().Set("Content-Type", "application/octet-stream")
        w.Write(encryptedResponse)
        fmt.Printf("Register request completed successfully\n")
    })

	mux.HandleFunc("/api/v1/public-key", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            w.WriteHeader(http.StatusMethodNotAllowed)
            return
        }

        pubKeyBytes := x509.MarshalPKCS1PublicKey(&a.serverKey.PublicKey)
        w.Header().Set("Content-Type", "application/octet-stream")
        w.Write(pubKeyBytes)
    })

	// LocalSend prepare upload endpoint
	mux.HandleFunc("/api/v1/prepare-upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request", http.StatusBadRequest)
			return
		}
	
		var req PrepareUploadRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}
	
		// Check session
		a.sessionMutex.RLock()
		_, exists := a.sessions[req.SessionID]
		a.sessionMutex.RUnlock()
		if !exists {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}
	
		// Generate transmission ID
		transmissionID := uuid.New().String()
	
		// Store transfer info
		a.transfers[transmissionID] = &FileTransfer{
			TransmissionID: transmissionID,
			Filename:      req.Filename,
			Size:         req.Size,
			Status:       "preparing",
		}
	
		resp := PrepareUploadResponse{
			TransmissionID: transmissionID,
		}
	
		respData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	
		w.Header().Set("Content-Type", "application/json")
		w.Write(respData)
	})

	// Upload endpoint
	mux.HandleFunc("/api/v1/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	
		// Get session and transmission IDs from headers
		sessionID := r.Header.Get("X-Session-ID")
		transmissionID := r.Header.Get("X-Transmission-ID")
	
		// Add logging to debug
		fmt.Printf("Received upload request - SessionID: %s, TransmissionID: %s\n", sessionID, transmissionID)
	
		// Validate session (without storing the unused session variable)
		a.sessionMutex.RLock()
		sessionExists := a.sessions[sessionID] != nil
		a.sessionMutex.RUnlock()
		
		if !sessionExists {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}
	
		// Validate transmission
		a.transferMutex.RLock()
		transfer, transferExists := a.transfers[transmissionID]
		a.transferMutex.RUnlock()
		
		if !transferExists {
			http.Error(w, fmt.Sprintf("Invalid transmission ID: %s", transmissionID), http.StatusBadRequest)
			return
		}
	
		// Parse the multipart form
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
	
		file, handler, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Failed to get file", http.StatusBadRequest)
			return
		}
		defer file.Close()
	
		// Create file
		filePath := filepath.Join(a.uploadDir, handler.Filename)
		dst, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to create file", http.StatusInternalServerError)
			return
		}
		defer dst.Close()
	
		// Save file
		if _, err := io.Copy(dst, file); err != nil {
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}
	
		// Update transfer status
		a.transferMutex.Lock()
		transfer.Status = "completed"
		a.transferMutex.Unlock()
	
		w.WriteHeader(http.StatusOK)
	})

	a.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	// Start server in a goroutine
	go func() {
		if err := a.server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Printf("HTTPS server error: %v\n", err)
			runtime.LogError(a.ctx, fmt.Sprintf("HTTPS server error: %v", err))
		}
	}()

	runtime.LogInfo(a.ctx, fmt.Sprintf("LocalSend HTTPS server started on port %d", port))
	return nil
}

// Helper to decrypt incoming register request
func (a *App) decryptRegisterRequest(encryptedData []byte) (*RegisterRequest, error) {
    // Parse the encrypted payload
    var payload EncryptedPayload
    if err := json.Unmarshal(encryptedData, &payload); err != nil {
        return nil, fmt.Errorf("failed to parse encrypted payload: %v", err)
    }

    // Decrypt the AES key using server's private key
    aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, a.serverKey, payload.EncryptedKey)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt AES key: %v", err)
    }

    // Create AES cipher
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create AES cipher: %v", err)
    }

    // Create GCM mode
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    // Decrypt the data
    jsonData, err := gcm.Open(nil, payload.Nonce, payload.EncryptedData, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt data: %v", err)
    }

    // Parse the decrypted JSON
    var request RegisterRequest
    if err := json.Unmarshal(jsonData, &request); err != nil {
        return nil, fmt.Errorf("failed to parse request: %v", err)
    }

    return &request, nil
}

// Helper to derive symmetric key from public keys
func (a *App) deriveKey(senderPubKey []byte) ([]byte, error) {
    fmt.Printf("Starting key derivation\n")

    // Hash both public keys together to create a shared secret
    h := sha256.New()
    h.Write(x509.MarshalPKCS1PublicKey(&a.serverKey.PublicKey))  // Server's public key
    h.Write(senderPubKey)  // Client's public key
    key := h.Sum(nil)
    
    fmt.Printf("Derived key length: %d, first few bytes: %x\n", len(key), key[:8])
    return key, nil
}


// Helper to encrypt response with symmetric key
func encryptResponse(response interface{}, key []byte) ([]byte, error) {
    fmt.Printf("Encrypting response with key length: %d\n", len(key))
    
    // Convert response to JSON
    jsonData, err := json.Marshal(response)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal response: %v", err)
    }
    fmt.Printf("Response JSON: %s\n", string(jsonData))

    // Create AES cipher
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %v", err)
    }

    // Generate nonce
    nonce := make([]byte, 12)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %v", err)
    }

    // Create GCM mode
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    // Encrypt and seal
    ciphertext := aesgcm.Seal(nonce, nonce, jsonData, nil)
    fmt.Printf("Encrypted response length: %d\n", len(ciphertext))
    
    return ciphertext, nil
}

// Shutdown is called at application termination
func (a *App) Shutdown(ctx context.Context) {
	if a.server != nil {
		if err := a.server.Shutdown(ctx); err != nil {
			runtime.LogError(a.ctx, fmt.Sprintf("Error shutting down server: %v", err))
		}
		runtime.LogInfo(a.ctx, "Server stopped successfully")
	}
}

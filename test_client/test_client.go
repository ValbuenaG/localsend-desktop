//test_client.go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
	"crypto/sha256"
    "encoding/json"
    "fmt"
    "bytes"
    "net/http"
    "io/ioutil"
    "io"
    "mime/multipart"
    "os"
)

type RegisterRequest struct {
    PIN          string `json:"pin"`
    SenderPubKey []byte `json:"senderPublicKey"`
}

type RegisterResponse struct {
    SessionID string `json:"sessionId"`
}

type PrepareUploadRequest struct {
    SessionID string `json:"sessionId"`
    Filename  string `json:"filename"`
    Size      int64  `json:"size"`
}

type PrepareUploadResponse struct {
    TransmissionID string `json:"transmissionId"`
}

type EncryptedPayload struct {
    EncryptedKey  []byte `json:"encryptedKey"`
    EncryptedData []byte `json:"encryptedData"`
    Nonce        []byte `json:"nonce"`
}

type FileTransferRequest struct {
    FileId string `json:"fileId"`
    Token  string `json:"token"` 
 }

 func main() {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }
    client := &http.Client{Transport: tr}
 
    pin := "619005"
    register(client)
    
    err := uploadFile("test.txt", pin, client)
    if err != nil {
        panic(fmt.Sprintf("Failed to upload file: %v", err))
    }
 }

func register(client *http.Client) string {
    fmt.Println("Starting registration process...")

    // Generate client keypair
    clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        panic(fmt.Sprintf("Failed to generate client keypair: %v", err))
    }
    fmt.Println("Generated client keypair")

    // Create register request
    request := RegisterRequest{
        PIN:          "619005", // Update with current PIN
        SenderPubKey: x509.MarshalPKCS1PublicKey(&clientKey.PublicKey),
    }
    fmt.Printf("Created register request with PIN: %s\n", request.PIN)

    // Get server's public key
    serverPublicKey, err := getServerPublicKey(client)
    if err != nil {
        panic(fmt.Sprintf("Failed to get server public key: %v", err))
    }
    fmt.Println("Retrieved server public key")

    // Derive key (same as server)
    h := sha256.New()
    h.Write(x509.MarshalPKCS1PublicKey(serverPublicKey))  // Server's public key
    h.Write(x509.MarshalPKCS1PublicKey(&clientKey.PublicKey))  // Client's public key
    derivedKey := h.Sum(nil)
    fmt.Printf("Derived key length: %d, first few bytes: %x\n", len(derivedKey), derivedKey[:8])

    // Marshal request to JSON
    jsonData, err := json.Marshal(request)
    if err != nil {
        panic(fmt.Sprintf("Failed to marshal request: %v", err))
    }

    // Create AES cipher using derived key
    block, err := aes.NewCipher(derivedKey)
    if err != nil {
        panic(fmt.Sprintf("Failed to create AES cipher: %v", err))
    }

    // Create GCM mode
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(fmt.Sprintf("Failed to create GCM: %v", err))
    }

    // Generate nonce
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        panic(fmt.Sprintf("Failed to generate nonce: %v", err))
    }

    // Encrypt the request data
    encryptedData := gcm.Seal(nil, nonce, jsonData, nil)
    fmt.Printf("Encrypted request data length: %d\n", len(encryptedData))

    // Encrypt the derived key with server's public key
    encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, serverPublicKey, derivedKey)
    if err != nil {
        panic(fmt.Sprintf("Failed to encrypt key: %v", err))
    }

    // Create final payload
    payload := EncryptedPayload{
        EncryptedKey:  encryptedKey,
        EncryptedData: encryptedData,
        Nonce:        nonce,
    }

    // Marshal final payload
    finalData, err := json.Marshal(payload)
    if err != nil {
        panic(fmt.Sprintf("Failed to marshal payload: %v", err))
    }

    fmt.Println("Sending registration request to server...")
    // Send request
    resp, err := client.Post(
        "https://192.168.0.219:8080/api/localsend/v2/register",
        "application/octet-stream",
        bytes.NewBuffer(finalData),
    )
    if err != nil {
        panic(fmt.Sprintf("Failed to send request: %v", err))
    }
    defer resp.Body.Close()

    // Read and process response
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        panic(fmt.Sprintf("Failed to read response: %v", err))
    }
    fmt.Printf("Received response with status: %d\n", resp.StatusCode)

    if resp.StatusCode != http.StatusOK {
        // Try to read error message
        fmt.Printf("Error response: %s\n", string(body))
        panic(fmt.Sprintf("Server returned error status: %d", resp.StatusCode))
    }

    // Create cipher for response decryption using same derived key
    decBlock, err := aes.NewCipher(derivedKey)
    if err != nil {
        panic(fmt.Sprintf("Failed to create decrypt cipher: %v", err))
    }

    decGCM, err := cipher.NewGCM(decBlock)
    if err != nil {
        panic(fmt.Sprintf("Failed to create decrypt GCM: %v", err))
    }

    nonceSize := decGCM.NonceSize()
    if len(body) < nonceSize {
        panic(fmt.Sprintf("Response too short: got %d bytes, need at least %d bytes", len(body), nonceSize))
    }

    responseNonce := body[:nonceSize]
    ciphertext := body[nonceSize:]
    fmt.Printf("Nonce size: %d, Ciphertext size: %d\n", len(responseNonce), len(ciphertext))

    plaintext, err := decGCM.Open(nil, responseNonce, ciphertext, nil)
    if err != nil {
        fmt.Printf("Decryption failed with nonce: %x\n", responseNonce)
        fmt.Printf("Ciphertext: %x\n", ciphertext)
        panic(fmt.Sprintf("Failed to decrypt response: %v\n", err))
    }
    fmt.Println("Successfully decrypted response")

    var response RegisterResponse
    if err := json.Unmarshal(plaintext, &response); err != nil {
        panic(fmt.Sprintf("Failed to parse response JSON: %v", err))
    }

    fmt.Printf("Successfully registered, got session ID: %s\n", response.SessionID)
    return response.SessionID
}

func uploadFile(filename string, pin string, client *http.Client) error {
    // 1. Prepare upload with PIN
    prepareURL := fmt.Sprintf("https://192.168.0.219:8080/api/localsend/v2/prepare-upload?pin=%s", pin)
    resp, err := client.Post(prepareURL, "application/json", nil)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var prepareResp FileTransferRequest
    if err := json.NewDecoder(resp.Body).Decode(&prepareResp); err != nil {
        return err
    }

    // 2. Upload file
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    body := &bytes.Buffer{}
    writer := multipart.NewWriter(body)
    part, err := writer.CreateFormFile("file", filename)
    if err != nil {
        return err
    }
    io.Copy(part, file)
    writer.Close()

    // Create upload URL with query parameters
    uploadURL := fmt.Sprintf(
        "https://192.168.0.219:8080/api/localsend/v2/upload?pin=%s&fileId=%s&token=%s",
        pin,
        prepareResp.FileId,
        prepareResp.Token,
    )

    req, err := http.NewRequest("POST", uploadURL, body)
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", writer.FormDataContentType())

    resp, err = client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("upload failed with status: %s", resp.Status)
    }

    return nil
}


func getServerPublicKey(client *http.Client) (*rsa.PublicKey, error) {
    resp, err := client.Get("https://192.168.0.219:8080/api/v1/public-key")
    if err != nil {
        return nil, fmt.Errorf("failed to get public key: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("server returned %d", resp.StatusCode)
    }

    keyData, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %v", err)
    }

    pubKey, err := x509.ParsePKCS1PublicKey(keyData)
    if err != nil {
        return nil, fmt.Errorf("failed to parse public key: %v", err)
    }

    return pubKey, nil
}

func sendRegistration(client *http.Client, request RegisterRequest, serverKey *rsa.PublicKey) string {
    // Marshal request to JSON
    jsonData, err := json.Marshal(request)
    if err != nil {
        panic(fmt.Sprintf("Failed to marshal request: %v", err))
    }

    // Generate AES key for hybrid encryption
    aesKey := make([]byte, 32)
    if _, err := rand.Read(aesKey); err != nil {
        panic(fmt.Sprintf("Failed to generate AES key: %v", err))
    }

    // Encrypt AES key with RSA
    encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, serverKey, aesKey)
    if err != nil {
        panic(fmt.Sprintf("Failed to encrypt AES key: %v", err))
    }

    // Create AES cipher
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        panic(fmt.Sprintf("Failed to create AES cipher: %v", err))
    }

    // Create GCM mode
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(fmt.Sprintf("Failed to create GCM: %v", err))
    }

    // Generate nonce
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        panic(fmt.Sprintf("Failed to generate nonce: %v", err))
    }

    // Encrypt the data
    encryptedData := gcm.Seal(nil, nonce, jsonData, nil)

    // Create final payload
    payload := EncryptedPayload{
        EncryptedKey:  encryptedKey,
        EncryptedData: encryptedData,
        Nonce:        nonce,
    }

    // Marshal final payload
    finalData, err := json.Marshal(payload)
    if err != nil {
        panic(fmt.Sprintf("Failed to marshal payload: %v", err))
    }

    // Send request
    resp, err := client.Post(
        "https://192.168.0.219:8080/api/v1/register",
        "application/octet-stream",
        bytes.NewBuffer(finalData),
    )
    if err != nil {
        panic(fmt.Sprintf("Failed to send request: %v", err))
    }
    defer resp.Body.Close()

    // Decrypt response
    body, _ := ioutil.ReadAll(resp.Body)
    
    // Parse response
    var response RegisterResponse
    json.Unmarshal(body, &response)

    return response.SessionID
}
package main

import (
    "fmt"
    "bytes"
    "net/http"
    "io"
    "mime/multipart"
    "os"
    "encoding/json"
)

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

type FileTransferRequest struct {
    FileId string `json:"fileId"`
    Token  string `json:"token"` 
}

func main() {
    client := &http.Client{}

    pin := "847795"
    sessionId := register(client)
    fmt.Printf("Got session ID: %s\n", sessionId)
    
    err := uploadFile("test.txt", pin, sessionId, client)
    if err != nil {
        panic(fmt.Sprintf("Failed to upload file: %v", err))
    }
    fmt.Println("File upload completed successfully")
}

func register(client *http.Client) string {
    fmt.Println("Starting registration process...")
    
    // Create registration request payload
    regRequest := RegisterRequest{
        Alias:       "TestClient",
        Version:     "2.0",
        DeviceModel: "GoClient",
        DeviceType:  "desktop",
        Fingerprint: "test-fingerprint",
        Port:        53317,
        Protocol:    "http",
        Download:    true,
    }
    
    payload, err := json.Marshal(regRequest)
    if err != nil {
        panic(fmt.Sprintf("Failed to marshal registration request: %v", err))
    }

    // Send registration request
    resp, err := client.Post(
        "http://192.168.0.191:53317/api/localsend/v2/register",
        "application/json",
        bytes.NewBuffer(payload),
    )
    if err != nil {
        panic(fmt.Sprintf("Failed to send request: %v", err))
    }
    defer resp.Body.Close()

    // Parse response
    var response RegisterResponse
    if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
        panic(fmt.Sprintf("Failed to parse response: %v", err))
    }

    fmt.Printf("Successfully registered, got session ID: %s\n", response.SessionID)
    return response.SessionID
}

func uploadFile(filename string, pin string, sessionId string, client *http.Client) error {
    // 1. Prepare upload with PIN
    prepareURL := fmt.Sprintf("http://192.168.0.191:53317/api/localsend/v2/prepare-upload?pin=%s", pin)
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
        "http://192.168.0.191:53317/api/localsend/v2/upload?sessionId=%s&fileId=%s&token=%s",
        sessionId,
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
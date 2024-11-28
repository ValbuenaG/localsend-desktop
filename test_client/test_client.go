package main

import (
    "fmt"
    "bytes"
    "net/http"
    "crypto/tls"
    "io"
    "mime/multipart"
    "os"
    "encoding/json"
)

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

    pin := "957732"
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
    
    // Send registration request
    resp, err := client.Post(
        "https://192.168.0.219:8080/api/localsend/v2/register",
        "application/json",
        nil,
    )
    if err != nil {
        panic(fmt.Sprintf("Failed to send request: %v", err))
    }
    defer resp.Body.Close()

    // Parse response
    var response map[string]string
    if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
        panic(fmt.Sprintf("Failed to parse response: %v", err))
    }

    sessionId := response["sessionId"]
    fmt.Printf("Successfully registered, got session ID: %s\n", sessionId)
    return sessionId
}

func uploadFile(filename string, pin string, sessionId string, client *http.Client) error {
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
        "https://192.168.0.219:8080/api/localsend/v2/upload?sessionId=%s&fileId=%s&token=%s",
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
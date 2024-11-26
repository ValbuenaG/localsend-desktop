# LocalSend Protocol POC

A proof of concept implementation of LocalSend protocol for offline file sharing, implemented in Go. This POC focus specifically on device registration and file transfer capabilities.

## Overview

The POC consists of two main components:
- Server (`app.go`): A Wails desktop app running an HTTPS server
- Test Client (`test_client.go`): A command-line client demonstrating the protocol flow

## LocalSend Protocol Implementation

This POC replicates the LocalSend registration endpoint (`/api/localsend/v2/register`)

## Registration Flow

1. **Client Side** (`test_client.go`):
```
- Generate RSA keypair
- Get server's public key
- Create register request (PIN + client public key)
- Derive symmetric key (SHA256 of concatenated public keys)
- Encrypt request with AES-GCM
- Send encrypted payload to server
```

2. **Server Side** (`app.go`):
```
- Generate random PIN
- Accept registration request
- Decrypt payload using server's private key
- Validate PIN
- Generate and encrypt session ID
- Return encrypted session ID to client
```

## File Transfer

After successful registration, files can be transferred using:

1. **Prepare Upload**:
```
POST /api/v1/prepare-upload
- Requires session ID
- Returns transmission ID
```

2. **File Upload**:
```
POST /api/v1/upload
- Requires session ID and transmission ID
- Sends file via multipart form
- Protected by HTTPS
```

## Basic Usage

1. Start Server:
```
- $ cd localsend-desktop
- $ wails dev
- start server from the desktop app
```

2. Run Test Client:
```
- $ cd test_client
- $ go run test_client.go
```


## Limitations

- Accepts self-signed certificates without verification
- No certificate pinning
- File data not encrypted at application level
- Basic implementation of session management

## Testing

The POC includes a web interface for testing at root path (`/`), showing:
- Server IP
- Current PIN
- File upload interface with progress tracking
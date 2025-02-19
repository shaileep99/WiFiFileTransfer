# WiFiFileTransfer

## Introduction

**WiFiFileTransfer** is a backend-only file transfer application built in **C**, designed for seamless local network file sharing. It leverages systems programming concepts like **dynamic memory management, process/threads handling, concurrency, file I/O, inter-procedure calls, networking**, and more. This project was implemented as part of a systems programming course to meet specific academic requirements.

WiFiFileTransfer provides two distinct modes of operation for file transfer:
1. **TCP Upload Mode:** Clients can upload files to the server by specifying a filename or path. The server listens on a TCP port, accepting file uploads and saving them in a specified directory.
2. **UDP Broadcast Receive Mode:** The server passively listens on a UDP port for broadcasted file data from other devices on the same network, enabling quick file sharing without establishing an active connection.

This lightweight and efficient server is perfect for local Wi-Fi environments where devices need a simple, backend-only solution for sharing files without a frontend interface.

### Key Features:
- **Secure and Reliable File Transfer:** AES-256 encryption for TCP transfers ensures data integrity and security.
- **Modes of Operation:**
  - **TCP Upload Mode:** Enables reliable file transfers with error handling.
  - **UDP Broadcast Mode:** Allows quick, lightweight file sharing without requiring an active connection.
- **Concurrent Processing:** Multi-threaded architecture handles simultaneous transfers.
- **File Management:** Received files are stored in a structured directory and can be listed easily.
- **Cross-Platform Compatibility:** Designed for POSIX-compliant systems like Linux.

### How It Works:
1. **Server Initialization:** The server starts listening on a TCP or UDP port based on the selected mode.
2. **File Transfer:**
   - In **TCP Mode**, a client connects to the server, uploads a file, and the server saves it to a specified directory.
   - In **UDP Mode**, the server passively listens for file broadcasts and saves them with standardized or metadata-based naming.
3. **Thread Management:** Threads handle client connections and file operations concurrently for efficient processing.

The project integrates the following systems programming concepts:
- **Dynamic Memory Management:** Efficient use of heap memory for buffer allocation.
- **Process/Threads Handling:** Use of POSIX threads for concurrent file transfers.
- **Concurrency:** Multiple file transfers handled simultaneously using threading and synchronization.
- **Networking:** Implementation of TCP and UDP protocols for file transfer.
- **File I/O:** Reading, writing, and managing files on the server.
- **Inter-Procedure Calls:** Modular design with functions handling encryption, file operations, and networking.

---

## Installation

### Prerequisites
- GCC Compiler
- OpenSSL Library
- POSIX-compliant Operating System (e.g., Linux)

### Steps to Install

1. Download the source code:
```bash
cd Project3
```

2. Compile the application using the provided Makefile:
```bash
make
```

3. Run the application:
```bash
./file_transfer
```

---

## Usage

### Server-Side Execution
1. Start the server by running the compiled executable:
   ./file_transfer

2. Choose a mode of operation (TCP or UDP) and configure the necessary settings.

### Client-Side Usage
- **TCP Upload Mode:** Connect to the server's IP and port to upload files.
- **UDP Broadcast Mode:** Broadcast file data to the server's UDP port for quick sharing.

### Menu Options
1. **Send File (TCP):** Input the target IP and file path to send a file securely.
2. **List Received Files:** View all files stored in the server's receiving directory.
3. **Show Server IP:** Display the local IP address of the server.
4. **Exit:** Quit the application.

---

## File Structure

WiFiFileTransfer/
├── decryption.c        # Decryption logic
├── decryption.h        # Decryption function declarations
├── encryption.c        # Encryption logic
├── encryption.h        # Encryption function declarations
├── file_transfer.c     # File sending and receiving logic
├── Makefile            # Build instructions
└── README.md           # Documentation


---

## Dependencies

The following libraries are required:
- **OpenSSL:** Used for AES-256 encryption and secure random number generation.
- **POSIX Threads (pthreads):** Enables multi-threading for concurrent file transfers.

To install dependencies on Ubuntu/Debian:
```bash
sudo apt update
sudo apt install gcc libssl-dev
```


# DirectDrop

A simple, direct, and secure **peer-to-peer (P2P)** file transfer tool written in Python3. DirectDrop allows you to send files directly between two computers over a network connection without intermediaries, with optional AES encryption for secure transfers.

**License:**  
MIT License

## Key Features
* **End-to-End Encryption**: `AES-256-CBC` encryption with `PBKDF2` key derivation
* **Memory Protection**: `SecureString` implementation employs best-effort techniques to minimize memory leaks, though zero leakage cannot be guaranteed
* **Multiple Transfer Modes**: Choose between `strict`, `non-strict`, and `low-memory` modes
* **Progress Tracking**: Real-time transfer statistics with speed metrics. (Only available on client)
* **Checksum Verification**: `SHA3-512` Integrity checking for all transfers
* **Network Flexibility**: Works across LAN or internet with configurable interfaces

## How it works
DirectDrop establishes a direct `TCP` connection between machines:
1. The *sender (server)* listens on a specified port with `-l / --listen`
2. The *receiver (client)* connects to the port using `-c / -connect <IP>:<PORT>`
3. File encryption mode, strict mode, and low memory mode is synced
4. File metadata is being transferred.
5. Main File Transfer Process
6. `SHA3-512` Checksum

## Usage
> [!TIP]
> If you don't have python3 installed on your computer, no worries, a pre-compiled binary is available on the [release](https://github.com/max9836/DirectDrop/releases/latest) page

## Installing the requirements
```bash
pip install -r requirements.txt
```

### Arguments
| Argument                   | Description                                                 | Advanced Description |
|----------------------------|-------------------------------------------------------------|----------------------|
| `-l`, `--listen`           | Listen for incoming connections                             | Starts the program in server mode, waiting for inbound file transfer requests. Typically used in combination with `--port` and `--interface`. |
| `-f <file>`, `--file`      | Specify the file path to send, or name to save as on receive| In send mode: full path of file to transfer. In receive mode: the desired filename to save the received content. |
| `-c <IP>`, `--connect`     | Connect to a given IP address to receive a file             | Initiates client mode targeting the specified IP. Requires `--port`. Performs TCP handshake and begins file reception. Format: `-c 192.168.0.2/9000` / `-c 192.168.0.2:9000` |
| `-i <iface>`, `--interface`| Specify the network interface                               | Binds the listener (server mode) to a specific network interface. Useful for multi-homed systems. |
| `-e`, `--encrypt`          | Encrypt the file before sending                             | Uses AES or similar encryption on file data before transmission. Requires user to input a key at runtime. Compatible with `--low-mem-mode`. |
| `-p <port>`, `--port`      | Port number to use                                          | TCP port used for sending or receiving. Defaults to 0, letting the OS choose a free port. |
| `-F`, `--force`            | Overwrite file without confirmation                         | Bypasses confirmation prompts when overwriting existing files during receive. Useful for scripting or automation. |
| `-v`, `--verbose`          | Enable verbose output                                       | Outputs progress, status, and file metadata during transfer. Helps with tracking and user feedback. |
| `-d`, `--debug`            | Enable debug output                                         | Adds low-level diagnostic messages including connection events, chunk handling, and internal state. |
| `--use-strict`             | Enable strict chunk handling mode                           | Enforces strict per-chunk integrity. The receiver waits for each chunk to fully arrive before continuing. Useful for debugging connectivity or fragmentation issues. |
| `--low-mem-mode`           | Enable low-memory mode                                      | Encrypts chunks individually rather than loading the entire file. Reduces RAM usage, but might be a lot slower. Only effective with `--encrypt`. |

### Basic Transfer
**Sender / Server (has the file)**:
The command below opens a port on a server and prepare to send the file `myfile.txt`
```bash
python3 directdrop.py -l -f myfile.txt
```
If you are running the pre-compiled binaries:
```bash
./directdrop -l -f myfile.txt
```

**Receiver / Client (gets the file)**:
The command below connects to `192.168.0.2` on port `9000`
```bash
python3 directdrop.py -c 192.168.0.2/9000
```
and the following command does the same thing
```bash
python3 directdrop.py -c 192.168.0.2:9000
```

### Encrypted Transfer
**Sender**:
After the execution of the following command, there will be a prompt for encryption password
```bash
python3 directdrop.py -l -f secret.docx -e
```

**Receiver**:
```bash
python3 directdrop.py -c 192.168.0.2/9000 -e
```

### Advanced options
| Option             | Description                                                    |
|--------------------|----------------------------------------------------------------|
| `-i <interface>`    | Bind to specific network interface                             |
| `--low-mem-mode`    | Enable memory-efficient per-chunk encryption (for large files) |
| `--use-strict`      | Enable strict packet verification mode                         |
| `-F`                | Force overwrite existing files without prompt                  |
| `-v`                | Verbose output                                                 |

### 🔧 Advanced Configuration Options

| Parameter | Description |
|----------|-------------|
| `pim` | **Personal Iteration Multiplier** used in password hashing (e.g., PBKDF2). A higher value increases resistance to brute-force attacks. Recommended: 6144 or more for modern systems. |
| `connect_timeout` | Time (in seconds) to wait for a connection to be established before giving up. Useful to avoid indefinite hangs when peer is offline. |
| `low_mem_mode` | Enables memory-efficient mode where chunks are encrypted individually before transmission. Essential for large files on systems with limited RAM. Only usable when encryption is enabled (`-e`). |
| `throttling_delay` | Delay between each packet send (in milliseconds). Prevents network congestion and buffer overflow errors, especially in strict mode. Must not be set to 0. |
| `strict_packet_chunk_size` | Packet size (in bytes) for **strict mode**, where each chunk must be fully received before proceeding. Helps ensure reliable transfer over unstable links. Default is 4MB. Do not exceed 2GB limit due to socket size constraints. |
| `non_strict_packet_chunk_size` | Packet size (in bytes) for **non-strict mode**, where packets can be received continuously. Max allowed value is `2147479552` (just under 2GB). |
| `low_mem_mode_packet_chunk_size` | Defines the chunk size when low-memory mode is enabled. Default is `4MB`. Adjust to `10KB` for very constrained systems or increase up to `1GB` for faster performance on modern machines. |
| `memory_shred_passes` | Number of passes used to overwrite sensitive memory (e.g., encryption keys, plaintext buffers) before deallocation. Higher values reduce the risk of memory recovery by forensic tools but may affect performance. Recommended: 2–3 passes. |


## Security Notes
DirectDrop implements:
* Secure memory handling with multiple shred passes
* Time-consistant operations
* Protected key storage
* Hardware-isolate encryption

> [!IMPORTANT]
> This script provides strong software protection but cannot guarantee prevention of all hardware-based memory leaks (cold boot attacks, DMA exploits, etc.).

For maximum security:
1. Use on systems with encrypted RAM
2. Restrict physical access during transfer
3. Shut down systems after sensitive transfers

## Encryption Methods
| Criteria         | Whole-File Encryption (`-e`)                  | Per-Chunk Encryption (`--low-mem-mode`)                |
|------------------|-----------------------------------------------|--------------------------------------------------------|
| **Security**      | ✅ Highest (single IV, hides file structure)   | ⚠️ Good (requires proper IV management)                 |
| **Memory Usage**  | ❌ High (loads entire file)                   | ✅ Low (streams chunks)                                 |
| **Speed**         | ❌ Slower for large files                     | ✅ Faster (parallelizable)                              |
| **File Structure**| ✅ Completely hidden                          | ⚠️ Partial visibility (chunk sizes)                     |
| **Best For**      | Sensitive small/medium files                 | Large files or low-memory devices                      |

### Recommendations
* **Use Standard Encryption (`-e`)** when:
  * Transfering sensitive documents
  * File size < 1GB
  * System has sufficient RAM
* **Use Low-Memory Mode (`--low-mem-mode`)** when:
  * Transferring files > 1GB
  * Operating on memory-constrained devices
  * Performance is critical

## Troubleshooting
**Invalid Args**
* Make sure you have exactly one of `-l` (with `-f`) or `-c`

**Connectivity Issues**
* Verify firewall allows TCP on specific port
* Check interface binding with `-i` if on multi-homed systems
* Increase `connect_timeout` in `config.py` for slow networks
* Try using `--use-strict` for strict mode so the system receives the exact number of bytes on the chunk before continues.
> [!TIP]
> You can try using `-d` for debug output to see chunk hashes. If the chunk hashes don't match after several chunks, try increasing `throttling_delay` in `config.py`

**Encryption Error**
* Ensure identical passwords on both sides
* Verify both sides use same mode (e.g. standard/low-memory)
* Check system clocks are synchronized (affects key derivation)

**Performance Problems**
* Adjust `throttling_delay` for you network
* Try different chunk sizes in `config.py`
* Disable strict mode (`--use-strict`) for faster transfers

### Not yet resolved?
If your issue still haven't resolved, you are welcome to open an issue on Github Issue page.
I am very sorry about the inconvenience

## Contributing
Contributions are welcomed.

## License
This project is licensed under MIT license.

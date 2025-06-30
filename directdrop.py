import socket
import argparse
import os
import sys
import time
import gc
import netifaces
import re as regex
from exceptions import *
from hashlib import sha3_512, md5
from config import *
from encryption import *

class logger:
    def log(self, message):
        print(f"{message}")
    def info(self, message):
        print(f"[INFO] {message}")
        return True
    def error(self, Exceptions: Exception, message=None):
        if Exceptions is None and message is None:
            return False
        if Exceptions is None:
            print(f"[ERROR] {message}")
        elif message is None:
            raise Exceptions
        else:
            print(f"[ERROR] {message}")
            raise Exceptions
        return True
    def debug(self, message):
        if self.is_debug:
            print(f"[DEBUG] {message}")
        return True
    def warning(self, message):
        print(f"[WARNING] {message}")
    def verbose(self, message):
        if self.is_verbose:
            print(f"[VERBOSE] {message}")

    def __init__(self, is_verbose=False, is_debug=False):
        self.is_verbose = is_verbose
        self.is_debug = is_debug

class arg:

    listen = False
    file = ""
    connect = ""
    encrypt = False
    port = 0
    interface = ""
    server_addr = connect
    server_port = 0

    # This is not updated after args parser, use low_mem_mode from config.py instead
    low_mem_mode = False
    use_strict = False
    force = False
    verbose = False
    debug = False

    key = SecureString()
    is_encrypted = False

args = arg()
log = logger()
tmp_file = []

class FileTransferSystem():
    def __init__(self, socket: socket.SocketType, addr, encrypt: bool=False):
        self.socket = socket
        self.ip_address = addr[0]
        self.port = addr[1]
        self.encrypt = encrypt
        self.socket = socket
        if args.encrypt is True:
            self.encryptor = EncryptionSystem(args.key)

    def receive(self):
        log.debug("Syncing modes... (Encryption (and key) & low_mem_mode & strict_mode)")

        chunk_size_sync = low_mem_mode_packet_chunk_size if low_mem_mode else strict_packet_chunk_size if args.use_strict else non_strict_packet_chunk_size
        self.SyncEncryption()
        self.SyncMode("Strict Mode", args.use_strict, StrictModeImbalanceException())
        self.SyncMode("Low memory mode", low_mem_mode, LowMemModeImbalanceException())
        self.SyncValue(chunk_size_sync, PacketChunkSizeNotMatch(f"Packet chunk size mismatch: Expected {chunk_size_sync} for {'low_mem_mode' if low_mem_mode else 'strict mode' if args.use_strict else 'normal mode'}, got {chunk_size_sync}"))

        log.info(f"Recieving file from {self.ip_address}:{self.port}.")

        if self.encrypt:
            fn_encrypted = secure_unpad(secure_recv(self.socket, 256))
            fs_encrypted = secure_unpad(secure_recv(self.socket, 128))

            self.filename = self.encryptor.decrypt(fn_encrypted).decode("utf-8")
            self.filesize = int(self.encryptor.decrypt(fs_encrypted))
        else:
            self.filename = secure_unpad(secure_recv(self.socket, 256)).decode('utf-8')
            self.filesize = int(secure_unpad(secure_recv(self.socket, 128)))

        if args.file != "":
            self.filename = args.file
        else:
            args.file = self.filename

        h_filesize = ""
        if log.is_verbose:
            h_filesize = human_readable(self.filesize)

        log.verbose(f"Received file metadata: FILE_NAME: {self.filename} FILE_SIZE: {self.filesize} ({h_filesize})")

        if os.path.exists(self.filename):
            if not args.force:
                while True:
                    in_ = input(f"File {self.filename} already exists, do you want to overwrite it (you can use --force to bypass this prompt)? [y/N] ")
                    if in_ in ("y", "Y", "n", "N", ""):
                        break
                match in_:
                    case "y" | "Y":
                        pass
                    case "n" | "N":
                        close_socket(self.socket)
                        exit(0)
                    case "":
                        close_socket(self.socket)
                        exit(0)
            else:
                log.info(f"Overwriting existing file: '{self.filename}'")

        # THE MAGIC STARTS HERE

        self.totalpackets = self.filesize / strict_packet_chunk_size
        if self.totalpackets % 1 != 0:
            self.totalpackets = int(self.totalpackets) + 1
        else:
            self.totalpackets = int(self.totalpackets)

        self.last_packet_size = self.filesize - ((self.totalpackets - 1) * strict_packet_chunk_size)

        with open(self.filename,"wb") as file:
            received = 0
            received_packet = 0
            while received < self.filesize:
                speed_meter_start_time = time.time()
                received_packet += 1
                if low_mem_mode:
                    current_bait_size: int = 0
                    # Receive bait first
                    recv_bait = secure_recv(self.socket, 256)
                    recv_bait = secure_unpad(recv_bait)
                    current_bait_size = int(self.encryptor.decrypt(recv_bait))
                    enc_recv = secure_recv(self.socket, current_bait_size)
                    recv = self.encryptor.decrypt(enc_recv)

                elif args.use_strict:
                    if received_packet != self.totalpackets:
                        recv = self.socket.recv(self.filesize)
                    else:
                        # Last packet
                        recv = self.socket.recv(self.last_packet_size)
                    while True:
                        if received + len(recv) == self.filesize:
                            break
                        if len(recv) < strict_packet_chunk_size:
                            if received_packet != self.totalpackets:
                                recv += self.socket.recv(self.filesize)
                            else:
                                # Last packet
                                recv += self.socket.recv(self.last_packet_size)
                        elif len(recv) > strict_packet_chunk_size:
                            close_socket(self.socket, True)
                            log.error(CorruptedPacket(), f"A packet larger than packet_chunk_size is received; Expected size: {strict_packet_chunk_size}; Got: {len(recv)}")
                            return
                        else:
                            break
                else:
                    recv = self.socket.recv(self.filesize - received)
                received += len(recv)
                if low_mem_mode:
                    log.debug(f"Packet {received_packet} received with bytes {len(enc_recv)} [{human_readable(len(enc_recv))}]; Chunk-checksum: {md5(enc_recv).hexdigest()}")
                else:
                    log.debug(f"Packet {(received_packet) if args.use_strict else (str(received_packet) + '/' + str(self.totalpackets))} received with bytes {len(recv)} [{human_readable(len(recv))}]; Chunk-checksum: {md5(recv).hexdigest()}")
                sys.stdout.write(f"{' ' * 100}\r")
                sys.stdout.write(f"{(received/self.filesize*100):.2f}% Done.\t({received}/{self.filesize})\t[{human_readable(received)}/{human_readable(self.filesize)}]\t" + "{" + format_speed(len(recv)/(time.time() - speed_meter_start_time)) + "}\r")
                sys.stdout.flush()
                file.write(recv)
        print()

        log.verbose("Calculating checksum...")
        checksum = sha3_512(open(self.filename, 'rb').read())

        # Note that the checksum here is the ENCRYPTED FILE CHECKSUM.

        log.verbose(f"Checksum: {checksum.hexdigest()}")

        if self.encrypt:
            recv = secure_unpad(secure_recv(self.socket, 128))
            server_checksum = self.encryptor.decrypt(recv)
            self.socket.send(secure_pad(128, self.encryptor.encrypt(checksum.digest())))

        else:
            server_checksum = secure_recv(self.socket, 64)
            self.socket.send(checksum.digest())

        if server_checksum == checksum.digest():
            log.info(f"File transfer completed, {'encrypted' if self.encrypt else 'unencrypted'} checksum verified")
        else:
            log.info(f"File transfer completed, BUT {'ENCRYPTED ' if self.encrypt else 'UNECRYPTED '}CHECKSUM DID NOT MATCH")
            log.warning("CHECKSUM FROM SERVER DID NOT MATCH")
            log.verbose("SERVER_SENT_CHECKSUM=" + server_checksum.hex())

    def send(self):
        log.debug("Syncing modes... (Encryption (and key) & low_mem_mode & strict_mode)")

        chunk_size_sync = low_mem_mode_packet_chunk_size if low_mem_mode else strict_packet_chunk_size if args.use_strict else non_strict_packet_chunk_size
        self.SyncEncryption()
        self.SyncMode("Strict Mode", args.use_strict, StrictModeImbalanceException())
        self.SyncMode("Low memory mode", low_mem_mode, LowMemModeImbalanceException())
        self.SyncValue(chunk_size_sync, PacketChunkSizeNotMatch(f"Packet chunk size mismatch: Expected {chunk_size_sync} for {'low_mem_mode' if low_mem_mode else 'strict mode' if args.use_strict else 'normal mode'}, got {chunk_size_sync}"))

        log.info(f"Sending file to {self.ip_address}:{self.port}.")

        self.filename = args.file
        self.filesize = os.path.getsize(self.filename + (".enc" if self.encrypt and not low_mem_mode else ""))

        log.debug(f"Sending file metadata to client: name: {self.filename}; size: {self.filesize}")

        if self.encrypt:

            encrypted_fn = secure_pad(256, self.encryptor.encrypt(bytes(str(self.filename), "utf-8")))
            encrypted_fs = secure_pad(128, self.encryptor.encrypt(bytes(str(self.filesize), "utf-8")))

            self.socket.send(encrypted_fn)
            self.socket.send(encrypted_fs)

        else:

            self.socket.send(secure_pad(256, self.filename.encode('utf-8')))
            self.socket.send(secure_pad(128, str(self.filesize).encode('utf-8')))

        # THE MAGIC STARTS HERE
        if not low_mem_mode:
            self.totalpackets = self.filesize / (strict_packet_chunk_size if args.use_strict else non_strict_packet_chunk_size)
            if self.totalpackets % 1 != 0:
                self.totalpackets = int(self.totalpackets) + 1
            else:
                self.totalpackets = int(self.totalpackets)

        log.verbose("Sending main file...")
        with open(self.filename + (".enc" if self.encrypt and not low_mem_mode else ""), "rb") as files:
            sent = 0
            sent_packet = 0
            while sent < self.filesize:
                sent_packet += 1
                if low_mem_mode:
                    content = files.read(low_mem_mode_packet_chunk_size)
                    encrypted = self.encryptor.encrypt(content)
                    self.socket.send(secure_pad(256, self.encryptor.encrypt(bytes(str(len(encrypted)), "utf-8"))))
                    bytes_sent = secure_send(self.socket, encrypted)
                    log.debug(f"Encrypted packet {sent_packet} sent with bytes {bytes_sent} [{human_readable(bytes_sent)}]; Chunk-checksum: {md5(encrypted if self.encrypt else content).hexdigest()}")
                    sent += len(content)
                else:
                    pointer = 0
                    chunk_size = min(strict_packet_chunk_size if args.use_strict else non_strict_packet_chunk_size, self.filesize - sent)
                    content = files.read(chunk_size)
                    bytes_sent = secure_send(self.socket, content)
                    pointer += bytes_sent
                    log.debug(f"Packet {sent_packet}/{self.totalpackets} sent with bytes {bytes_sent} [{human_readable(bytes_sent)}]; Chunk-checksum: {md5(content).hexdigest()}")
                    sent += bytes_sent
                time.sleep(throttling_delay / 1000)

        log.verbose("Calculating checksum...")
        checksum = sha3_512(open(self.filename + '.enc' if self.encrypt and not low_mem_mode else self.filename, 'rb').read())
        log.verbose(f"Checksum: {checksum.hexdigest()}")

        if self.encrypt:
            self.socket.send(secure_pad(128, self.encryptor.encrypt(checksum.digest())))
            recv = secure_unpad(secure_unpad(secure_recv(self.socket, 128)))
            client_checksum = self.encryptor.decrypt(recv)

        else:
            self.socket.send(checksum.digest())
            client_checksum = secure_recv(self.socket, 64)

        if client_checksum == checksum.digest():
            log.info(f"File transfer completed, {'encrypted' if self.encrypt else 'unencrypted'} checksum verified")
        else:
            log.info(f"File transfer completed, BUT {'ENCRYPTED ' if self.encrypt else 'UNENCRYPTED '}CHECKSUM DID NOT MATCH")
            log.warning("CHECKSUM FROM CLIENT DID NOT MATCH")
            log.verbose("CLIENT_REPLIED_CHECKSUM=" + client_checksum.hex())

        clean()

    def SyncEncryption(self):
        global pim
        encryption_true_byte = b'\x00'
        encryption_false_byte = b'\x01'
        our_byte = encryption_true_byte if args.encrypt else encryption_false_byte

        secure_send(self.socket, our_byte)
        their_byte = secure_recv(self.socket, 1)

        if our_byte != their_byte:
            log.error(InvalidKeyOnClientError(f"Encryption is enabled on {'sever' if their_byte == encryption_true_byte and not args.listen else 'client'}. However, it it not active on the {'server' if not (their_byte == encryption_true_byte and not args.listen) else 'client'}. Please ensure that both ends use -e / --encrypt to encrypt the traffic"))
            
        if args.encrypt:
            local_key_hash = b''
            with args.key.temporary_access() as key:
                local_key_hash = sha3_512(key.encode("utf-8")).digest()
            secure_send(self.socket, local_key_hash)
            key_verf = secure_recv(self.socket, 64)
            if key_verf != local_key_hash:
                log.error(InvalidKeyOnClientError())

            # PIM sync
            secure_send(self.socket, secure_pad(16, bytes(str(pim).encode("utf-8"))))
            their_pim = int(secure_unpad(secure_recv(self.socket, 16)))
            if pim != their_pim:
                log.warning("The PIM of the server is differnet from the client. Using server PIM")
                if not args.listen: # Client mode
                    pim = int(their_pim)
                    self.encryptor.pim = pim

    def SyncValue(self, value: int, exception: Exception):
        try:
            if self.encrypt:
                chunk_str = str(value).encode('utf-8')
                encrypted_chunk = self.encryptor.encrypt(chunk_str)
                self.socket.send(secure_pad(2048, encrypted_chunk))

                recv = secure_unpad(secure_recv(self.socket, 2048))
                decrypted = self.encryptor.decrypt(recv)
                remote_chunk = int(decrypted.decode('utf-8'))
            else:

                chunk_str = str(value).encode('utf-8')
                self.socket.send(secure_pad(32, chunk_str))

                recv = secure_unpad(secure_recv(self.socket, 32))
                remote_chunk = int(recv.decode('utf-8'))

            if value != remote_chunk:
                log.error(exception)

            return True

        except ValueError as e:
            log.error(CorruptedPacket(f"Invalid chunk size received: {str(e)}"))
        except Exception as e:
            log.error(CorruptedPacket(f"Chunk size verification failed: {str(e)}"))

    def SyncMode(self, mode_name: str, mode_value: bool, exception: Exception):
        try:
            true_byte = b'\x01'
            false_byte = b'\x02'

            if self.encrypt:
                self.socket.send(secure_pad(64, self.encryptor.encrypt(true_byte if mode_value else false_byte)))

                recv = secure_unpad(secure_recv(self.socket, 64))
                their_byte = self.encryptor.decrypt(recv)
            else:
                self.socket.send(true_byte if mode_value else false_byte)
                their_byte = secure_recv(self.socket, 1)

            if mode_value and their_byte == false_byte or not mode_value and their_byte == true_byte:
                log.error(exception)

            log.debug(f"{mode_name} mode synchronized successfully")
            return True
        except (LowMemModeImbalanceException, StrictModeImbalanceException, InvalidKeyOnClientError) as e:
            log.error(e)
            return False
        except Exception as e:
            log.error(CorruptedPacket(f"Mode synchronization failed: {str(e)}"))
            return False

def close_socket(_socket: socket.SocketType, is_Error = False):
    if _socket.fileno() == -1:
        return
    log.verbose(f"Socket {_socket.getsockname()[0]} with port {_socket.getsockname()[1]} closed" + " because of an error" if is_Error else "")
    try:
        _socket.shutdown(socket.SHUT_RDWR)
    except Exception as e:
        log.error(None, f"Failed to shutdown socket: {str(e)}")
    finally:
        _socket.close()
        clean()

def secure_pad(pad_size: int, obj: bytes):
    if obj[-1] == 0x00:
        # Encryption last byte is 0x00, use 0x01 as padding bytes
        padded = obj.ljust(pad_size, b'\x01')
    else:
        padded = obj.ljust(pad_size, b'\x00')
    return padded

def secure_unpad(obj: bytes):
    obj_size = len(obj)
    unpadded = obj.rstrip(b'\x00')
    if len(unpadded) == obj_size:
        unpadded = obj.rstrip(b'\x01')
    return unpadded

def secure_send(socket: socket.SocketType, data: bytes):
    current_bytes_sent = 0
    while current_bytes_sent < len(data):
        r_sent = socket.send(data[current_bytes_sent:])
        if r_sent == 0:
            raise ConnectionError("Socket connection broken")
        current_bytes_sent += r_sent
    return current_bytes_sent

def secure_recv(socket: socket.SocketType, buffersize: int) -> bytes:
    received_bytes = 0
    recv = b''
    while received_bytes < buffersize:
        chunk = socket.recv(buffersize - received_bytes)
        recv += chunk
        received_bytes += len(chunk)
    return recv

def encrypt_file():
    filename = args.file
    tmp_file.append(filename + ".enc")
    encryptor = EncryptionSystem(args.key)
    with open(filename, "rb") as file, open(filename + ".enc", "wb") as enc_file:
        log.info(f"File {filename} encrypting to {filename + '.enc'}")
        encrypted = encryptor.encrypt(file.read())
        enc_file.write(encrypted)
    log.info(f"File successfully encrypted")

def decrypt_file():
    log.info(f"Decrypting the file...")
    filename = args.file
    decryptor = EncryptionSystem(args.key)
    decryptor.pim = pim
    encrypted = open(filename, "rb").read()
    decrypted = decryptor.decrypt(encrypted)
    open(filename, "wb").write(decrypted)
    log.info(f"File successfully decrypted")

def clean():
    for filename in tmp_file:
        try:
            os.remove(filename)
            log.debug(f"Removed temp file: {filename}")
        except FileNotFoundError as e:
            log.error(None, f"Error removing temp file: {str(e)}")
    
    args.key.clear()
    collected = gc.collect()

    log.debug(f"Garbage collector collected {collected} objects")

def human_readable(byte: int) -> str:
    for unit in ["bytes", "KB", "MB", "GB"]:
        if byte < 1024:
            return f"{byte:.2f} {unit}"
        byte /= 1024
    return f"{byte:.2f} TB"

def format_speed(bytes_per_sec):
    _bytes_per_sec = bytes_per_sec
    for unit in ['bytes/sec', 'KB/sec', 'MB/sec', 'GB/sec']:
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.2f} {unit} | {format_ispeed(_bytes_per_sec)}"
        bytes_per_sec /= 1024
    return f"{bytes_per_sec:.2f} TB/sec | {format_ispeed(_bytes_per_sec)}"

def format_ispeed(bytes_per_sec):
    bits_per_sec = bytes_per_sec * 8
    for unit in ['bps', 'Kbps', 'Mbps', 'Gbps']:
        if bits_per_sec < 1000:
            return f"{bits_per_sec:.2f} {unit}"
        bits_per_sec /= 1000
    return f"{bits_per_sec:.2f} Tbps"

def transfer_file(socket: socket.SocketType, addr):
    log.info(f"Starting file transfer with {addr[0]} on port {addr[1]}.")
    transfer = FileTransferSystem(socket, addr, args.encrypt)
    try:
        transfer.send()
    except BrokenPipeError as e:
        clean()
        log.error(ConnectionTerminatedByClientException())
    except ConnectionResetError as e:
        clean()
        log.error(ConnectionTerminatedByClientException())
    except Exception as e:
        close_socket(socket, True)
        log.warning(f"Connection closed because of an error: {str(e)}")
        log.error(e)
    log.verbose(f"Socket {socket.getsockname()[0]} with port {socket.getsockname()[1]} Closed")
    socket.close()

def get_file(socket: socket.SocketType):
    log.info(f"Starting file transfer from {socket.getpeername()[0]} on port {socket.getpeername()[1]}.")
    transfer = FileTransferSystem(socket, socket.getpeername(), args.encrypt)
    try:
        transfer.receive()
    except BrokenPipeError:
        clean()
        log.error(ConnectionTerminatedByClientException())
    except Exception as e:
        clean()
        socket.close()
        log.warning(f"Connection closed because of an error: {str(e)}")
        log.error(e)
    log.verbose(f"Socket {socket.getsockname()[0]} with port {socket.getsockname()[1]} Closed")
    socket.close()

def connect():
    sock = socket.SocketType
    if args.interface != "":
        addr = netifaces.ifaddresses(args.interface)
        source_addr = addr[netifaces.AF_INET][0]['addr']
        sock = socket.create_connection((args.server_addr, args.server_port), timeout=connect_timeout, source_address=(source_addr, args.port))
    else:
        sock = socket.create_connection((args.server_addr, args.server_port), timeout=connect_timeout, source_address=("", args.port))
    log.info(f"Connected to {args.connect} from port {sock.getsockname()[1]}.")
    return sock

def listen():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if args.interface == "":
        local_ip = socket.gethostbyname(socket.gethostname())
    else:
        addr = netifaces.ifaddresses(args.interface)
        local_ip = addr[netifaces.AF_INET][0]['addr']
    server_socket.setsockopt(socket.SOL_SOCKET, 25, args.interface.encode())
    server_socket.bind((local_ip, args.port))
    server_socket.listen(0)
    log.log(f"Local IP address: {server_socket.getsockname()[0]}")
    log.log(f"Server is listening on port {server_socket.getsockname()[1]}")

    timeout_logtime = [3, 5, 10, 15, 17, 25, 30, 45, 60, 90, 120, 180]

    total = 0
    for i in range(len(timeout_logtime)):
        total += timeout_logtime[i]
    log.log(f"Waiting for incoming connections for a total of {total} seconds.")
    del total

    for timeout in range(len(timeout_logtime)):
        server_socket.settimeout(timeout_logtime[timeout])
        log.verbose(f"Listening for incoming connections on port {server_socket.getsockname()[1]} . Waiting for another {timeout_logtime[timeout]} seconds... (Timeout {timeout + 1}/{len(timeout_logtime)})")
        try:
            client_socket, addr = server_socket.accept()
            client_socket.settimeout(connect_timeout)
            server_socket.settimeout(connect_timeout)
            return client_socket, addr
        except socket.timeout:
            if timeout == len(timeout_logtime) - 1:
                server_socket.close()
                clean()
                log.error(NoConnectionError("No incoming connection within the timeout period."))
            else:
                log.verbose(f"No incoming connection within {timeout_logtime[timeout]} seconds. Retrying...")
                continue

def main():
    global low_mem_mode
    argparser = argparse.ArgumentParser(description="A simple, direct, and secure peer-to-peer (P2P) file transfer tool written in Python3. DirectDrop allows you to send files directly between two computers over a network connection without intermediaries, with optional AES encryption for secure transfers.",prog="DirectDrop",usage="%(prog)s [options]")
    argparser.add_argument("-l", "--listen", help="Listen for incoming connections", action="store_true")
    argparser.add_argument("-f <file>", "--file", help="Specify the file path to send, or name to save as on receive")
    argparser.add_argument("-c <IP>", "--connect", help="Connect to a given IP address to receive a file")
    argparser.add_argument("-i <INTERFACE>", "--interface", help="Specify the network interface")
    argparser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the file before sending. You will need to enter the key later")
    argparser.add_argument("-p", "--port", type=int, default=0, help="Port number to use (default: automatically assigned)")
    argparser.add_argument("-F", "--force", action="store_true", help="Overwrite file without confirmation")
    argparser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    argparser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    # Enable strict mode when chunk checksum is checked individually to debug connectivity issues.
    argparser.add_argument("--use-strict", action="store_true", help="Enable strict chunk handling mode. See README.md for more details")
    # Low memory mode is only available with -e encrypt arguemnt because it is used to aviod encrypting the file together
    argparser.add_argument("--low-mem-mode", action="store_true", help="Enable low-memory mode. See README.md for more details")
    argparser.parse_args(namespace=args)

    if args.verbose:
        log.is_verbose = True
    if args.debug:
        log.is_debug = True

    if (not os.path.isfile(args.file)) and args.listen is True:
        raise FileNotFoundError(f"File '{args.file}' does not exist. Please check the file path and try again.")

    if args.encrypt:
        args.key = secure_pwinput("Enter the key for encryption: ", mask="")
        with args.key.temporary_access() as key:
            if len(key) < 5:
                log.warning("Using a password with fewer than 5 characters is not allowed. Please choose a longer password to ensure minimum security requirements are met.")
                return
            elif len(key) < 12:
                log.warning("Using a password with fewer than 12 characters is considered insecure. It is recommended to use a longer password.")

    if args.low_mem_mode:
        low_mem_mode = True

    if args.low_mem_mode and args.use_strict:
        log.warning("Low memory mode with ignore use strict mode")
    if args.low_mem_mode and not args.encrypt:
        log.warning("Low memory mode has no effect without encryption argument")
        low_mem_mode = False
    if throttling_delay < 0.1:
        log.warning("Using a throttling delay lower than 0.1 ms may significantly increase the risk of packet corruption.")

    # This limitation works on my wifi adapter, not sure about other laptops.
    if strict_packet_chunk_size > 2147479552 or non_strict_packet_chunk_size > 2147479552 or low_mem_mode_packet_chunk_size > 2147479552:
        log.warning("The current packet chunk size is larger than the maximum packet size that python socket library can handle, try reduce this to 2147479552 or lower")
        return

    if  (args.connect != "" and args.listen is True):
        raise InvalidArgsCombo()

    if pim < 600:
        log.warning("Your PIM value is considered insecure. Please set one above 600")
    elif pim > 10000:
        log.error(ValueError("Your PIM value is too large (have to be less than 10000)"))

    if args.connect != "":
        if regex.match(r"^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}[/:]\d{1,5}$", args.connect) is None:
            log.error(None, "Invalid connection IP string. Use a ':' or '/' to specify the IP address followed by port number. The port number should be generated or specified on the server script.")
            return
        else:
            args.server_addr = regex.match(r"^\d+.\d+.\d+.\d+", args.connect).group(0)
            args.server_port = regex.search(r"[:/](\d+)$", args.connect).group(1)

    if args.listen:
        if args.encrypt and not low_mem_mode:
            encrypt_file()
        listened = listen()
        os.system("clear")
        log.log(f"Connection established with {listened[1][0]} on port {listened[1][1]}.")
        transfer_file(listened[0], listened[1])
    elif args.connect:
        connected = connect()
        sys.stdout.flush()
        get_file(connected)
        if args.encrypt and not low_mem_mode:
            decrypt_file()
    else:
        argparser.print_help()

if __name__ == "__main__":
    main()

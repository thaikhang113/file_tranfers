# server.py
import socket
import sqlite3
import os
import threading
import uuid 
from datetime import datetime
import time
import base64 
import struct 
import traceback 


try:
    from Crypto.Cipher import AES
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
     print("FATAL ERROR: PyCryptodome library not found. Install with 'pip install pycryptodome'")
     import sys
     sys.exit(1)




HOST = '10.11.12.109' 

PORT = 55555
BUFFER_SIZE = 8192 
STORAGE_DIR = "server_storage" 
DB_NAME = "server_data.db" 
SOCKET_TIMEOUT = 60.0 
CHUNK_TIMEOUT = 20.0 

KEY = b'Pb8qfKDyzwoqjiXrPVpsdhrsWxj8q8Tbv_f2n1S25Ds=' 
AES_KEY = None
NONCE_SIZE = 12 
TAG_SIZE = 16   
try:
    AES_KEY = base64.urlsafe_b64decode(KEY)
    if len(AES_KEY) not in [16, 24, 32]:
        raise ValueError("Decoded key length must be 16, 24, or 32 bytes for AES.")
    print(f"AES Key loaded successfully ({len(AES_KEY)*8}-bit).")
except (ValueError, TypeError, base64.binascii.Error) as e:
    print(f"FATAL: Invalid AES encryption key: {e}")
    import sys
    sys.exit(1)


if not os.path.exists(STORAGE_DIR):
    try:
        os.makedirs(STORAGE_DIR)
        print(f"Created storage directory: {STORAGE_DIR}")
    except OSError as e:
        print(f"FATAL: Could not create storage directory '{STORAGE_DIR}': {e}")
        import sys
        sys.exit(1)

db_lock = threading.Lock() 

def get_db_connection():
    """Gets a new database connection."""

    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False, timeout=10.0) 
        conn.execute("PRAGMA journal_mode=WAL;") 
        return conn
    except sqlite3.Error as e:
        print(f"FATAL: Could not connect to database {DB_NAME}: {e}")

        raise 

def initialize_database():
    """Initializes the database schema if it doesn't exist."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        print(f"Initializing database schema in {DB_NAME}...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL UNIQUE,
            file_size INTEGER NOT NULL, -- Store the size of the stored file (nonce+enc+tag)
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_recipient ON files (recipient)")
        conn.commit()
        print("Database schema initialized successfully.")
    except sqlite3.Error as e:
        print(f"FATAL: Failed to initialize database schema: {e}")
        raise 
    finally:
        if conn:
            conn.close()



def send_error(client_socket, addr, message):
    """Sends an error message back to the client."""
    log_message = f"[ERROR][{addr}] {message}"
    print(log_message)
    try:
        error_msg = f"ERROR: {message}"
        client_socket.sendall(error_msg.encode())
    except (socket.error, BrokenPipeError) as send_err:

        print(f"[ERROR][{addr}] Failed to send error message to client (socket error): {send_err}")

def verify_aes_gcm(file_path):
    """
    Verifies the integrity of the stored file (nonce + enc_data + tag).
    Reads the file in chunks for verification to handle large files.
    Returns (bool: success, str: message).
    """
    if not os.path.exists(file_path):
        return False, "File not found for verification."

    try:
        with open(file_path, 'rb') as f:

            nonce = f.read(NONCE_SIZE)
            if len(nonce) != NONCE_SIZE:
                return False, "File too small or failed to read nonce."

            f.seek(0, os.SEEK_END)
            total_size = f.tell()
            if total_size < NONCE_SIZE + TAG_SIZE:
                return False, "File too small to contain nonce and tag."
            data_size = total_size - NONCE_SIZE - TAG_SIZE

            f.seek(total_size - TAG_SIZE, os.SEEK_SET)
            tag = f.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
 
                 return False, "Failed to read full tag from end of file."

 
            f.seek(NONCE_SIZE, os.SEEK_SET) 
            cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
            bytes_processed = 0
            while bytes_processed < data_size:
                read_amount = min(BUFFER_SIZE, data_size - bytes_processed)
                chunk = f.read(read_amount)
                if not chunk:
                    return False, f"Unexpected end of file during verification at byte {bytes_processed}/{data_size}."

                cipher.decrypt(chunk) 
                bytes_processed += len(chunk)

            cipher.verify(tag)
            return True, "Verification successful."

    except FileNotFoundError: 
        return False, "File vanished during verification process."
    except ValueError as e: 
        return False, f"Integrity check failed: {e}" 
    except IOError as e:
         return False, f"File read error during verification: {e}"
    except Exception as e:
        print(f"CRITICAL: Unexpected error during verification of {file_path}: {e}\n{traceback.format_exc()}")
        return False, f"Unexpected server error during verification: {type(e).__name__}"


def handle_client(client_socket, addr):
    """Handles a single client connection."""
    print(f"[+] New connection from {addr}")
    conn = None 
    cursor = None
    current_file_operation_path = None

    try:
        client_socket.settimeout(SOCKET_TIMEOUT)

        command_data_bytes = client_socket.recv(BUFFER_SIZE)
        if not command_data_bytes:
            print(f"[WARNING][{addr}] Client disconnected before sending command.")
            return 
        command_data = command_data_bytes.decode().strip()
        print(f"[{addr}] Received command: {command_data}")

        parts = command_data.split(':', 3) 
        command = parts[0].upper() 

        conn = get_db_connection()
        cursor = conn.cursor()

        if command == "SEND" and len(parts) == 4:
            sender, recipient, original_filename = parts[1], parts[2], parts[3]

            if not sender or not recipient or not original_filename:
                 send_error(client_socket, addr, "Invalid SEND format: Missing sender, recipient, or filename.")
                 return

            original_filename = os.path.basename(original_filename).strip()

            if not original_filename or original_filename in ['.', '..']:
                send_error(client_socket, addr, "Invalid or disallowed original filename.")
                return

            stored_filename = f"{uuid.uuid4().hex}_{original_filename}.enc"
            current_file_operation_path = os.path.join(STORAGE_DIR, stored_filename)

            print(f"[{addr}] Preparing to receive '{original_filename}' from '{sender}' for '{recipient}'. Storing as '{stored_filename}'.")

            client_socket.sendall(b"OK_SEND")

            client_socket.settimeout(CHUNK_TIMEOUT) 
            nonce = client_socket.recv(NONCE_SIZE)
            client_socket.settimeout(SOCKET_TIMEOUT) 
            if len(nonce) != NONCE_SIZE:
                 send_error(client_socket, addr, f"Failed to receive complete nonce ({len(nonce)}/{NONCE_SIZE} bytes). Transfer aborted.")
                 
                 return
            print(f"[{addr}] Received nonce. Receiving encrypted file data and tag...")

            total_bytes_written = 0
            output_file = None
            try:
                output_file = open(current_file_operation_path, 'wb')
                output_file.write(nonce)
                total_bytes_written += len(nonce)

                while True:
                    client_socket.settimeout(CHUNK_TIMEOUT) 
                    chunk = client_socket.recv(BUFFER_SIZE)
                    client_socket.settimeout(SOCKET_TIMEOUT)

                    if not chunk:
                        print(f"[{addr}] Client finished sending stream.")
                        break 

                    output_file.write(chunk)
                    total_bytes_written += len(chunk)

                output_file.close()
                output_file = None 
                print(f"[{addr}] Finished writing {total_bytes_written} bytes to {current_file_operation_path}")

                if total_bytes_written < NONCE_SIZE + TAG_SIZE:
                     verified = False
                     verify_msg = f"Received file size ({total_bytes_written}) is too small for nonce and tag."
                     print(f"[ERROR][{addr}] {verify_msg}")
                else:

                     print(f"[{addr}] Verifying file integrity...")
                     verified, verify_msg = verify_aes_gcm(current_file_operation_path)
                     print(f"[{addr}] Verification result: {verified} - {verify_msg}")

                if verified:

                    try:
                        with db_lock:
                            cursor.execute("""
                                INSERT INTO files (sender, recipient, original_filename, stored_filename, file_size)
                                VALUES (?, ?, ?, ?, ?)
                            """, (sender, recipient, original_filename, stored_filename, total_bytes_written)) 
                            conn.commit()
                        print(f"[{addr}] Database updated for '{stored_filename}'.")
                        client_socket.sendall(b"SUCCESS: File received and verified.")
                        current_file_operation_path = None 

                    except sqlite3.Error as db_e:
                        print(f"[ERROR][{addr}] Database error after verification: {db_e}")
                        send_error(client_socket, addr, f"Server database error after file receipt: {db_e}")

                else:
                     send_error(client_socket, addr, f"File integrity check failed. {verify_msg}")
                     

            except (socket.error, IOError) as e:
 
                print(f"[ERROR][{addr}] Error during file receive/write: {e}")
                send_error(client_socket, addr, f"File receiving/writing failed on server ({type(e).__name__}).")

            except socket.timeout:
                 print(f"[ERROR][{addr}] Timeout occurred during file data reception.")
                 send_error(client_socket, addr, "Timeout receiving file data on server.")

            finally:

                if output_file and not output_file.closed:
                    output_file.close()


        elif command == "CHECK" and len(parts) == 2:
            recipient_username = parts[1]
            if not recipient_username:
                send_error(client_socket, addr, "Invalid CHECK format: Missing username.")
                return

            print(f"[{addr}] Checking inbox for '{recipient_username}'.")
            try:
                file_list = []
                
                with db_lock:
                    cursor.execute("""
                        SELECT id, sender, original_filename, timestamp
                        FROM files
                        WHERE recipient = ?
                        ORDER BY timestamp DESC
                    """, (recipient_username,))
                    
                    files_db = cursor.fetchall()

                if files_db:
                    
                    
                    response = ";".join([f"{f[0]},{f[1]},{f[2]},{f[3]}" for f in files_db])
                else:
                    response = "EMPTY"

                
                client_socket.sendall(response.encode())
                print(f"[{addr}] Sent inbox list to '{recipient_username}'. Found: {len(files_db)} items.")

            except sqlite3.Error as db_e:
                 send_error(client_socket, addr, f"Database error checking inbox: {db_e}")
            except (socket.error, BrokenPipeError) as e:
                 print(f"[ERROR][{addr}] Socket error sending inbox list: {e}")
            except Exception as e:
                 
                 print(f"[ERROR][{addr}] Unexpected server error checking inbox: {e}\n{traceback.format_exc()}")
                 send_error(client_socket, addr, f"Unexpected server error checking inbox.")


        
        elif command == "GET" and len(parts) == 3:
            requesting_user, file_id_str = parts[1], parts[2]
            print(f"[{addr}] User '{requesting_user}' requesting file ID '{file_id_str}'.")

            if not requesting_user:
                send_error(client_socket, addr, "Invalid GET format: Missing username.")
                return
            if not file_id_str.isdigit():
                 send_error(client_socket, addr, "Invalid GET format: File ID must be a number.")
                 return

            file_id = int(file_id_str)
            file_path_to_send = None 

            try:
                stored_filename = None
                file_size_db = 0 

                
                with db_lock:
                    cursor.execute("""
                        SELECT recipient, stored_filename, file_size
                        FROM files
                        WHERE id = ?
                    """, (file_id,))
                    result = cursor.fetchone()

                if result:
                    recipient_db, stored_filename, file_size_db = result

                    
                    if recipient_db != requesting_user:
                        print(f"[ACCESS DENIED][{addr}] User '{requesting_user}' tried GET for file ID {file_id} owned by '{recipient_db}'.")
                        send_error(client_socket, addr, "Access denied. You are not the recipient of this file.")
                        return

                    file_path_to_send = os.path.join(STORAGE_DIR, stored_filename)

                    
                    if not os.path.exists(file_path_to_send):
                        print(f"[ERROR][{addr}] File '{stored_filename}' (ID {file_id}) found in DB but missing from storage!")
                        send_error(client_socket, addr, "File consistency error on server. File not found in storage.")
                        
                        
                        return

                    
                    try:
                        actual_file_size = os.path.getsize(file_path_to_send)
                        print(f"[{addr}] File ID {file_id} ({stored_filename}) found for user {requesting_user}. Size: {actual_file_size} bytes.")
                        
                        if actual_file_size != file_size_db:
                            print(f"[WARNING][{addr}] File size mismatch for ID {file_id}. DB: {file_size_db}, Actual: {actual_file_size}. Using actual size.")
                            
                            

                    except OSError as stat_e:
                        print(f"[ERROR][{addr}] Could not get size of {file_path_to_send}: {stat_e}")
                        send_error(client_socket, addr, f"Server error accessing file details: {stat_e}")
                        return

                    
                    client_socket.sendall(f"FOUND:{actual_file_size}".encode())

                    
                    client_socket.settimeout(CHUNK_TIMEOUT) 
                    ack = client_socket.recv(BUFFER_SIZE)
                    client_socket.settimeout(SOCKET_TIMEOUT) 

                    if ack != b"READY":
                        print(f"[{addr}] Client not ready or sent unexpected ACK '{ack.decode() if ack else 'None'}', aborting file send for ID {file_id}.")
                        
                        return

                    
                    print(f"[{addr}] Sending file '{stored_filename}' ({actual_file_size} bytes) to '{requesting_user}'.")
                    input_file = None
                    try:
                        input_file = open(file_path_to_send, 'rb')
                        bytes_sent = 0
                        while True:
                            chunk = input_file.read(BUFFER_SIZE)
                            if not chunk:
                                break 
                            client_socket.sendall(chunk)
                            bytes_sent += len(chunk)
                        
                        print(f"[{addr}] Finished sending '{stored_filename}'. Sent {bytes_sent}/{actual_file_size} bytes.")
                        
                        
                        
                        
                        
                        
                        


                    except IOError as read_e:
                         
                         print(f"[ERROR][{addr}] Server error reading file during send: {read_e}")
                    except (socket.error, BrokenPipeError) as send_e:
                         
                         print(f"[ERROR][{addr}] Socket error sending file chunk for ID {file_id}: {send_e}")
                    finally:
                         if input_file and not input_file.closed:
                             input_file.close()

                else:
                    
                    print(f"[NOT FOUND][{addr}] File ID {file_id} not found in database.")
                    send_error(client_socket, addr, f"File ID {file_id} not found.")

            except sqlite3.Error as db_e:
                 print(f"[ERROR][{addr}] Database error retrieving file info for ID {file_id_str}: {db_e}")
                 send_error(client_socket, addr, f"Database error retrieving file info: {db_e}")
            except (socket.error, BrokenPipeError) as e:
                 
                 print(f"[ERROR][{addr}] Socket error during GET operation for ID {file_id_str}: {e}")
                 
            except Exception as e:
                print(f"[ERROR][{addr}] Unexpected error retrieving file ID {file_id_str}: {e}\n{traceback.format_exc()}")
                
                send_error(client_socket, addr, "Unexpected server error retrieving file.")

        
        else:
            invalid_cmd_msg = f"Received invalid or incomplete command: {command_data}"
            print(f"[WARNING][{addr}] {invalid_cmd_msg}")
            send_error(client_socket, addr, "Invalid command or format received.")

    
    except ConnectionResetError:
        print(f"[!] Connection reset by peer {addr}")
    except socket.timeout:
         print(f"[ERROR][{addr}] Socket timeout waiting for client action.")
         
    except (socket.error, BrokenPipeError) as e:
        
        print(f"[ERROR][{addr}] General socket error: {e}")
    except sqlite3.Error as e:
        
        print(f"[CRITICAL][{addr}] Database connection/operation error: {e}")
        
        try: send_error(client_socket, addr, "Critical server database error.")
        except: pass 
    except Exception as e:
        
        print(f"[CRITICAL][{addr}] An unexpected error occurred in handle_client: {e}\n{traceback.format_exc()}")
        
        try: send_error(client_socket, addr, "An unexpected server error occurred.")
        except: pass 

    
    finally:
        
        if conn:
            try:
                conn.close()
            except Exception as db_close_err:
                 print(f"[ERROR][{addr}] Error closing DB connection: {db_close_err}")

        
        if current_file_operation_path and os.path.exists(current_file_operation_path):
            try:
                print(f"[{addr}] Cleaning up failed/unverified file transfer: {current_file_operation_path}")
                os.remove(current_file_operation_path)
            except OSError as rm_e:
                 print(f"[ERROR][{addr}] Failed to clean up file {current_file_operation_path}: {rm_e}")

        
        print(f"[-] Connection closed for {addr}")
        try:
             client_socket.shutdown(socket.SHUT_RDWR) 
        except (socket.error, OSError):
             pass 
        finally:
             client_socket.close()


def start_server():
    """Starts the main server listening loop."""
    
    if not PYCRYPTODOME_AVAILABLE or AES_KEY is None:
        print("FATAL: PyCryptodome or AES Key not available. Server cannot start.")
        return

    try:
        initialize_database() 
    except Exception as db_init_err:
         print(f"FATAL: Database initialization failed: {db_init_err}. Server cannot start.")
         return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5) 
        print(f"[*] Server listening on {HOST}:{PORT}")
        print(f"[*] Using AES-{len(AES_KEY)*8} GCM Encryption.")
        print(f"[*] Storage Directory: {STORAGE_DIR}")
        print(f"[*] Database File: {DB_NAME}")
        print("[*] Server started. Waiting for connections...")

        while True:
            try:
                
                client_socket, addr = server_socket.accept()
                
                
                client_thread = threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True)
                client_thread.start()
            except KeyboardInterrupt:
                 
                 print("\n[*] KeyboardInterrupt received, initiating server shutdown...")
                 break 
            except Exception as e:
                
                print(f"[ERROR] Error accepting connection: {e}")
                
                time.sleep(0.1)

    except OSError as e:
        
        print(f"[FATAL] Could not bind to {HOST}:{PORT}. Error: {e}")
    except Exception as e:
         print(f"[FATAL] An unexpected error occurred during server setup: {e}\n{traceback.format_exc()}")
    finally:
        
        print("[*] Shutting down server socket.")
        server_socket.close()
        print("[*] Server stopped.")


if __name__ == "__main__":
    start_server()
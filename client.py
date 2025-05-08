# client.py
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox, scrolledtext
import socket
import os
import threading
import sqlite3
import base64 
import struct 
import uuid 

import time
import subprocess 
import mimetypes 
import sys 

import traceback 

try:
    from argon2 import PasswordHasher, exceptions as argon2_exceptions
    ARGON2_AVAILABLE = True
except ImportError:
    print("ERROR: Argon2 library not found.\nPlease install it: pip install argon2-cffi")
    messagebox.showerror("Dependency Error", "Argon2 library not found.\nPlease install it: pip install argon2-cffi")
    sys.exit(1)

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
     print("ERROR: PyCryptodome library not found.\nPlease install it: pip install pycryptodome")
     messagebox.showerror("Dependency Error", "PyCryptodome library not found.\nPlease install it: pip install pycryptodome")
     sys.exit(1)











PYGAME_AVAILABLE = False
try:
    import pygame
    pygame.init()
    pygame.font.init() 
    PYGAME_AVAILABLE = True
    print("Pygame initialized successfully.")
except ImportError:
    print("INFO: Pygame not found, mini-game will be disabled.")
except Exception as pg_err:
    print(f"WARNING: Pygame initialized with an error: {pg_err}. Mini-game might have issues.")
    





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
    messagebox.showerror("Key Error", f"Invalid AES encryption key: {e}\nPlease provide a valid URL-safe Base64 encoded 16, 24, or 32-byte key.")
    sys.exit(1)


SERVER_IP = '10.11.12.109'  
SERVER_PORT = 55555
BUFFER_SIZE = 8192 
DB_NAME = "users.db" 

TEMP_DIR = "temp_client" 
SOCKET_TIMEOUT = 60.0 
CHUNK_TIMEOUT = 20.0 


if ARGON2_AVAILABLE:
    ph = PasswordHasher()



conn_local_db = sqlite3.connect(DB_NAME)
cursor_local_db = conn_local_db.cursor()
cursor_local_db.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL -- Store hash instead of plain text
)
""")
conn_local_db.commit()



def get_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except AttributeError: 
        base_path = os.path.abspath(".")
    except Exception: 
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)














def run_mini_game(game_window):
    if not PYGAME_AVAILABLE:
        messagebox.showwarning("Game Unavailable", "Pygame is not available or failed to initialize. Cannot start game.", parent=game_window)
        game_window.destroy()
        return

    try:
        
        screen = pygame.display.set_mode((400, 300))
        pygame.display.set_caption("Mini-Game!")
        clock = pygame.time.Clock()

        white = (255, 255, 255)
        red = (255, 0, 0)
        blue = (0, 0, 255)
        score = 0
        font = pygame.font.Font(None, 30)

        x, y = 100, 100
        speed_x, speed_y = 4, 3
        size = 25
        running = True
        start_time = time.time()
        game_duration = 15 

        while running:
            elapsed_time = time.time() - start_time
            if elapsed_time > game_duration:
                running = False

            
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False
                if event.type == pygame.MOUSEBUTTONDOWN:
                    mouse_x, mouse_y = event.pos
                    if x < mouse_x < x + size and y < mouse_y < y + size:
                        score += 1
                        
                        x = (50 + (score * 17)) % (screen.get_width() - size)
                        y = (50 + (score * 23)) % (screen.get_height() - size)


            
            x += speed_x
            y += speed_y

            
            if x <= 0 or x + size >= screen.get_width(): speed_x = -speed_x
            if y <= 0 or y + size >= screen.get_height(): speed_y = -speed_y
            
            x = max(0, min(x, screen.get_width() - size))
            y = max(0, min(y, screen.get_height() - size))

            
            screen.fill(white)
            pygame.draw.rect(screen, red, (x, y, size, size))
            score_text = font.render(f"Score: {score}", True, blue)
            time_left = max(0, game_duration - elapsed_time)
            time_text = font.render(f"Time: {int(time_left)}s", True, blue)
            screen.blit(score_text, (10, 10))
            screen.blit(time_text, (screen.get_width() - 100, 10))

            pygame.display.flip()
            clock.tick(60) 

        
        
        messagebox.showinfo("Game Over", f"Your score: {score}", parent=game_window)
        game_window.destroy()

    except pygame.error as pg_err:
         print(f"Error running game: {pg_err}")
         messagebox.showerror("Game Error", f"A Pygame error occurred:\n{pg_err}", parent=game_window)
         if game_window: game_window.destroy()
    except Exception as e:
        print(f"Unexpected error running game: {e}")
        messagebox.showerror("Game Error", f"An unexpected error occurred:\n{e}", parent=game_window)
        if game_window: game_window.destroy()



class FileTransferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Transfer (AES+Argon2)")
        self.geometry("700x600") 

        self.current_user = None
        self.server_ip = SERVER_IP
        self.server_port = SERVER_PORT

        
        style = ttk.Style(self)
        style.theme_use('clam') 

        
        if not os.path.exists(TEMP_DIR):
            try:
                os.makedirs(TEMP_DIR)
                print(f"Created temporary directory: {TEMP_DIR}")
            except OSError as e:
                 messagebox.showerror("Startup Error", f"Could not create temporary directory '{TEMP_DIR}':\n{e}")
                 self.quit() 
                 return 

        
        self.main_frame = ttk.Frame(self, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        
        self.auth_frame = ttk.Frame(self.main_frame)
        ttk.Label(self.auth_frame, text="Welcome!", font=('Arial', 16)).pack(pady=10)
        ttk.Button(self.auth_frame, text="Login", command=self.login).pack(fill=tk.X, pady=5)
        ttk.Button(self.auth_frame, text="Register", command=self.register).pack(fill=tk.X, pady=5)

        
        self.app_frame = ttk.Frame(self.main_frame)
        self.welcome_label = ttk.Label(self.app_frame, text="", font=('Arial', 14))
        self.welcome_label.pack(pady=10)

        action_frame = ttk.Frame(self.app_frame)
        action_frame.pack(fill=tk.X, pady=10)
        ttk.Button(action_frame, text="Send File", command=self.prompt_send_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Check Inbox", command=self.check_inbox).pack(side=tk.LEFT, padx=5)
        
        self.progress_bar = ttk.Progressbar(action_frame, orient='horizontal', mode='determinate', length=200)
        self.progress_bar.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        ttk.Button(action_frame, text="Logout", command=self.logout).pack(side=tk.RIGHT, padx=5)
        
        if PYGAME_AVAILABLE:
             ttk.Button(action_frame, text="Mini-Game", command=self.launch_game_independent).pack(side=tk.RIGHT, padx=5)


        
        inbox_label = ttk.Label(self.app_frame, text="Your Inbox:")
        inbox_label.pack(anchor=tk.W, pady=(10, 0))
        inbox_list_frame = ttk.Frame(self.app_frame)
        inbox_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        inbox_scrollbar_y = ttk.Scrollbar(inbox_list_frame, orient=tk.VERTICAL)
        inbox_scrollbar_x = ttk.Scrollbar(inbox_list_frame, orient=tk.HORIZONTAL)
        self.inbox_list = tk.Listbox(inbox_list_frame,
                                    height=15,
                                    width=90, 
                                    yscrollcommand=inbox_scrollbar_y.set,
                                    xscrollcommand=inbox_scrollbar_x.set,
                                    activestyle='dotbox')
        inbox_scrollbar_y.config(command=self.inbox_list.yview)
        inbox_scrollbar_x.config(command=self.inbox_list.xview)

        inbox_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        inbox_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.inbox_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.inbox_list.bind("<Double-Button-1>", self.on_inbox_select)

        
        self.status_var = tk.StringVar(value="Status: Not logged in.")
        self.status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        
        self.show_auth_frame()

    def update_status(self, message):
        
        self.after(0, self.status_var.set, f"Status: {message}")

    def update_progress(self, value, maximum):
        """Updates progress bar on the main thread."""
        def _update():
            self.progress_bar['maximum'] = max(1, maximum) 
            self.progress_bar['value'] = min(value, maximum) 
        self.after(0, _update)

    def reset_progress(self):
        """Resets progress bar on the main thread."""
        self.after(0, lambda: self.progress_bar.config(value=0, maximum=100))

    
    def show_auth_frame(self):
        self.app_frame.pack_forget()
        self.auth_frame.pack(fill=tk.BOTH, expand=True)
        self.current_user = None
        self.update_status("Not logged in.")
        self.inbox_list.delete(0, tk.END)
        self.reset_progress()

    def show_app_frame(self):
        self.auth_frame.pack_forget()
        self.app_frame.pack(fill=tk.BOTH, expand=True)
        self.welcome_label.config(text=f"Welcome, {self.current_user}!")
        self.update_status(f"Logged in as {self.current_user}.")
        self.reset_progress()
        self.check_inbox() 

    def register(self):
        if not ARGON2_AVAILABLE:
             messagebox.showerror("Error", "Argon2 library is not available. Cannot register.", parent=self)
             return

        username = simpledialog.askstring("Register", "Enter Username:", parent=self)
        if not username: return
        password = simpledialog.askstring("Register", "Enter Password:", show='*', parent=self)
        if not password: return
        
        password_confirm = simpledialog.askstring("Register", "Confirm Password:", show='*', parent=self)
        if password != password_confirm:
             messagebox.showerror("Error", "Passwords do not match.", parent=self)
             return

        try:
            
            self.update_status("Hashing password...") 
            hashed_password = ph.hash(password)
            self.update_status("Registering...")
            cursor_local_db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn_local_db.commit()
            messagebox.showinfo("Success", "Registration successful! Please login.", parent=self)
            self.update_status("Registration successful.")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists.", parent=self)
            self.update_status("Registration failed: Username exists.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during registration: {e}", parent=self)
            self.update_status(f"Registration error: {e}")
        finally:
            
            self.after(3000, lambda: self.update_status(f"Logged out" if not self.current_user else f"Logged in as {self.current_user}"))


    def login(self):
        if not ARGON2_AVAILABLE:
             messagebox.showerror("Error", "Argon2 library is not available. Cannot login.", parent=self)
             return

        username = simpledialog.askstring("Login", "Enter Username:", parent=self)
        if not username: return
        password = simpledialog.askstring("Login", "Enter Password:", show='*', parent=self)
        if not password: return

        try:
            cursor_local_db.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            result = cursor_local_db.fetchone()

            if result:
                hashed_password = result[0]
                self.update_status("Verifying password...")
                
                threading.Thread(target=self._verify_password_thread, args=(hashed_password, password, username), daemon=True).start()
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.", parent=self)
                self.update_status("Login failed: Invalid credentials.")

        except Exception as e:
             messagebox.showerror("Error", f"An error occurred during login: {e}", parent=self)
             self.update_status(f"Login error: {e}")

    def _verify_password_thread(self, hashed_password, password, username):
        """Runs password verification in a thread to avoid freezing the GUI."""
        try:
            ph.verify(hashed_password, password)
            
            self.after(0, self._login_success, username)

            
            
            
            
            

        except argon2_exceptions.VerifyMismatchError:
            self.after(0, self._login_failure, "Invalid username or password.")
        except argon2_exceptions.VerificationError as verify_e: 
            self.after(0, self._login_failure, f"Password verification failed: {verify_e}")
        except Exception as e:
             self.after(0, self._login_failure, f"Unexpected error during verification: {e}")

    def _login_success(self, username):
        """Updates GUI after successful login verification."""
        self.current_user = username
        self.show_app_frame() 

    def _login_failure(self, message):
        """Updates GUI after failed login verification."""
        messagebox.showerror("Login Failed", message, parent=self)
        self.update_status(f"Login failed: {message}")

    
    
    
    
    
    
    
    
    

    def logout(self):
       self.show_auth_frame()

    
    def prompt_send_file(self):
        if not self.current_user:
            messagebox.showwarning("Not Logged In", "Please login first.", parent=self)
            return

        filepath = filedialog.askopenfilename(title="Select file to send", parent=self)
        if not filepath: return

        recipient = simpledialog.askstring("Recipient", "Enter recipient's username:", parent=self)
        if not recipient: return
        if recipient == self.current_user:
             messagebox.showwarning("Self Send", "You cannot send a file to yourself.", parent=self)
             return

        try:
             file_size = os.path.getsize(filepath)
             if file_size == 0:
                 messagebox.showwarning("Empty File", "Cannot send an empty file.", parent=self)
                 return
        except OSError as e:
             messagebox.showerror("File Error", f"Could not access file: {e}", parent=self)
             return

        self.reset_progress()
        thread = threading.Thread(target=self.send_file_thread, args=(filepath, recipient, file_size), daemon=True)
        thread.start()

        
        


    def launch_game_independent(self):
         """Launches the mini-game in a separate top-level window."""
         if not PYGAME_AVAILABLE:
             messagebox.showwarning("Game Unavailable", "Pygame is not available or failed to initialize.", parent=self)
             return

         game_window = tk.Toplevel(self)
         game_window.title("Mini-Game")
         game_window.geometry("250x100")
         game_window.resizable(False, False)
         ttk.Label(game_window, text="Click Start to play!").pack(pady=15)
         
         ttk.Button(game_window, text="Start Game", command=lambda gw=game_window: run_mini_game(gw)).pack(pady=5)


    def send_file_thread(self, filepath, recipient, file_size):
        original_filename = os.path.basename(filepath)
        self.update_status(f"Preparing to send {original_filename} ({file_size // 1024} KB)...")
        client_socket = None
        input_file = None

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(SOCKET_TIMEOUT)
            client_socket.connect((self.server_ip, self.server_port))

            
            command = f"SEND:{self.current_user}:{recipient}:{original_filename}"
            print(f"DEBUG [Client]: Sending command: {command}")
            client_socket.sendall(command.encode())

            
            client_socket.settimeout(CHUNK_TIMEOUT) 
            ack = client_socket.recv(BUFFER_SIZE).decode()
            client_socket.settimeout(SOCKET_TIMEOUT) 
            if ack != "OK_SEND":
                error_msg = f"Server refused send request or sent invalid ACK: {ack}"
                raise ConnectionAbortedError(error_msg) 

            self.update_status(f"Encrypting and sending {original_filename}...")

            
            nonce = get_random_bytes(NONCE_SIZE)
            cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)

            
            client_socket.sendall(nonce)

            
            input_file = open(filepath, 'rb')
            total_sent = 0
            self.update_progress(0, file_size) 

            while True:
                chunk = input_file.read(BUFFER_SIZE)
                if not chunk:
                    break 

                encrypted_chunk = cipher.encrypt(chunk)
                client_socket.sendall(encrypted_chunk)
                total_sent += len(chunk) 
                self.update_progress(total_sent, file_size)

            input_file.close() 
            input_file = None 

            
            tag = cipher.digest()
            if len(tag) != TAG_SIZE:
                 raise ValueError(f"Generated incorrect tag size: {len(tag)}") 
            client_socket.sendall(tag)
            print(f"DEBUG [Client]: Sent {total_sent} data bytes, {NONCE_SIZE} nonce bytes, {TAG_SIZE} tag bytes.")

            
            client_socket.shutdown(socket.SHUT_WR)
            print(f"DEBUG [Client]: Finished sending data + tag, shut down write.")

            
            self.update_status("Waiting for server verification...")
            client_socket.settimeout(SOCKET_TIMEOUT * 2) 
            response_bytes = client_socket.recv(BUFFER_SIZE)
            response = response_bytes.decode()
            print(f"DEBUG [Client]: Received confirmation: '{response}'")

            if response.startswith("SUCCESS"):
                self.update_status(f"File '{original_filename}' sent and verified successfully.")
                self.after(0, lambda: messagebox.showinfo("Success", f"File '{original_filename}' sent successfully to {recipient}.", parent=self))
                
            else:
                error_msg = response if response else "No confirmation from server."
                if response.startswith("ERROR:"): error_msg = response[len("ERROR:"):].strip()
                raise ConnectionAbortedError(f"Server error after upload: {error_msg}")

        except (ValueError, TypeError) as crypto_e: 
             err_msg = f"Encryption error: {crypto_e}"
             self.update_status(err_msg)
             self.after(0, lambda: messagebox.showerror("Encryption Error", f"Failed during encryption/tagging:\n{crypto_e}", parent=self))
        except FileNotFoundError:
             err_msg = f"Error: File '{original_filename}' not found."
             self.update_status(err_msg)
             self.after(0, lambda: messagebox.showerror("File Error", f"File not found: {filepath}", parent=self))
        except IOError as e:
            err_msg = f"File read error: {e}"
            self.update_status(err_msg)
            self.after(0, lambda: messagebox.showerror("File Error", f"Could not read file '{original_filename}':\n{e}", parent=self))
        except socket.timeout:
             err_msg = "Connection timed out during send."
             self.update_status(err_msg)
             self.after(0, lambda: messagebox.showerror("Connection Timeout", err_msg, parent=self))
        except (socket.error, ConnectionAbortedError, BrokenPipeError) as e:
            err_msg = f"Connection error: {e}"
            self.update_status(err_msg)
            self.after(0, lambda: messagebox.showerror("Connection Error", f"Could not connect or send failed:\n{e}", parent=self))
        except Exception as e:
            err_msg = f"Unexpected error during send: {e}"
            self.update_status(err_msg)
            self.after(0, lambda: messagebox.showerror("Error", f"{err_msg}\nCheck logs for details.", parent=self))
            print(f"CRITICAL SEND ERROR: {e}\n", traceback.format_exc()) 
        finally:
             if input_file and not input_file.closed:
                 input_file.close()
             if client_socket:
                 try:
                    client_socket.close()
                 except socket.error: pass 
                 print("DEBUG [Client]: Send socket closed.")
             self.reset_progress() 


    
    def check_inbox(self):
        if not self.current_user: return
        self.update_status("Checking inbox...")
        self.inbox_list.delete(0, tk.END) 
        self.inbox_list.insert(tk.END, "Refreshing...") 
        self.inbox_list.config(state=tk.DISABLED) 

        thread = threading.Thread(target=self.check_inbox_thread, daemon=True)
        thread.start()

    def check_inbox_thread(self):
        response = "" 
        client_socket = None
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(SOCKET_TIMEOUT)
            client_socket.connect((self.server_ip, self.server_port))

            command = f"CHECK:{self.current_user}"
            print(f"DEBUG [Client]: Sending command: {command}")
            client_socket.sendall(command.encode())

            
            response_bytes = b""
            client_socket.settimeout(CHUNK_TIMEOUT) 
            while True:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break 
                response_bytes += chunk
            client_socket.settimeout(SOCKET_TIMEOUT) 
            response = response_bytes.decode().strip()

            print(f"DEBUG [Client]: Received inbox response ({len(response_bytes)} bytes).")

        except socket.timeout:
             self.update_status("Error: Timeout waiting for inbox response.")
             self.after(0, lambda: messagebox.showerror("Inbox Error", "Server did not respond in time.", parent=self))
             response = "ERROR: Timeout waiting for server response." 
        except (socket.error, ConnectionRefusedError, BrokenPipeError) as e:
            self.update_status(f"Connection error checking inbox: {e}")
            self.after(0, lambda e=e: messagebox.showerror("Connection Error", f"Could not connect to server:\n{e}", parent=self))
            response = f"ERROR: Connection error - {e}"
        except Exception as e:
            self.update_status(f"Error checking inbox: {e}")
            self.after(0, lambda e=e: messagebox.showerror("Error", f"An unexpected error occurred:\n{e}", parent=self))
            response = f"ERROR: Client-side error - {e}"
        finally:
             if client_socket:
                 try:
                    client_socket.close()
                 except socket.error: pass
                 print("DEBUG [Client]: Check inbox socket closed.")
             
             self.after(0, self._update_inbox_list, response)


    def _update_inbox_list(self, response):
        """Helper function to update the listbox from the main thread."""
        self.inbox_list.config(state=tk.NORMAL) 
        self.inbox_list.delete(0, tk.END) 

        if not response:
             self.update_status("Received empty/invalid response from server.")
             self.inbox_list.insert(tk.END, "Error receiving inbox data.")
             
             

        elif response == "EMPTY":
            self.update_status("Inbox is empty.")
            self.inbox_list.insert(tk.END, "No new files.")

        elif response.startswith("ERROR:"):
             error_message = response[len("ERROR:"):].strip()
             self.update_status(f"Server error checking inbox: {error_message}")
             self.inbox_list.insert(tk.END, f"Server Error: {error_message}")
             
             

        else:
            
            files = response.split(';')
            count = 0
            malformed_count = 0
            for f_data in files:
                if not f_data: continue 
                try:
                    
                    parts = f_data.split(',', 3)
                    if len(parts) == 4:
                         file_id, sender, filename, timestamp = parts
                         if not file_id.isdigit(): raise ValueError("Invalid file ID format")
                         
                         display_text = f"ID:{file_id:<5} | From: {sender:<15} | File: {filename:<40} | Received: {timestamp}"
                         self.inbox_list.insert(tk.END, display_text)
                         count += 1
                    else:
                         raise ValueError("Incorrect number of comma-separated parts")

                except ValueError as parse_e:
                    print(f"WARNING [Client]: Skipping malformed inbox entry: '{f_data}' - Reason: {parse_e}")
                    malformed_count += 1
                    self.inbox_list.insert(tk.END, f"[Malformed Entry: {f_data[:60]}...]") 

            status_msg = f"Inbox refreshed. {count} valid file(s)."
            if malformed_count > 0:
                status_msg += f" Skipped {malformed_count} malformed entries."
                
                
            self.update_status(status_msg)


    
    def on_inbox_select(self, event):
        selected_indices = self.inbox_list.curselection()
        if not selected_indices: return
        selected_item = self.inbox_list.get(selected_indices[0])

        
        if not selected_item.strip().startswith("ID:"):
             print(f"DEBUG [Client]: Ignoring selection: {selected_item}")
             return

        try:
            
            parts = selected_item.split('|')
            file_id_part = parts[0] 
            sender_part = parts[1]  
            filename_part = parts[2]

            file_id = int(file_id_part.split(':')[1].strip())
            sender = sender_part.split(':')[1].strip()
            original_filename = filename_part.split('File:')[1].strip()

        except (IndexError, ValueError, TypeError) as e:
             messagebox.showerror("Selection Error", f"Could not parse file info from selected item:\n'{selected_item}'\nError: {e}", parent=self)
             return

        
        action = simpledialog.askstring("Action", f"File: {original_filename}\nFrom: {sender}\n\nChoose action:\n1. Download & Save\n2. View Directly (Temporary)", parent=self)

        if action == '1':
            self.prompt_download_file(file_id, original_filename)
        elif action == '2':
            self.view_file(file_id, original_filename)
        

    def prompt_download_file(self, file_id, original_filename):
        save_path = filedialog.asksaveasfilename(
            title="Save Decrypted File As...",
            initialfile=original_filename, 
            parent=self
        )
        if not save_path: return 

        self.reset_progress()
        
        thread = threading.Thread(target=self.process_downloaded_file, args=(file_id, original_filename, save_path, False), daemon=True)
        thread.start()

    def view_file(self, file_id, original_filename):
         self.reset_progress()
         
         
         temp_view_filename = f"view_{uuid.uuid4().hex}_{original_filename}"
         temp_view_path = os.path.join(TEMP_DIR, temp_view_filename)

         
         thread = threading.Thread(target=self.process_downloaded_file, args=(file_id, original_filename, temp_view_path, True), daemon=True)
         thread.start()

    def process_downloaded_file(self, file_id, original_filename, dest_path, is_viewing):
        """Handles downloading encrypted data, decrypting, verifying, and saving/opening."""
        self.update_status(f"Requesting file ID {file_id}...")
        temp_enc_path = None 
        enc_file = None      
        dec_file = None      
        total_size_from_server = 0

        try:
            
            temp_enc_path, total_size_from_server = self._get_file_from_server(file_id)
            if temp_enc_path is None:
                
                return 

            self.update_status(f"Decrypting '{original_filename}'...")
            if total_size_from_server < NONCE_SIZE + TAG_SIZE:
                raise ValueError("Downloaded file is too small to contain nonce and tag.")

            
            data_payload_size = total_size_from_server - NONCE_SIZE - TAG_SIZE
            self.update_progress(0, data_payload_size) 

            enc_file = open(temp_enc_path, 'rb')
            
            dec_file = open(dest_path, 'wb')

            
            nonce = enc_file.read(NONCE_SIZE)
            if len(nonce) != NONCE_SIZE:
                 raise IOError("Could not read full nonce from temporary encrypted file.")

            
            cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
            decrypted_bytes_processed = 0
            while decrypted_bytes_processed < data_payload_size:
                
                read_size = min(BUFFER_SIZE, data_payload_size - decrypted_bytes_processed)
                encrypted_chunk = enc_file.read(read_size)
                if not encrypted_chunk:
                    
                    raise IOError("Unexpected end of file while reading encrypted data payload.")

                
                decrypted_chunk = cipher.decrypt(encrypted_chunk)
                dec_file.write(decrypted_chunk)
                decrypted_bytes_processed += len(encrypted_chunk) 
                self.update_progress(decrypted_bytes_processed, data_payload_size)

            
            tag = enc_file.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                 raise IOError(f"Could not read full tag ({len(tag)}/{TAG_SIZE}) from temporary encrypted file.")

            
            if enc_file.read(1):
                 print(f"WARNING [Client]: Extra data found after tag in temporary encrypted file '{temp_enc_path}'.")

            
            try:
                cipher.verify(tag)
                print(f"DEBUG [Client]: AES-GCM verification successful for file ID {file_id}.")
                
                dec_file.close()
                dec_file = None 

                
                if is_viewing:
                    self.update_status(f"Opening '{original_filename}' for viewing...")
                    
                    self._open_file_externally(dest_path, original_filename)
                    
                else:
                    
                    self.update_status(f"File '{original_filename}' saved successfully.")
                    self.after(0, lambda: messagebox.showinfo("Download Complete", f"File saved successfully to:\n{dest_path}", parent=self))
                

            except ValueError as verify_error: 
                
                print(f"CRITICAL [Client]: AES-GCM verification FAILED for file ID {file_id}: {verify_error}")
                self.update_status(f"Decryption failed! File is corrupted or wrong key used.")
                self.after(0, lambda: messagebox.showerror("Decryption Error", f"Verification failed!\nThe file is corrupted, incomplete, or the encryption key is incorrect.\n({verify_error})", parent=self))
                
                if dec_file and not dec_file.closed: dec_file.close(); dec_file = None
                if os.path.exists(dest_path):
                    try: os.remove(dest_path)
                    except OSError as rm_err: print(f"Warning: Could not remove failed decryption file {dest_path}: {rm_err}")
                

        except (ValueError, IOError, MemoryError) as e:
             err_msg = f"Error processing downloaded file: {e}"
             self.update_status(err_msg)
             self.after(0, lambda: messagebox.showerror("Processing Error", f"Failed to decrypt or save file '{original_filename}':\n{e}", parent=self))
             
             if dec_file and not dec_file.closed: dec_file.close(); dec_file = None
             if os.path.exists(dest_path):
                  try: os.remove(dest_path)
                  except OSError as rm_err: print(f"Warning: Could not remove incomplete file {dest_path}: {rm_err}")
        except Exception as e:
             err_msg = f"Unexpected error processing file ID {file_id}: {e}"
             self.update_status(err_msg)
             self.after(0, lambda: messagebox.showerror("Error", f"{err_msg}\nCheck logs.", parent=self))
             print(f"CRITICAL PROCESSING ERROR: {e}\n", traceback.format_exc())
             
             if dec_file and not dec_file.closed: dec_file.close(); dec_file = None
             if os.path.exists(dest_path):
                  try: os.remove(dest_path)
                  except OSError as rm_err: print(f"Warning: Could not remove incomplete file {dest_path}: {rm_err}")
        finally:
             
             if enc_file and not enc_file.closed:
                 enc_file.close()
             if dec_file and not dec_file.closed: 
                 dec_file.close()
                 
                 if os.path.exists(dest_path):
                     try:
                         print(f"Cleaning up incomplete destination file from finally: {dest_path}")
                         os.remove(dest_path)
                     except OSError as rm_err: print(f"Warning: Could not remove incomplete file {dest_path}: {rm_err}")

             
             if temp_enc_path and os.path.exists(temp_enc_path):
                 try:
                     print(f"DEBUG [Client]: Removing temporary encrypted download: {temp_enc_path}")
                     os.remove(temp_enc_path)
                 except OSError as e:
                     print(f"Warning: Could not remove temporary encrypted file {temp_enc_path}: {e}")
             self.reset_progress()


    def _get_file_from_server(self, file_id):
        """
        Requests file from server, receives stream into a temporary file.
        Returns (temp_file_path, total_size) on success, (None, 0) on failure.
        Handles initial connection and size negotiation.
        """
        client_socket = None
        temp_enc_file = None
        
        temp_enc_path = os.path.join(TEMP_DIR, f"download_{uuid.uuid4().hex}.enc")
        total_received = 0
        expected_size = 0

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(SOCKET_TIMEOUT)
            client_socket.connect((self.server_ip, self.server_port))

            command = f"GET:{self.current_user}:{file_id}"
            print(f"DEBUG [Client]: Sending command: {command}")
            client_socket.sendall(command.encode())

            
            self.update_status(f"Waiting for server response for file ID {file_id}...")
            client_socket.settimeout(CHUNK_TIMEOUT) 
            response = client_socket.recv(BUFFER_SIZE).decode()
            client_socket.settimeout(SOCKET_TIMEOUT) 
            print(f"DEBUG [Client]: Received initial GET response: '{response}'")

            if response.startswith("FOUND:"):
                try:
                    
                    expected_size = int(response.split(':', 1)[1])
                    print(f"DEBUG [Client]: Server reports file size: {expected_size} bytes.")
                    if expected_size <= NONCE_SIZE + TAG_SIZE: 
                         raise ValueError(f"Server reported invalid or too small file size ({expected_size}).")
                except (IndexError, ValueError) as size_e:
                     error_msg = f"Server sent invalid size information: {response} ({size_e})"
                     raise ConnectionAbortedError(error_msg)

                
                self.update_status(f"Downloading file (approx. {expected_size // 1024} KB)...")
                client_socket.sendall(b"READY")
                self.update_progress(0, expected_size) 

                
                temp_enc_file = open(temp_enc_path, 'wb')
                while total_received < expected_size:
                    try:
                        client_socket.settimeout(CHUNK_TIMEOUT) 
                        
                        bytes_to_read = min(BUFFER_SIZE, expected_size - total_received)
                        chunk = client_socket.recv(bytes_to_read)
                        client_socket.settimeout(SOCKET_TIMEOUT) 

                        if not chunk:
                            
                            raise socket.error(f"Server disconnected during transfer. Received {total_received}/{expected_size} bytes.")

                        temp_enc_file.write(chunk)
                        total_received += len(chunk)
                        self.update_progress(total_received, expected_size)

                    except socket.timeout:
                        
                        raise socket.timeout(f"Timeout receiving file data chunk for ID {file_id}.")

                
                temp_enc_file.close() 
                temp_enc_file = None 
                print(f"DEBUG [Client]: Received {total_received} bytes into {temp_enc_path}")

                
                if total_received != expected_size:
                    
                    print(f"WARNING [Client]: Received size ({total_received}) differs from server reported size ({expected_size}). Download may be corrupt.")
                    

                self.update_status(f"Download complete ({total_received // 1024} KB). Preparing decryption...")
                return temp_enc_path, total_received 

            else: 
                error_msg = response if response else "Unknown error from server."
                if response.startswith("ERROR:"): error_msg = response[len("ERROR:"):].strip()
                raise ConnectionAbortedError(f"Server error getting file ID {file_id}: {error_msg}")

        except socket.timeout as e:
             err_msg = f"Connection timed out requesting file ID {file_id}. {e}"
             self.update_status(err_msg)
             self.after(0, lambda: messagebox.showerror("Connection Timeout", err_msg, parent=self))
             return None, 0
        except (socket.error, ConnectionAbortedError, ConnectionRefusedError, BrokenPipeError) as e:
            err_msg = f"Connection error getting file: {e}"
            self.update_status(err_msg)
            self.after(0, lambda: messagebox.showerror("Connection Error", f"{err_msg}", parent=self))
            return None, 0
        except (IOError, ValueError) as e: 
            err_msg = f"Local file/data error during download: {e}"
            self.update_status(err_msg)
            self.after(0, lambda: messagebox.showerror("Local Error", err_msg, parent=self))
            return None, 0
        except Exception as e:
            err_msg = f"Unexpected error receiving file: {e}"
            self.update_status(err_msg)
            self.after(0, lambda: messagebox.showerror("Error", f"{err_msg}\nCheck logs.", parent=self))
            print(f"CRITICAL RECEIVE ERROR: {e}\n", traceback.format_exc())
            return None, 0
        finally:
             
             if temp_enc_file and not temp_enc_file.closed:
                 temp_enc_file.close()
             
             if temp_enc_path and os.path.exists(temp_enc_path) and total_received != expected_size:
                 try:
                     print(f"Cleaning up incomplete/failed download: {temp_enc_path}")
                     os.remove(temp_enc_path)
                 except OSError as rm_err: print(f"Warning: Could not remove failed download file {temp_enc_path}: {rm_err}")
             if client_socket:
                 try:
                    client_socket.close()
                 except socket.error: pass
                 print(f"DEBUG [Client]: Get file socket closed for ID {file_id}.")
             

    def _open_file_externally(self, file_path, original_filename):
         """Attempts to open the decrypted temporary file with the default app."""
         self.update_status(f"Attempting to open '{original_filename}'...")
         try:
             opened_successfully = False
             if sys.platform == "win32":
                 os.startfile(file_path) 
                 opened_successfully = True
             elif sys.platform == "darwin": 
                 subprocess.run(['open', file_path], check=True) 
                 opened_successfully = True
             else: 
                 subprocess.run(['xdg-open', file_path], check=True) 
                 opened_successfully = True

             if opened_successfully:
                  
                  self.update_status(f"Viewing '{original_filename}'. Temp file: ...{os.path.basename(file_path)}")
                  print(f"INFO: Opened temporary file '{file_path}' for viewing.")
                  
                  
                  

         except FileNotFoundError:
              err_msg = f"No default application found for '{original_filename}'."
              self.update_status(err_msg)
              self.after(0, lambda: messagebox.showerror("View Error", f"{err_msg}\nTemporary file saved at:\n{file_path}", parent=self))
         except subprocess.CalledProcessError as open_e: 
              err_msg = f"Application error opening file: {open_e}"
              self.update_status(err_msg)
              self.after(0, lambda: messagebox.showerror("View Error", f"{err_msg}\n\nTemporary file saved at:\n{file_path}", parent=self))
         except Exception as open_e: 
             err_msg = f"Could not open file with default application: {open_e}"
             self.update_status(err_msg)
             self.after(0, lambda: messagebox.showerror("View Error", f"{err_msg}\n\nTemporary file saved at:\n{file_path}", parent=self))



def main():
    
    if not ARGON2_AVAILABLE or not PYCRYPTODOME_AVAILABLE or AES_KEY is None:
         print("ERROR: Core dependencies (Argon2, PyCryptodome) or Key are missing/invalid. Exiting.")
         
         return 

    app = FileTransferApp()
    
    def on_closing():
        print("Window closed by user.")
        
        
        app.quit() 
        app.destroy() 

    app.protocol("WM_DELETE_WINDOW", on_closing)

    try:
        app.mainloop()
    except KeyboardInterrupt:
        print("Application interrupted by user (Ctrl+C).")
        

    finally:
        
        print("Application shutting down...")

        
        if 'conn_local_db' in globals() and conn_local_db:
            try:
                conn_local_db.close()
                print("Local user database connection closed.")
            except Exception as db_close_err:
                print(f"Error closing local DB: {db_close_err}")

        
        print(f"Attempting to clean up temporary directory: {TEMP_DIR}")
        items_removed = 0
        items_kept = 0
        try:
            if os.path.exists(TEMP_DIR):
                for filename in os.listdir(TEMP_DIR):
                    
                    if filename.startswith("download_") or filename.startswith("view_"):
                        file_path = os.path.join(TEMP_DIR, filename)
                        try:
                            print(f"Removing temp file: {file_path}")
                            os.remove(file_path)
                            items_removed += 1
                        except PermissionError:
                             print(f"Could not remove temp file {file_path}: Permission denied (File might still be open by viewer?)")
                             items_kept += 1
                        except Exception as e:
                            print(f"Could not remove temp file {file_path}: {e}")
                            items_kept += 1
        except Exception as e:
            print(f"Could not fully clean up temp directory {TEMP_DIR}: {e}")
        finally:
            print(f"Temp cleanup finished. Removed: {items_removed}, Kept/Failed: {items_kept}")

        
        if PYGAME_AVAILABLE:
            try:
                pygame.quit()
                print("Pygame quit successfully.")
            except Exception as pqe:
                print(f"Error quitting Pygame: {pqe}")


if __name__ == "__main__":
    main()
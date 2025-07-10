import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.fernet import Fernet
import hashlib

class RansomwareSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Educational Ransomware Simulator")
        self.root.geometry("600x450")
        self.root.resizable(False, False)
        
        # Safety disclaimer
        self.show_disclaimer()
        
        # Encryption key
        self.key = None
        self.key_file = "simulator_key.key"
        
        # UI Setup
        self.setup_ui()
        
    def show_disclaimer(self):
        disclaimer = """
        WARNING: EDUCATIONAL USE ONLY
        
        This is a simulated ransomware demonstration tool designed 
        for cybersecurity education purposes only.
        
        DO NOT use this tool on any system without explicit permission.
        Unauthorized use may be illegal and unethical.
        
        By continuing, you acknowledge this is for educational purposes
        and you have proper authorization to run this simulation.
        """
        messagebox.showwarning("Disclaimer", disclaimer.strip())
    
    def setup_ui(self):
        # Style configuration
        style = ttk.Style()
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        style.configure('TButton', font=('Arial', 10))
        style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = ttk.Label(main_frame, text="Ransomware Simulation Tool", style='Header.TLabel')
        header.pack(pady=(0, 20))
        
        # Warning label
        warning = ttk.Label(main_frame, 
                          text="This tool demonstrates how ransomware works for educational purposes only.",
                          wraplength=550,
                          justify=tk.CENTER)
        warning.pack(pady=(0, 20))
        
        # Operation frame
        op_frame = ttk.Frame(main_frame)
        op_frame.pack(fill=tk.X, pady=10)
        
        # Select directory button
        self.dir_path = tk.StringVar()
        dir_btn = ttk.Button(op_frame, text="Select Target Folder", command=self.select_directory)
        dir_btn.pack(side=tk.LEFT, padx=5)
        
        dir_label = ttk.Label(op_frame, textvariable=self.dir_path)
        dir_label.pack(side=tk.LEFT, padx=5)
        
        # Key frame
        key_frame = ttk.Frame(main_frame)
        key_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(key_frame, text="Encryption Key:").pack(side=tk.LEFT)
        self.key_entry = ttk.Entry(key_frame, width=50)
        self.key_entry.pack(side=tk.LEFT, padx=5)
        
        # Buttons frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        
        encrypt_btn = ttk.Button(btn_frame, text="Simulate Encryption", command=self.encrypt_files)
        encrypt_btn.pack(side=tk.LEFT, padx=10)
        
        decrypt_btn = ttk.Button(btn_frame, text="Simulate Decryption", command=self.decrypt_files)
        decrypt_btn.pack(side=tk.LEFT, padx=10)
        
        # Log frame
        log_frame = ttk.Frame(main_frame)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(log_frame, text="Activity Log:").pack(anchor=tk.W)
        
        self.log_text = tk.Text(log_frame, height=8, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        
        # Footer
        footer = ttk.Label(main_frame, 
                          text="FOR EDUCATIONAL USE ONLY | DO NOT USE MALICIOUSLY",
                          font=('Arial', 8),
                          foreground='red')
        footer.pack(pady=(10, 0))
    
    def select_directory(self):
        directory = filedialog.askdirectory(title="Select Folder for Simulation")
        if directory:
            self.dir_path.set(directory)
            self.log(f"Selected directory: {directory}")
    
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def generate_key(self):
        if not os.path.exists(self.key_file):
            self.key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(self.key)
            self.log("Generated new encryption key")
        else:
            with open(self.key_file, "rb") as key_file:
                self.key = key_file.read()
            self.log("Loaded existing encryption key")
        
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, self.key.decode())
    
    def encrypt_files(self):
        if not self.dir_path.get():
            messagebox.showerror("Error", "Please select a directory first")
            return
            
        try:
            if not self.key:
                self.generate_key()
            
            fernet = Fernet(self.key)
            target_dir = self.dir_path.get()
            
            self.log(f"\nStarting encryption simulation on: {target_dir}")
            
            # Create a simulated ransom note
            with open(os.path.join(target_dir, "SIMULATED_RANSOM_NOTE.txt"), "w") as note:
                note.write("""SIMULATED RANSOM NOTE (FOR EDUCATION ONLY)

Your files have been encrypted in this simulated ransomware demonstration.

This is part of a cybersecurity education exercise. No actual ransomware 
has been installed on your system. 

To decrypt these files, use the decryption function in the simulator tool
with the following key:

{}
""".format(self.key.decode()))
            
            # Encrypt files in the directory
            processed_files = 0
            for filename in os.listdir(target_dir):
                filepath = os.path.join(target_dir, filename)
                
                # Skip directories and our own files
                if (os.path.isdir(filepath) or 
                    filename == "SIMULATED_RANSOM_NOTE.txt" or 
                    filename == self.key_file):
                    continue
                
                try:
                    with open(filepath, "rb") as file:
                        original_data = file.read()
                    
                    encrypted_data = fernet.encrypt(original_data)
                    
                    with open(filepath, "wb") as file:
                        file.write(encrypted_data)
                    
                    processed_files += 1
                    self.log(f"Encrypted: {filename}")
                    
                except Exception as e:
                    self.log(f"Error processing {filename}: {str(e)}")
            
            self.log(f"Encryption simulation complete. {processed_files} files processed.")
            messagebox.showinfo("Simulation Complete", 
                              f"Simulated encryption completed on {processed_files} files.\n"
                              "A simulated ransom note has been created.")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.log(f"Error: {str(e)}")
    
    def decrypt_files(self):
        if not self.dir_path.get():
            messagebox.showerror("Error", "Please select a directory first")
            return
            
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Please enter the encryption key")
            return
            
        try:
            fernet = Fernet(key.encode())
            target_dir = self.dir_path.get()
            
            self.log(f"\nStarting decryption simulation on: {target_dir}")
            
            # Decrypt files in the directory
            processed_files = 0
            for filename in os.listdir(target_dir):
                filepath = os.path.join(target_dir, filename)
                
                # Skip directories and our own files
                if (os.path.isdir(filepath) or 
                    filename == "SIMULATED_RANSOM_NOTE.txt" or 
                    filename == self.key_file):
                    continue
                
                try:
                    with open(filepath, "rb") as file:
                        encrypted_data = file.read()
                    
                    decrypted_data = fernet.decrypt(encrypted_data)
                    
                    with open(filepath, "wb") as file:
                        file.write(decrypted_data)
                    
                    processed_files += 1
                    self.log(f"Decrypted: {filename}")
                    
                except Exception as e:
                    self.log(f"Error processing {filename}: {str(e)}")
            
            # Remove the simulated ransom note
            ransom_note = os.path.join(target_dir, "SIMULATED_RANSOM_NOTE.txt")
            if os.path.exists(ransom_note):
                os.remove(ransom_note)
                self.log("Removed simulated ransom note")
            
            self.log(f"Decryption simulation complete. {processed_files} files processed.")
            messagebox.showinfo("Simulation Complete", 
                              f"Simulated decryption completed on {processed_files} files.")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.log(f"Error: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = RansomwareSimulator(root)
    root.mainloop()

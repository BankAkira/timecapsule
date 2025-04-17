import os
import zipfile
import datetime
import time
import base64
import json
import getpass
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class TimeCapsule:
    def __init__(self, capsule_name="time_capsule"):
        """Initialize the time capsule with a name."""
        self.capsule_name = capsule_name
        self.items = []
        self.unlock_date = None
        self.temp_dir = "temp_capsule_files"
        
        # Create temp directory if it doesn't exist
        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)
    
    def set_unlock_date(self, year, month, day):
        """Set the date when the time capsule can be unlocked."""
        self.unlock_date = datetime.datetime(year, month, day)
        if self.unlock_date < datetime.datetime.now():
            raise ValueError("Unlock date must be in the future!")
        return self.unlock_date
    
    def add_text(self, text_content, filename=None):
        """Add text content to the time capsule."""
        if filename is None:
            filename = f"note_{len(self.items) + 1}.txt"
        
        file_path = os.path.join(self.temp_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(text_content)
        
        self.items.append({
            "type": "text",
            "filename": filename,
            "date_added": datetime.datetime.now().isoformat()
        })
        
        print(f"Added text as '{filename}'")
        return filename
    
    def add_file(self, file_path):
        """Add any file to the time capsule."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        filename = os.path.basename(file_path)
        destination = os.path.join(self.temp_dir, filename)
        
        # Copy file to temp directory
        with open(file_path, 'rb') as src_file:
            with open(destination, 'wb') as dst_file:
                dst_file.write(src_file.read())
        
        self.items.append({
            "type": "file",
            "filename": filename,
            "original_path": file_path,
            "date_added": datetime.datetime.now().isoformat()
        })
        
        print(f"Added file: {filename}")
        return filename
    
    def create_key_from_password(self, password, salt=None):
        """Generate an encryption key from a password."""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def seal_capsule(self, password):
        """Create and encrypt the time capsule."""
        if not self.unlock_date:
            raise ValueError("Unlock date must be set before sealing the capsule")
        
        if not self.items:
            raise ValueError("Time capsule is empty. Add some items first.")
        
        # Create metadata
        metadata = {
            "name": self.capsule_name,
            "unlock_date": self.unlock_date.isoformat(),
            "items": self.items,
            "creation_date": datetime.datetime.now().isoformat()
        }
        
        # Save metadata to temp directory
        metadata_path = os.path.join(self.temp_dir, "metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Create zip file
        zip_path = f"{self.capsule_name}.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(self.temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.temp_dir)
                    zipf.write(file_path, arcname)
        
        # Generate key from password
        key, salt = self.create_key_from_password(password)
        fernet = Fernet(key)
        
        # Encrypt the zip file
        with open(zip_path, 'rb') as f:
            encrypted_data = fernet.encrypt(f.read())
        
        # Create final sealed capsule
        sealed_path = f"{self.capsule_name}_sealed.tc"
        with open(sealed_path, 'wb') as f:
            # Store salt and unlock date at the beginning for easy access during unlock
            unlock_timestamp = int(self.unlock_date.timestamp())
            f.write(unlock_timestamp.to_bytes(8, byteorder='big'))
            f.write(salt)
            # Store the encrypted data
            f.write(encrypted_data)
        
        # Clean up
        os.remove(zip_path)
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        os.rmdir(self.temp_dir)
        
        print(f"Time capsule sealed successfully: {sealed_path}")
        print(f"This capsule will unlock on {self.unlock_date.strftime('%B %d, %Y')}")
        print("IMPORTANT: Remember your password! It cannot be recovered.")
        
        return sealed_path
    
    @staticmethod
    def unlock_capsule(capsule_path, password):
        """Try to unlock a time capsule."""
        if not os.path.exists(capsule_path):
            raise FileNotFoundError(f"Capsule not found: {capsule_path}")
        
        # Read the capsule file
        with open(capsule_path, 'rb') as f:
            # First 8 bytes are the unlock timestamp
            unlock_bytes = f.read(8)
            unlock_timestamp = int.from_bytes(unlock_bytes, byteorder='big')
            
            # Next 16 bytes are the salt
            salt = f.read(16)
            
            # Rest is the encrypted data
            encrypted_data = f.read()
        
        # Check if it's time to unlock
        current_time = datetime.datetime.now().timestamp()
        unlock_date = datetime.datetime.fromtimestamp(unlock_timestamp)
        
        if current_time < unlock_timestamp:
            days_remaining = (unlock_date - datetime.datetime.now()).days
            print(f"This capsule cannot be opened yet!")
            print(f"Unlock date: {unlock_date.strftime('%B %d, %Y')}")
            print(f"Time remaining: {days_remaining} days")
            return False
        
        # Generate key from password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        
        # Create extract directory
        capsule_name = os.path.basename(capsule_path).replace('_sealed.tc', '')
        extract_dir = f"{capsule_name}_opened"
        if not os.path.exists(extract_dir):
            os.makedirs(extract_dir)
        
        try:
            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Save the decrypted zip
            temp_zip = os.path.join(extract_dir, "temp.zip")
            with open(temp_zip, 'wb') as f:
                f.write(decrypted_data)
            
            # Extract the zip
            with zipfile.ZipFile(temp_zip, 'r') as zipf:
                zipf.extractall(extract_dir)
            
            # Clean up
            os.remove(temp_zip)
            
            # Read metadata
            metadata_path = os.path.join(extract_dir, "metadata.json")
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            print(f"Time capsule '{metadata['name']}' opened successfully!")
            print(f"Created on: {metadata['creation_date']}")
            print(f"Contents extracted to: {os.path.abspath(extract_dir)}")
            print(f"Items in capsule: {len(metadata['items'])}")
            
            return True
            
        except Exception as e:
            print(f"Failed to unlock capsule: {str(e)}")
            print("This could be due to an incorrect password.")
            return False


def create_time_capsule():
    """Interactive function to create a time capsule."""
    print("\n===== TIME CAPSULE CREATOR =====")
    name = input("Name your time capsule: ")
    capsule = TimeCapsule(name)
    
    # Set unlock date
    print("\nWhen should this capsule unlock?")
    year = int(input("Year: "))
    month = int(input("Month (1-12): "))
    day = int(input("Day (1-31): "))
    
    try:
        unlock_date = capsule.set_unlock_date(year, month, day)
        print(f"Unlock date set to: {unlock_date.strftime('%B %d, %Y')}")
    except ValueError as e:
        print(f"Error: {str(e)}")
        return
    
    # Add items
    while True:
        print("\nAdd items to your time capsule:")
        print("1. Add text note")
        print("2. Add file")
        print("3. Seal capsule")
        print("4. Cancel")
        
        choice = input("Choice: ")
        
        if choice == "1":
            filename = input("Filename (leave blank for default): ")
            print("Enter your text (type 'END' on a new line to finish):")
            lines = []
            while True:
                line = input()
                if line == "END":
                    break
                lines.append(line)
            text_content = "\n".join(lines)
            
            if filename:
                capsule.add_text(text_content, filename)
            else:
                capsule.add_text(text_content)
                
        elif choice == "2":
            file_path = input("Enter path to file: ")
            try:
                capsule.add_file(file_path)
            except FileNotFoundError:
                print("File not found. Please check the path and try again.")
                
        elif choice == "3":
            if not capsule.items:
                print("Your time capsule is empty! Add some items first.")
                continue
                
            print("\nYou're about to seal your time capsule with these items:")
            for i, item in enumerate(capsule.items, 1):
                print(f"{i}. {item['filename']} ({item['type']})")
            
            confirm = input("\nProceed with sealing? (y/n): ")
            if confirm.lower() != 'y':
                continue
                
            print("\nSet a password to encrypt your time capsule.")
            print("IMPORTANT: This password cannot be recovered. If you forget it, you won't be able to open the capsule.")
            
            while True:
                password = getpass.getpass("Password: ")
                confirm_password = getpass.getpass("Confirm password: ")
                
                if password != confirm_password:
                    print("Passwords don't match. Try again.")
                    continue
                
                if len(password) < 8:
                    print("Password should be at least 8 characters long.")
                    continue
                    
                break
            
            capsule_path = capsule.seal_capsule(password)
            print(f"\nTime capsule created: {os.path.abspath(capsule_path)}")
            return
            
        elif choice == "4":
            print("Time capsule creation cancelled.")
            return
            
        else:
            print("Invalid choice. Please try again.")


def open_time_capsule():
    """Interactive function to try to open a time capsule."""
    print("\n===== TIME CAPSULE OPENER =====")
    
    capsule_path = input("Enter path to time capsule file (.tc): ")
    if not os.path.exists(capsule_path):
        print(f"File not found: {capsule_path}")
        return
    
    password = getpass.getpass("Enter password: ")
    
    TimeCapsule.unlock_capsule(capsule_path, password)


def main():
    """Main function to provide a simple CLI for the time capsule."""
    while True:
        print("\n===== TIME CAPSULE =====")
        print("1. Create a new time capsule")
        print("2. Try to open a time capsule")
        print("3. Exit")
        
        choice = input("Choice: ")
        
        if choice == "1":
            create_time_capsule()
        elif choice == "2":
            open_time_capsule()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
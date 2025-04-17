# timecapsule
# Digital Time Capsule

A Python-based application that creates encrypted time capsules that remain locked until a specified future date.

## Overview

The Digital Time Capsule allows you to preserve digital content (text notes, images, documents, and any other files) in an encrypted format that cannot be accessed until a predetermined date. Each time capsule is secured with password-based encryption, ensuring that your memories and messages remain private until the intended time of opening.

![Time Capsule Concept](https://www.mermaidchart.com/raw/d6b74f83-55d3-4a8c-9346-114bedc8a9e2?theme=light&version=v0.1&format=svg)

## Features

- **Time-Based Locking**: Set a specific future date when the capsule can be opened
- **Password Protection**: All capsules are secured with strong encryption
- **Content Flexibility**: Add text notes and any type of file to your capsule
- **User-Friendly Interface**: Simple command-line interface for creating and opening capsules
- **Secure File Format**: Custom `.tc` format that verifies temporal validity before decryption

## Requirements

- Python 3.6+
- Required packages:
  - cryptography

## Installation

1. Clone this repository or download the script:
   ```bash
   git clone https://github.com/BankAkira/timecapsule
   cd digital-time-capsule
   ```

2. Install the required dependencies:
   ```bash
   pip install cryptography
   ```

## Usage

Run the script to start the application:

```bash
python time_capsule.py
```

### Creating a New Time Capsule

1. Select option `1` from the main menu
2. Enter a name for your time capsule
3. Set the unlock date (year, month, day)
4. Add content to your capsule:
   - Text notes: Enter your message or memories
   - Files: Specify file paths to include photos, documents, etc.
5. When finished adding items, select "Seal capsule"
6. Create a strong password (you'll need this to open the capsule!)
7. Your sealed time capsule will be created as `[name]_sealed.tc`

### Opening a Time Capsule

1. Select option `2` from the main menu
2. Enter the path to your `.tc` file
3. Enter your password
4. The system will check if the unlock date has passed:
   - If it's too early, you'll see the remaining time
   - If the date has passed and the password is correct, contents will be extracted

## Technical Details

- **Encryption**: Uses PBKDF2 with SHA-256 for key derivation and Fernet symmetric encryption (AES-128 in CBC mode)
- **File Format**: Custom `.tc` format that stores:
  - Unlock timestamp (8 bytes)
  - Salt for password-based key derivation (16 bytes)
  - Encrypted data (remaining bytes)
- **Storage**: All capsule contents are bundled into a zip archive before encryption

## Security Considerations

- **Password Security**: Choose a strong, unique password you can remember. There is no password recovery option!
- **Safe Storage**: Keep your `.tc` files backed up in multiple locations to prevent loss
- **System Clock**: The unlock mechanism relies on your system's date/time. Manipulating your system clock may allow premature access.

## Example Scenarios

- Create a message for your future self to read on a significant birthday
- Prepare a time capsule for your children to open when they reach a certain age
- Store predictions or goals to be revealed on a future date
- Archive important documents that should remain sealed for a specific period

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by traditional time capsules and the human desire to preserve moments for the future
- Built using Python's cryptography library for secure encryption

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Contact

If you have any questions or suggestions, please open an issue or contact the maintainer.

---

Remember: The best time capsules contain items that will be meaningful when opened in the future. Consider what future-you or future-others might appreciate discovering!
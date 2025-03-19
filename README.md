# File Encryptor

A powerful Rust-based command-line utility for secure file and directory encryption.

## Features

- **Strong Encryption**: Uses industry-standard AES-256 encryption
- **File and Directory Support**: Encrypt individual files or entire directory structures
- **Large File Handling**: Memory-efficient streaming approach for large files
- **Directory Recursion**: Option to include subdirectories in encryption/decryption
- **Progress Tracking**: Real-time progress display with time estimates
- **Secure Key Derivation**: Password-based key generation with salt and multiple iterations
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation

### From Source

1. Make sure you have Rust and Cargo installed. If not, install from [rustup.rs](https://rustup.rs/)
2. Clone this repository:
   ```
   git clone https://github.com/vjpovlitz/rustFile-FolderEncrypter.git
   cd rustFile-FolderEncrypter
   ```
3. Build the release version:
   ```
   cargo build --release
   ```
4. The executable will be located at `target/release/file_encryptor`

## Usage

### Encrypting a File

```bash
./target/release/file_encryptor encrypt -i path/to/file.txt -p "your_secure_password"
```

This creates `path/to/file.txt.encrypted`

### Decrypting a File

```bash
./target/release/file_encryptor decrypt -i path/to/file.txt.encrypted -p "your_secure_password"
```

This creates `path/to/file.txt.encrypted.decrypted`

### Encrypting a Directory

```bash
./target/release/file_encryptor encrypt-dir -i path/to/directory -p "your_secure_password" -r
```

The `-r` flag enables recursive processing of subdirectories.
This creates a new directory `path/to/directory_encrypted` with all files encrypted.

### Decrypting a Directory

```bash
./target/release/file_encryptor decrypt-dir -i path/to/directory_encrypted -p "your_secure_password" -r
```

This creates a new directory `path/to/directory_encrypted_decrypted` with all files decrypted.

## Command-Line Options

### Global Options

- `-p, --password <PASSWORD>`: Password for encryption/decryption

### File Encryption Options

- `-i, --input <INPUT>`: Path to the input file
- `-o, --output <OUTPUT>`: Optional path for the output file

### Directory Encryption Options

- `-i, --input <INPUT>`: Path to the input directory
- `-o, --output <OUTPUT>`: Optional path for the output directory
- `-r, --recursive`: Process subdirectories recursively

## How It Works

1. **File Encryption**:
   - Generates a random salt and initialization vector (IV)
   - Derives an encryption key from your password using multiple hash iterations
   - Encrypts the file data using AES-256
   - Stores the salt, IV, and encrypted data in Base64 format

2. **Directory Encryption**:
   - Creates a corresponding directory structure for the output
   - Encrypts each file individually
   - Maintains the directory structure

3. **Large File Handling**:
   - Files over 10MB use a streaming encryption approach
   - Processes the file in 1MB chunks to minimize memory usage

## Security Considerations

- **Password Strength**: Choose a strong, unique password
- **Password Storage**: This tool does not store your password anywhere
- **Encryption Algorithm**: Uses AES-256, a widely trusted encryption standard
- **Implementation**: Relies on well-tested Rust cryptography libraries

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [RustCrypto](https://github.com/RustCrypto) team for their excellent cryptography libraries
- [Clap](https://github.com/clap-rs/clap) for the command-line argument parsing 
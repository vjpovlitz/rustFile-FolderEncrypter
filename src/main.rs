// File Encryptor - A Rust-based encryption utility
// =======================================================
// This program provides secure file and directory encryption using AES-256.
// It supports both individual file operations and recursive directory processing.
//
// Key features:
// - AES-256 encryption for strong security
// - Password-based key derivation with salt for protection against rainbow table attacks
// - Support for large files via streaming encryption/decryption
// - Directory encryption with optional recursive processing
// - Progress tracking with time estimates
//
// Author: Your Name
// License: MIT

// Import required libraries
use std::fs;  // For file system operations
use std::path::PathBuf;  // For handling file paths
use anyhow::{Context, Result};  // For improved error handling
use clap::{Parser, Subcommand};  // For command-line argument parsing

// Import our custom modules
mod crypto;       // Core encryption/decryption logic
mod streaming;    // Large file handling via streaming
mod progress;     // Progress tracking and reporting

/// A simple file encryption and decryption tool
/// This struct represents the main command-line interface
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // Define that our CLI will have subcommands (encrypt/decrypt)
    #[command(subcommand)]
    command: Commands,
}

/// The subcommands our application supports
/// Each subcommand has its own set of arguments
#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    /// This command reads a plaintext file and produces an encrypted version
    Encrypt {
        /// The file to encrypt - this is the source file
        #[arg(short, long)]
        input: PathBuf,
        
        /// The output file path - where the encrypted file will be saved
        /// This is optional; if not provided, we'll add .encrypted extension
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// The password to use for encryption
        /// This will be used to derive the encryption key
        /// Choose a strong password for better security
        #[arg(short, long)]
        password: String,
    },
    
    /// Decrypt a file
    /// This command reads an encrypted file and produces the original plaintext version
    Decrypt {
        /// The file to decrypt - this should be a previously encrypted file
        #[arg(short, long)]
        input: PathBuf,
        
        /// The output file path - where the decrypted file will be saved
        /// This is optional; if not provided, we'll add .decrypted extension
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// The password to use for decryption
        /// Must match the password used for encryption
        #[arg(short, long)]
        password: String,
    },
    
    /// Encrypt an entire directory
    /// This command encrypts all files in a directory, maintaining the directory structure
    EncryptDir {
        /// The directory to encrypt - this is the source directory
        #[arg(short, long)]
        input: PathBuf,
        
        /// The output directory - where the encrypted files will be saved
        /// This is optional; if not provided, we'll create a new directory with .encrypted suffix
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// The password to use for encryption
        /// This will be used to derive the encryption key for all files
        #[arg(short, long)]
        password: String,
        
        /// Whether to include subdirectories in the encryption process
        /// If true, will recursively process all subdirectories
        #[arg(short, long, default_value = "false")]
        recursive: bool,
    },
    
    /// Decrypt an entire directory
    /// This command decrypts all encrypted files in a directory, reconstructing the original structure
    DecryptDir {
        /// The directory to decrypt - this should contain previously encrypted files
        #[arg(short, long)]
        input: PathBuf,
        
        /// The output directory - where the decrypted files will be saved
        /// This is optional; if not provided, we'll create a new directory with .decrypted suffix
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// The password to use for decryption
        /// Must match the password used for encryption
        #[arg(short, long)]
        password: String,
        
        /// Whether to include subdirectories in the decryption process
        /// If true, will recursively process all subdirectories
        #[arg(short, long, default_value = "false")]
        recursive: bool,
    },
}

/// Main function - entry point of our application
/// Parses command-line arguments and dispatches to the appropriate handler
fn main() -> Result<()> {
    // Parse command-line arguments into our Cli struct
    let cli = Cli::parse();

    // Match on the subcommand to determine what action to take
    match &cli.command {
        // Handle the encrypt command - for single file encryption
        Commands::Encrypt { input, output, password } => {
            // Determine the output path: either use the provided path
            // or create one by adding .encrypted extension to the input path
            let output_path = output.clone().unwrap_or_else(|| {
                let mut path = input.clone();
                path.set_extension("encrypted");
                path
            });
            
            // Call our encryption function
            encrypt_file(input, &output_path, password)
                .context("Failed to encrypt file")?;
            
            // Print success message with the output file path
            println!("File encrypted successfully: {:?}", output_path);
        }
        
        // Handle the decrypt command - for single file decryption
        Commands::Decrypt { input, output, password } => {
            // Determine the output path: either use the provided path
            // or create one by adding .decrypted extension to the input path
            let output_path = output.clone().unwrap_or_else(|| {
                let mut path = input.clone();
                path.set_extension("decrypted");
                path
            });
            
            // Call our decryption function
            decrypt_file(input, &output_path, password)
                .context("Failed to decrypt file")?;
            
            // Print success message with the output file path
            println!("File decrypted successfully: {:?}", output_path);
        }
        
        // Handle directory encryption
        Commands::EncryptDir { input, output, password, recursive } => {
            // Determine the output directory path
            let output_path = output.clone().unwrap_or_else(|| {
                let mut path_str = input.to_string_lossy().to_string();
                path_str.push_str("_encrypted");
                PathBuf::from(path_str)
            });
            
            // Create the output directory if it doesn't exist
            fs::create_dir_all(&output_path)
                .context("Failed to create output directory")?;
            
            // Call our directory encryption function
            encrypt_directory(input, &output_path, password, *recursive)
                .context("Failed to encrypt directory")?;
            
            println!("Directory encrypted successfully: {:?}", output_path);
        }
        
        // Handle directory decryption
        Commands::DecryptDir { input, output, password, recursive } => {
            // Determine the output directory path
            let output_path = output.clone().unwrap_or_else(|| {
                let mut path_str = input.to_string_lossy().to_string();
                path_str.push_str("_decrypted");
                PathBuf::from(path_str)
            });
            
            // Create the output directory if it doesn't exist
            fs::create_dir_all(&output_path)
                .context("Failed to create output directory")?;
            
            // Call our directory decryption function
            decrypt_directory(input, &output_path, password, *recursive)
                .context("Failed to decrypt directory")?;
            
            println!("Directory decrypted successfully: {:?}", output_path);
        }
    }

    // If we got here, everything succeeded
    Ok(())
}

/// Wrapper function for file encryption
/// This detects if the file is large and uses the appropriate method
/// 
/// Large files (>10MB) are handled with the streaming implementation
/// to avoid loading the entire file into memory at once.
/// Small files use the in-memory implementation for better performance.
///
/// Parameters:
/// - input_path: The path to the file to encrypt
/// - output_path: The path where the encrypted file will be saved
/// - password: The password used to derive the encryption key
fn encrypt_file(input_path: &PathBuf, output_path: &PathBuf, password: &str) -> Result<()> {
    // Check if this is a large file
    match streaming::is_large_file(input_path) {
        Ok(is_large) => {
            if is_large {
                // Use the streaming version for large files
                println!("Large file detected, using streaming encryption...");
                streaming::encrypt_large_file(input_path, output_path, password)
                    .context("Failed to encrypt large file")
            } else {
                // Use the in-memory version for small files
                crypto::encrypt_file(input_path, output_path, password)
                    .context("Failed to encrypt file")
            }
        },
        Err(_) => {
            // If we couldn't determine the size, use the in-memory version
            crypto::encrypt_file(input_path, output_path, password)
                .context("Failed to encrypt file")
        }
    }
}

/// Wrapper function for file decryption
/// This uses the appropriate method based on file extension and size
/// 
/// Large files (>10MB) are handled with the streaming implementation
/// to avoid loading the entire file into memory at once.
/// Small files use the in-memory implementation for better performance.
///
/// Parameters:
/// - input_path: The path to the encrypted file
/// - output_path: The path where the decrypted file will be saved
/// - password: The password used to derive the decryption key
fn decrypt_file(input_path: &PathBuf, output_path: &PathBuf, password: &str) -> Result<()> {
    // Check if this is a large file
    match fs::metadata(input_path) {
        Ok(metadata) => {
            if metadata.len() > 10 * 1024 * 1024 {  // 10MB
                // Use the streaming version for large files
                println!("Large file detected, using streaming decryption...");
                streaming::decrypt_large_file(input_path, output_path, password)
                    .context("Failed to decrypt large file")
            } else {
                // Use the in-memory version for small files
                crypto::decrypt_file(input_path, output_path, password)
                    .context("Failed to decrypt file")
            }
        },
        Err(_) => {
            // If we couldn't determine the size, use the in-memory version
            crypto::decrypt_file(input_path, output_path, password)
                .context("Failed to decrypt file")
        }
    }
}

/// Encrypt an entire directory
/// 
/// This function:
/// 1. Recursively walks through the input directory (if recursive is true)
/// 2. Creates corresponding subdirectories in the output directory
/// 3. Encrypts each file found
///
/// The directory structure is preserved, with each file being encrypted
/// individually. This allows for selective decryption later.
///
/// Parameters:
/// - input_dir: The source directory containing files to encrypt
/// - output_dir: The destination directory for encrypted files
/// - password: The password to use for encryption
/// - recursive: Whether to process subdirectories
fn encrypt_directory(input_dir: &PathBuf, output_dir: &PathBuf, password: &str, recursive: bool) -> Result<()> {
    // Ensure the input is actually a directory
    if !input_dir.is_dir() {
        return Err(anyhow::anyhow!("Input path is not a directory"));
    }
    
    // Count total files to process for progress reporting
    let total_files = progress::count_files(input_dir, recursive)?;
    println!("Found {} files to encrypt", total_files);
    
    // Create a progress tracker
    let mut tracker = progress::ProgressTracker::new(total_files);
    
    // Helper function to encrypt files recursively
    fn encrypt_dir_recursive(
        dir: &PathBuf, 
        output_dir: &PathBuf, 
        password: &str, 
        recursive: bool,
        tracker: &mut progress::ProgressTracker
    ) -> Result<()> {
        // Process each entry in the directory
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                // It's a file, encrypt it
                let relative_path = path.strip_prefix(dir).unwrap_or(&path);
                let mut output_path = output_dir.join(relative_path);
                output_path.set_extension("encrypted");
                
                // Make sure parent directories exist
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                
                // Encrypt the file
                encrypt_file(&path, &output_path, password)?;
                
                // Update progress
                tracker.increment(&path);
            } else if path.is_dir() && recursive {
                // It's a directory and we're in recursive mode
                let relative_path = path.strip_prefix(dir).unwrap_or(&path);
                let new_output_dir = output_dir.join(relative_path);
                
                // Create the corresponding output directory
                fs::create_dir_all(&new_output_dir)?;
                
                // Recursively process this subdirectory
                encrypt_dir_recursive(&path, &new_output_dir, password, recursive, tracker)?;
            }
        }
        
        Ok(())
    }
    
    // Start the recursive encryption
    encrypt_dir_recursive(input_dir, output_dir, password, recursive, &mut tracker)?;
    
    // Print summary
    let elapsed = tracker.elapsed();
    let files_processed = tracker.processed_files();
    println!("Encryption complete! Encrypted {} files in {:.2} seconds", 
             files_processed, elapsed.as_secs_f64());
    
    Ok(())
}

/// Decrypt an entire directory
/// 
/// This function:
/// 1. Recursively walks through the input directory (if recursive is true)
/// 2. Creates corresponding subdirectories in the output directory
/// 3. Decrypts each .encrypted file found
///
/// Only files with .encrypted extension will be processed.
/// The original directory structure is reconstructed during decryption.
///
/// Parameters:
/// - input_dir: The source directory containing encrypted files
/// - output_dir: The destination directory for decrypted files
/// - password: The password to use for decryption
/// - recursive: Whether to process subdirectories
fn decrypt_directory(input_dir: &PathBuf, output_dir: &PathBuf, password: &str, recursive: bool) -> Result<()> {
    // Ensure the input is actually a directory
    if !input_dir.is_dir() {
        return Err(anyhow::anyhow!("Input path is not a directory"));
    }
    
    // Count total encrypted files to process for progress reporting
    let total_files = progress::count_files_with_extension(input_dir, "encrypted", recursive)?;
    println!("Found {} encrypted files to decrypt", total_files);
    
    // Create a progress tracker
    let mut tracker = progress::ProgressTracker::new(total_files);
    
    // Helper function to decrypt files recursively
    fn decrypt_dir_recursive(
        dir: &PathBuf, 
        output_dir: &PathBuf, 
        password: &str, 
        recursive: bool,
        tracker: &mut progress::ProgressTracker
    ) -> Result<()> {
        // Process each entry in the directory
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                // Check if this is an encrypted file
                if let Some(ext) = path.extension() {
                    if ext == "encrypted" {
                        // Get the original filename (without the .encrypted extension)
                        let file_stem = path.file_stem().unwrap_or_default();
                        let relative_path = path.strip_prefix(dir).unwrap_or(&path);
                        
                        // Determine the output path, maintaining directory structure
                        let parent = relative_path.parent().unwrap_or_else(|| std::path::Path::new(""));
                        let output_path = output_dir.join(parent).join(file_stem);
                        
                        // Make sure parent directories exist
                        if let Some(parent) = output_path.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        
                        // Decrypt the file
                        decrypt_file(&path, &output_path, password)?;
                        
                        // Update progress
                        tracker.increment(&path);
                    }
                }
            } else if path.is_dir() && recursive {
                // It's a directory and we're in recursive mode
                let relative_path = path.strip_prefix(dir).unwrap_or(&path);
                let new_output_dir = output_dir.join(relative_path);
                
                // Create the corresponding output directory
                fs::create_dir_all(&new_output_dir)?;
                
                // Recursively process this subdirectory
                decrypt_dir_recursive(&path, &new_output_dir, password, recursive, tracker)?;
            }
        }
        
        Ok(())
    }
    
    // Start the recursive decryption
    decrypt_dir_recursive(input_dir, output_dir, password, recursive, &mut tracker)?;
    
    // Print summary
    let elapsed = tracker.elapsed();
    let files_processed = tracker.processed_files();
    println!("Decryption complete! Decrypted {} files in {:.2} seconds", 
             files_processed, elapsed.as_secs_f64());
    
    Ok(())
}
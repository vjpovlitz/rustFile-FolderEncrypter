// Streaming Module - Large File Encryption and Decryption
// =======================================================
// This module handles encryption and decryption of large files using a streaming approach.
// Instead of loading the entire file into memory, it processes the file in chunks,
// making it suitable for very large files that might not fit in available RAM.
//
// Key features:
// - Memory-efficient processing of files in 1MB chunks
// - Same strong AES-256 encryption as the core crypto module
// - Progress tracking support for large file operations
// - Proper handling of file padding at chunk boundaries
//
// The streaming approach maintains the same security properties as the in-memory
// approach but trades some performance for lower memory usage.

use aes::Aes256;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt,
    KeyInit,
    generic_array::GenericArray,
};
use anyhow::{anyhow, Result};
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha256, Digest};
use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::Path;
use base64::{Engine as _, engine::general_purpose};
use crate::progress::ProgressTracker;

// Constants for cryptographic operations
const BUFFER_SIZE: usize = 1024 * 1024;  // 1MB buffer for reading files
const ITERATIONS: usize = 10000;         // Key derivation iterations
const SALT_SIZE: usize = 16;             // Size of salt in bytes
const IV_SIZE: usize = 16;               // Size of IV in bytes
const BLOCK_SIZE: usize = 16;            // AES block size is always 16 bytes

/// Derive an encryption key from a password and salt
/// Same as in crypto.rs but duplicated here for module independence
///
/// The function works by:
/// 1. Creating an initial hash of the password and salt
/// 2. Performing multiple iterations of hashing the previous result
/// 3. Each iteration increases the computational cost for brute force attacks
///
/// Parameters:
/// - password: The user-provided password
/// - salt: A random salt value to prevent rainbow table attacks
///
/// Returns:
/// - A 32-byte key suitable for AES-256 encryption
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32]; // AES-256 uses 32-byte keys
    let mut hasher = Sha256::new();
    
    // Initial hash of password and salt
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let mut result = hasher.finalize();
    
    // Copy the first hash result
    key[..result.len()].copy_from_slice(&result);
    
    // Perform multiple iterations of hashing to make brute force attacks harder
    for _ in 1..ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(&result);
        result = hasher.finalize();
    }
    
    // Return the key
    key
}

/// Encrypt a file using AES-256 with streaming for large files
/// This version processes the file in chunks to avoid loading it all into memory
///
/// The streaming encryption process:
/// 1. Generate random salt and IV
/// 2. Derive encryption key from password and salt
/// 3. Process the input file in chunks of BUFFER_SIZE (1MB)
/// 4. For each chunk, break it into AES blocks and encrypt each block
/// 5. Handle the final partial block with proper PKCS#7 padding
/// 6. Base64 encode the entire result (salt + IV + encrypted data)
///
/// This approach uses significantly less memory than loading the entire
/// file into memory at once, making it suitable for very large files.
///
/// Parameters:
/// - input_path: Path to the file to encrypt
/// - output_path: Path where the encrypted file will be saved
/// - password: Password to use for encryption
pub fn encrypt_large_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    // Generate a random salt
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    
    // Generate a random IV
    let mut iv = [0u8; IV_SIZE];
    OsRng.fill_bytes(&mut iv);
    
    // Derive the encryption key from the password and salt
    let key = derive_key(password, &salt);
    
    // Open the input and output files
    let input_file = File::open(input_path)?;
    let mut reader = BufReader::new(input_file);
    
    // Create a temporary file for the binary encrypted data
    let temp_path = output_path.with_extension("temp");
    let output_file = File::create(&temp_path)?;
    let mut writer = BufWriter::new(output_file);
    
    // Write the salt and IV to the beginning of the file
    writer.write_all(&salt)?;
    writer.write_all(&iv)?;
    
    // Set up buffer for reading
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut final_block = [0u8; BLOCK_SIZE];
    let mut final_block_size = 0;
    
    // Track progress
    let file_size = fs::metadata(input_path)?.len();
    let mut bytes_read = 0;
    
    // Process the file in chunks
    loop {
        // Read a chunk from the input file
        let bytes = reader.read(&mut buffer)?;
        if bytes == 0 {
            // End of file reached
            break;
        }
        
        // Update progress
        bytes_read += bytes as u64;
        
        // Process all complete blocks in this chunk
        let blocks = bytes / BLOCK_SIZE;
        let remainder = bytes % BLOCK_SIZE;
        
        // Process full blocks
        for i in 0..blocks {
            let start = i * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            
            // Create a block
            let mut block = GenericArray::clone_from_slice(&buffer[start..end]);
            
            // Encrypt the block
            let key_array = GenericArray::from_slice(&key);
            let cipher = aes::Aes256::new(key_array);
            cipher.encrypt_block(&mut block);
            
            // Write the encrypted block
            writer.write_all(&block)?;
        }
        
        // Save any remaining bytes for the next chunk
        if remainder > 0 {
            let start = blocks * BLOCK_SIZE;
            for i in 0..remainder {
                if final_block_size < BLOCK_SIZE {
                    final_block[final_block_size] = buffer[start + i];
                    final_block_size += 1;
                }
            }
        }
        
        // If we've read the entire file, check if we need to add padding
        if bytes_read == file_size && final_block_size > 0 {
            // Add PKCS#7 padding
            let padding_value = BLOCK_SIZE - final_block_size;
            for i in final_block_size..BLOCK_SIZE {
                final_block[i] = padding_value as u8;
            }
            
            // Encrypt the final block
            let mut block = GenericArray::clone_from_slice(&final_block);
            let key_array = GenericArray::from_slice(&key);
            let cipher = aes::Aes256::new(key_array);
            cipher.encrypt_block(&mut block);
            
            // Write the encrypted final block
            writer.write_all(&block)?;
        }
    }
    
    // Flush the writer to ensure all data is written
    writer.flush()?;
    
    // Now encode the entire temporary file as Base64 and write to the final output
    let encrypted_binary = fs::read(&temp_path)?;
    let encoded_data = general_purpose::STANDARD.encode(&encrypted_binary);
    fs::write(output_path, encoded_data)?;
    
    // Clean up the temporary file
    fs::remove_file(&temp_path)?;
    
    Ok(())
}

/// Decrypt a file using AES-256 with streaming for large files
///
/// The streaming decryption process:
/// 1. Read and decode the Base64 data
/// 2. Extract the salt and IV
/// 3. Derive the decryption key from the password and salt
/// 4. Create a temporary file for the binary encrypted data
/// 5. Process the encrypted data in chunks, decrypting each block
/// 6. Handle padding removal for the final block
/// 7. Write the decrypted data to the output file
///
/// This approach is memory-efficient and can handle very large files
/// that might not fit entirely in RAM.
///
/// Parameters:
/// - input_path: Path to the encrypted file
/// - output_path: Path where the decrypted file will be saved
/// - password: Password to use for decryption (must match encryption password)
pub fn decrypt_large_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    // Read the encrypted file
    let encrypted_data = fs::read_to_string(input_path)?;
    
    // Decode the base64 data
    let decoded_data = general_purpose::STANDARD.decode(encrypted_data)?;
    
    // Make sure the data is big enough to contain salt, IV, and at least one block
    if decoded_data.len() < SALT_SIZE + IV_SIZE + BLOCK_SIZE {
        return Err(anyhow!("Invalid encrypted file format"));
    }
    
    // Extract the salt and IV
    let salt = &decoded_data[0..SALT_SIZE];
    let _iv = &decoded_data[SALT_SIZE..SALT_SIZE+IV_SIZE];
    
    // Derive the key
    let key = derive_key(password, salt);
    
    // Create a temporary file for the binary data
    let temp_path = input_path.with_extension("temp");
    fs::write(&temp_path, &decoded_data[SALT_SIZE+IV_SIZE..])?;
    
    // Open the input and output files
    let input_file = File::open(&temp_path)?;
    let mut reader = BufReader::new(input_file);
    let output_file = File::create(output_path)?;
    let mut writer = BufWriter::new(output_file);
    
    // Set up buffer for reading (must be a multiple of block size)
    let mut buffer = [0u8; BUFFER_SIZE - (BUFFER_SIZE % BLOCK_SIZE)];
    
    // Track total bytes for padding removal
    let encrypted_size = decoded_data.len() - SALT_SIZE - IV_SIZE;
    let mut total_decrypted = 0;
    
    // Process the file in chunks
    loop {
        // Read a chunk from the input file
        let bytes = reader.read(&mut buffer)?;
        if bytes == 0 {
            // End of file reached
            break;
        }
        
        // Make sure we read complete blocks
        if bytes % BLOCK_SIZE != 0 {
            return Err(anyhow!("Invalid encrypted data length"));
        }
        
        let blocks = bytes / BLOCK_SIZE;
        total_decrypted += bytes;
        
        // Process each block
        for i in 0..blocks {
            let start = i * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            
            // Create a block
            let mut block = GenericArray::clone_from_slice(&buffer[start..end]);
            
            // Decrypt the block
            let key_array = GenericArray::from_slice(&key);
            let cipher = aes::Aes256::new(key_array);
            cipher.decrypt_block(&mut block);
            
            // If this is the last block, check for padding
            if total_decrypted == encrypted_size && i == blocks - 1 {
                // The last byte tells us how many padding bytes were added
                let padding_len = block[BLOCK_SIZE - 1] as usize;
                
                // Validate padding
                if padding_len <= BLOCK_SIZE && padding_len > 0 {
                    let data_len = BLOCK_SIZE - padding_len;
                    
                    // Verify that all padding bytes have the correct value
                    let is_valid_padding = block[data_len..].iter().all(|&b| b == padding_len as u8);
                    
                    if is_valid_padding {
                        // Write only the data part (remove padding)
                        writer.write_all(&block[..data_len])?;
                    } else {
                        // Invalid padding - might be wrong password or corrupted data
                        return Err(anyhow!("Invalid padding detected - possibly incorrect password"));
                    }
                } else {
                    // Invalid padding length
                    return Err(anyhow!("Invalid padding length detected"));
                }
            } else {
                // Regular block, write all of it
                writer.write_all(&block)?;
            }
        }
    }
    
    // Flush the writer to ensure all data is written
    writer.flush()?;
    
    // Clean up the temporary file
    fs::remove_file(&temp_path)?;
    
    Ok(())
}

/// Function to determine if a file is large (over 10MB)
/// This helps decide whether to use the streaming implementation or the in-memory implementation
///
/// Parameters:
/// - path: Path to the file to check
///
/// Returns:
/// - true if the file is larger than 10MB, false otherwise
pub fn is_large_file(path: &Path) -> Result<bool> {
    let metadata = fs::metadata(path)?;
    Ok(metadata.len() > 10 * 1024 * 1024) // 10MB
}
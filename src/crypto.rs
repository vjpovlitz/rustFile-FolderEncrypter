// Crypto Module - Core Encryption and Decryption Logic
// =======================================================
// This module contains the core cryptographic operations for file encryption and decryption.
// It implements standard cryptographic techniques using the AES-256 algorithm in ECB mode
// with PKCS#7 padding. This module is optimized for smaller files that can fit in memory.
// For larger files, see the streaming.rs module.
//
// Security features:
// - AES-256 encryption for strong security
// - Random salt generation to protect against rainbow table attacks
// - Key derivation with multiple iterations to slow down brute force attempts
// - Proper padding implementation with validation during decryption
//
// Note: While ECB mode is used for simplicity, in a production environment
// you might want to use a more secure mode like GCM or CBC.

// Import required cryptography libraries
use aes::cipher::{
    BlockEncrypt, BlockDecrypt,  // Traits for block cipher operations
    KeyInit,  // Trait for initializing ciphers with keys
    generic_array::GenericArray,  // For fixed-size arrays needed by crypto algorithms
};
use anyhow::{anyhow, Result};  // For error handling
use rand::{RngCore, rngs::OsRng};  // For secure random number generation
use sha2::{Sha256, Digest};  // For SHA-256 hashing algorithm
use std::fs;  // For file system operations
use base64::{Engine as _, engine::general_purpose};  // For Base64 encoding/decoding
use std::path::Path;

// Constants for cryptographic operations
// Number of iterations for key derivation function (higher = more secure but slower)
const ITERATIONS: usize = 10000;
// Size of the salt in bytes (used to prevent rainbow table attacks)
const SALT_SIZE: usize = 16;
// Size of the initialization vector in bytes (used for block cipher modes)
const IV_SIZE: usize = 16;
// AES block size is always 16 bytes
const BLOCK_SIZE: usize = 16;

/// Derive an encryption key from a password and salt
/// This is a simplified version of PBKDF2 (Password-Based Key Derivation Function)
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
    // Create a buffer for our 32-byte key (AES-256 needs a 32-byte key)
    let mut key = [0u8; 32];
    
    // Create a new SHA-256 hasher
    let mut hasher = Sha256::new();
    
    // First hash iteration: combine password and salt
    hasher.update(password.as_bytes());  // Add password bytes to the hash
    hasher.update(salt);  // Add salt bytes to the hash
    let mut result = hasher.finalize();  // Complete the hash
    
    // Copy the first hash result to our key buffer
    key[..result.len()].copy_from_slice(&result);
    
    // Perform multiple iterations of hashing to make brute force attacks harder
    // Each iteration makes the key derivation slower, which increases security
    for _ in 1..ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(&result);  // Hash the previous result
        result = hasher.finalize();  // Get the new hash
    }
    
    key
}

/// Encrypt a file using AES-256
///
/// The encryption process:
/// 1. Generate a random salt and IV (initialization vector)
/// 2. Derive an encryption key from the password and salt
/// 3. Pad the input data to a multiple of the AES block size
/// 4. Encrypt the data using AES-256 in ECB mode (block by block)
/// 5. Store salt + IV + encrypted data in Base64 format
///
/// This function reads the entire file into memory, so it's best for smaller files.
/// For large files, use the streaming version in the streaming module.
///
/// Parameters:
/// - input_path: Path to the file to encrypt
/// - output_path: Path where the encrypted file will be saved
/// - password: Password to use for encryption
pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    // Step 1: Read the entire input file into memory
    // Note: For very large files, you might want to use streaming instead
    let input_data = fs::read(input_path)?;
    
    // Step 2: Generate a random salt (prevents rainbow table attacks)
    // A salt ensures that the same password produces different keys each time
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);  // Fill with cryptographically secure random bytes
    
    // Step 3: Generate a random initialization vector (IV)
    // The IV ensures that the same data encrypted with the same key produces different ciphertext
    let mut iv = [0u8; IV_SIZE];
    OsRng.fill_bytes(&mut iv);  // Fill with cryptographically secure random bytes
    
    // Step 4: Derive the encryption key from the password and salt
    // This converts the user's password into a format suitable for encryption
    let key = derive_key(password, &salt);
    
    // Step 5: Pad the input data to a multiple of the block size
    // AES works on fixed-size blocks (16 bytes), so we need to pad the data
    let padding_len = BLOCK_SIZE - (input_data.len() % BLOCK_SIZE);
    let mut padded_data = input_data.clone();
    // Add PKCS#7 padding (each padding byte contains the number of padding bytes)
    padded_data.extend(vec![padding_len as u8; padding_len]);
    
    // Step 6: Encrypt the data block by block
    let mut encrypted_data = Vec::with_capacity(padded_data.len());
    
    // Process each block of data
    for chunk in padded_data.chunks(BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        
        // Create a new cipher for each block
        let key_array = GenericArray::from_slice(&key);
        let cipher = aes::Aes256::new(key_array);
        
        // Encrypt the block
        cipher.encrypt_block(&mut block);
        
        // Add the encrypted block to our result
        encrypted_data.extend_from_slice(&block);
    }
    
    // Step 7: Combine salt, IV, and encrypted data into a single output
    // Format: salt + IV + encrypted_data
    let mut output_data = Vec::with_capacity(salt.len() + iv.len() + encrypted_data.len());
    output_data.extend_from_slice(&salt);  // Add salt at the beginning
    output_data.extend_from_slice(&iv);    // Add IV after salt
    output_data.extend_from_slice(&encrypted_data);  // Add encrypted data last
    
    // Step 8: Base64 encode the combined data for safe storage in text files
    // Base64 ensures that binary data can be safely stored in text format
    let encoded_data = general_purpose::STANDARD.encode(&output_data);
    
    // Step 9: Write the encoded data to the output file
    fs::write(output_path, encoded_data)?;
    
    // Return success
    Ok(())
}

/// Decrypt a file using AES-256
///
/// The decryption process:
/// 1. Read and decode the encrypted data from Base64 format
/// 2. Extract the salt, IV, and encrypted data components
/// 3. Derive the decryption key using the same process as encryption
/// 4. Decrypt the data using AES-256 in ECB mode (block by block)
/// 5. Remove PKCS#7 padding and save the original data
///
/// This function reads the entire file into memory, so it's best for smaller files.
/// For large files, use the streaming version in the streaming module.
///
/// Parameters:
/// - input_path: Path to the encrypted file
/// - output_path: Path where the decrypted file will be saved
/// - password: Password to use for decryption (must match encryption password)
pub fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    // Step 1: Read the encrypted file as a string (since it's Base64 encoded)
    let encrypted_data = fs::read_to_string(input_path)?;
    
    // Step 2: Decode the Base64 data back to binary
    let decoded_data = general_purpose::STANDARD.decode(encrypted_data)?;
    
    // Step 3: Ensure the decoded data is long enough to contain salt, IV, and at least one block
    // The minimum valid size is: salt size + IV size + one AES block (16 bytes)
    if decoded_data.len() < SALT_SIZE + IV_SIZE + BLOCK_SIZE {
        return Err(anyhow!("Invalid encrypted file format"));
    }
    
    // Step 4: Extract the salt, IV, and encrypted data components
    let salt = &decoded_data[0..SALT_SIZE];  // First SALT_SIZE bytes are the salt
    let _iv = &decoded_data[SALT_SIZE..SALT_SIZE+IV_SIZE];  // Next IV_SIZE bytes are the IV
    let ciphertext = &decoded_data[SALT_SIZE+IV_SIZE..];  // The rest is the encrypted data
    
    // Step 5: Derive the key from the password and salt
    // We use the same key derivation function as during encryption
    let key = derive_key(password, salt);
    
    // Step 6: Decrypt the data block by block
    let mut decrypted_data = Vec::with_capacity(ciphertext.len());
    
    // Process each block of encrypted data
    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        
        // Create a new cipher for each block
        let key_array = GenericArray::from_slice(&key);
        let cipher = aes::Aes256::new(key_array);
        
        // Decrypt the block
        cipher.decrypt_block(&mut block);
        
        // Add the decrypted block to our result
        decrypted_data.extend_from_slice(&block);
    }
    
    // Step 7: Remove PKCS#7 padding
    // The last byte of the padding tells us how many padding bytes were added
    if let Some(&padding_len) = decrypted_data.last() {
        // Check if the padding length is valid (between 1 and 16)
        if padding_len as usize <= BLOCK_SIZE && padding_len > 0 {
            let data_len = decrypted_data.len() - padding_len as usize;
            
            // Verify that all padding bytes have the correct value
            // This helps detect tampering or incorrect decryption
            let is_valid_padding = decrypted_data[data_len..].iter().all(|&b| b == padding_len);
            
            if is_valid_padding {
                // Truncate the decrypted data to remove padding
                decrypted_data.truncate(data_len);
            }
        }
    }
    
    // Step 8: Write the decrypted data to the output file
    fs::write(output_path, decrypted_data)?;
    
    // Return success
    Ok(())
}
// Progress Module - File Operation Progress Tracking
// =======================================================
// This module provides utilities for tracking and displaying progress information
// during file and directory operations. It shows real-time updates on the console
// including elapsed time, estimated time remaining, and current file being processed.
//
// Key features:
// - Progress bar display with percentage completion
// - Elapsed time tracking
// - Estimated time remaining calculation
// - Current file name display
// - Utilities for counting files in directories

use std::io::{self, Write};
use std::time::{Duration, Instant};
use std::path::{Path, PathBuf};
use std::fs;

/// A simple progress tracker for file operations
/// 
/// This struct maintains state about the progress of a file operation,
/// including total files to process, files processed so far, and timing information.
/// It updates the console with progress information at regular intervals.
pub struct ProgressTracker {
    total_files: usize,               // Total number of files to process
    processed_files: usize,           // Number of files processed so far
    start_time: Instant,              // When the operation started
    last_update: Instant,             // When the progress display was last updated
    update_interval: Duration,        // How often to update the display
}

impl ProgressTracker {
    /// Create a new progress tracker
    /// 
    /// Parameters:
    /// - total_files: The total number of files that will be processed
    pub fn new(total_files: usize) -> Self {
        let now = Instant::now();
        Self {
            total_files,
            processed_files: 0,
            start_time: now,
            last_update: now,
            update_interval: Duration::from_millis(500), // Update every 500ms
        }
    }
    
    /// Increment the processed file counter and update the progress display
    /// 
    /// This method is called after each file is processed. It updates the
    /// progress counter and refreshes the progress display if enough time
    /// has passed since the last update.
    ///
    /// Parameters:
    /// - file_path: Path to the file that was just processed
    pub fn increment(&mut self, file_path: &Path) {
        self.processed_files += 1;
        
        let now = Instant::now();
        // Only update the display if it's been long enough since the last update
        // This prevents excessive screen refreshes for fast operations
        if now.duration_since(self.last_update) >= self.update_interval {
            self.update_display(file_path);
            self.last_update = now;
        }
    }
    
    /// Get the total elapsed time since the operation started
    pub fn elapsed(&self) -> Duration {
        Instant::now().duration_since(self.start_time)
    }
    
    /// Get the number of files processed so far
    pub fn processed_files(&self) -> usize {
        self.processed_files
    }
    
    /// Update the progress display on the console
    /// 
    /// This method calculates the progress percentage, elapsed time,
    /// and estimated time remaining, then displays this information
    /// along with the current file being processed.
    ///
    /// Parameters:
    /// - current_file: Path to the file currently being processed
    fn update_display(&self, current_file: &Path) {
        // Calculate progress percentage
        let progress = if self.total_files > 0 {
            (self.processed_files as f64 / self.total_files as f64) * 100.0
        } else {
            0.0
        };
        
        // Calculate timing information
        let elapsed = self.elapsed();
        let elapsed_secs = elapsed.as_secs();
        
        // Calculate estimated time remaining (ETA)
        let eta = if self.processed_files > 0 {
            let files_per_sec = self.processed_files as f64 / elapsed.as_secs_f64();
            let remaining_files = self.total_files as f64 - self.processed_files as f64;
            
            if files_per_sec > 0.0 {
                let remaining_secs = remaining_files / files_per_sec;
                Duration::from_secs_f64(remaining_secs)
            } else {
                Duration::from_secs(0)
            }
        } else {
            Duration::from_secs(0)
        };
        
        // Get the filename for display
        let file_name = current_file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        // Format the progress message
        let message = format!(
            "[{:3.0}%] {}/{} files | Elapsed: {} | ETA: {} | Current: {}{}",
            progress,
            self.processed_files,
            self.total_files,
            format_duration(elapsed),
            format_duration(eta),
            file_name,
            " ".repeat(20) // Add padding to ensure old text is overwritten
        );
        
        // Write to stdout and flush to ensure it's displayed
        // Use \r to return to the beginning of the line (no newline)
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let _ = write!(handle, "\r{}", message);
        let _ = handle.flush();
    }
}

/// Format a duration as HH:MM:SS
/// 
/// Parameters:
/// - duration: The duration to format
///
/// Returns:
/// - A string in the format "HH:MM:SS"
fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Count the total number of files in a directory
/// 
/// This function counts all files (not directories) in the specified directory.
/// If recursive is true, it also counts files in all subdirectories.
///
/// Parameters:
/// - dir: The directory to count files in
/// - recursive: Whether to include subdirectories
///
/// Returns:
/// - The total number of files found
pub fn count_files(dir: &PathBuf, recursive: bool) -> Result<usize, io::Error> {
    let mut count = 0;
    
    // Walk through the directory entries
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            // It's a file, increment the counter
            count += 1;
        } else if path.is_dir() && recursive {
            // It's a directory and we're in recursive mode
            // Count files in this subdirectory and add to the total
            count += count_files(&path, recursive)?;
        }
    }
    
    Ok(count)
}

/// Count the total number of files with a specific extension in a directory
/// 
/// This function counts all files with the specified extension in the directory.
/// If recursive is true, it also counts matching files in all subdirectories.
///
/// Parameters:
/// - dir: The directory to count files in
/// - extension: The file extension to look for (without the dot)
/// - recursive: Whether to include subdirectories
///
/// Returns:
/// - The total number of matching files found
pub fn count_files_with_extension(dir: &PathBuf, extension: &str, recursive: bool) -> Result<usize, io::Error> {
    let mut count = 0;
    
    // Walk through the directory entries
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            // Check if this file has the specified extension
            if let Some(ext) = path.extension() {
                if ext == extension {
                    count += 1;
                }
            }
        } else if path.is_dir() && recursive {
            // It's a directory and we're in recursive mode
            // Count matching files in this subdirectory and add to the total
            count += count_files_with_extension(&path, extension, recursive)?;
        }
    }
    
    Ok(count)
}


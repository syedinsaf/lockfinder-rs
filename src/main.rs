use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, exit};
use std::thread;
use std::time::Duration;
use std::collections::HashSet;
use regex::Regex;

// Embed handle.exe (which is actually handle64.exe renamed)
const HANDLE_EXE: &[u8] = include_bytes!("../assets/handle.exe");

// Windows Admin Elevation
#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length: u32 = 0;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );
        CloseHandle(token);
        result != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(target_os = "windows")]
fn relaunch_elevated() -> ! {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let current_exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(_) => {
            eprintln!("❌ Failed to get current executable path");
            pause_before_exit();
            exit(1);
        }
    };

    let exe_str = match current_exe.to_str() {
        Some(s) => s,
        None => {
            eprintln!("❌ Executable path contains invalid UTF-8");
            pause_before_exit();
            exit(1);
        }
    };

    // Rebuild arguments (skip program name)
    let mut params = String::new();
    for (i, arg) in env::args().skip(1).enumerate() {
        if i > 0 {
            params.push(' ');
        }
        if arg.contains(' ') || arg.contains('"') {
            let escaped = arg.replace('"', "\\\"");
            params.push('"');
            params.push_str(&escaped);
            params.push('"');
        } else {
            params.push_str(&arg);
        }
    }

    println!("🔒 Administrator privileges required. Requesting elevation...\n");
    println!("This window will close automatically after elevation.\n");

    unsafe {
        let operation: Vec<u16> = "runas\0".encode_utf16().collect();
        let file: Vec<u16> = exe_str.encode_utf16().chain(Some(0)).collect();
        let parameters: Vec<u16> = params.encode_utf16().chain(Some(0)).collect();

        let result = ShellExecuteW(
            0 as HWND,
            operation.as_ptr(),
            file.as_ptr(),
            if params.is_empty() { std::ptr::null() } else { parameters.as_ptr() },
            std::ptr::null(),
            SW_SHOWNORMAL as i32,
        );

        let result_code = result as isize;
        if result_code > 32 {
            thread::sleep(Duration::from_millis(800));
            exit(0);
        } else {
            let err_msg = match result_code {
                0 => "Out of memory or resources",
                2 => "File not found",
                3 => "Path not found",
                5 => "Access denied (UAC prompt cancelled)",
                8 => "Out of memory",
                31 => "No application associated with file type",
                _ => &format!("ShellExecuteW failed (error code: {})", result_code),
            };
            eprintln!("❌ Failed to request elevation: {}", err_msg);
            pause_before_exit();
            exit(1);
        }
    }
}

fn pause_before_exit() {
    print!("\nPress Enter to exit...");
    let _ = io::stdout().flush();
    let mut dummy = String::new();
    let _ = io::stdin().read_line(&mut dummy);
}

// Cleanup Handler 
struct TempFileGuard {
    path: PathBuf,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        TempFileGuard { path }
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

// Main Logic
fn main() {
    // Auto-elevate on Windows if needed
    #[cfg(target_os = "windows")]
    {
        if !is_elevated() {
            relaunch_elevated();
        }
    }

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        pause_before_exit();
        return;
    }

    // Parse arguments
    let mut force = false;
    let mut target_path = String::new();

    for arg in &args[1..] {
        if arg == "--force" {
            force = true;
        } else if target_path.is_empty() {
            target_path = arg.clone();
        } else {
            eprintln!("❌ Unexpected extra argument: {}", arg);
            print_usage();
            pause_before_exit();
            exit(1);
        }
    }

    if target_path.is_empty() {
        print_usage();
        pause_before_exit();
        return;
    }

    // Validate the path exists
    let target_path = match fs::canonicalize(&target_path) {
        Ok(canonical_path) => {
            // Convert back to regular path (strip \\?\ prefix if present)
            let path_str = canonical_path.to_string_lossy();
            if path_str.starts_with(r"\\?\") {
                path_str[4..].to_string()
            } else {
                path_str.to_string()
            }
        },
        Err(e) => {
            match e.kind() {
                io::ErrorKind::NotFound => {
                    eprintln!("❌ File or folder not found: {}", target_path);
                    eprintln!("💡 Please check the path and try again.");
                },
                io::ErrorKind::PermissionDenied => {
                    eprintln!("❌ Permission denied accessing: {}", target_path);
                    eprintln!("💡 The path might be in a restricted system folder.");
                },
                _ => {
                    eprintln!("❌ Cannot access path: {}", e);
                    eprintln!("💡 Path: {}", target_path);
                }
            }
            pause_before_exit();
            exit(1);
        }
    };

    let handle_exe_path = match extract_handle_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("❌ Failed to extract handle.exe: {}", e);
            pause_before_exit();
            exit(1);
        }
    };

    // Create guard to ensure cleanup on exit
    let _guard = TempFileGuard::new(handle_exe_path.clone());

    println!("🔍 Searching for processes locking: {}\n", target_path);

    let output = match Command::new(&handle_exe_path)
        .arg("-accepteula")
        .arg("-nobanner")
        .arg(&target_path)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("❌ handle.exe failed with error:");
                eprintln!("{}", stderr.trim());
                eprintln!("💡 This might indicate insufficient permissions or an invalid path.");
                pause_before_exit();
                exit(1);
            }
            output
        },
        Err(e) => {
            match e.kind() {
                io::ErrorKind::NotFound => {
                    eprintln!("❌ Failed to execute handle.exe: tool not found");
                    eprintln!("💡 The embedded tool may have failed to extract properly.");
                },
                io::ErrorKind::PermissionDenied => {
                    eprintln!("❌ Permission denied executing handle.exe");
                    eprintln!("💡 Antivirus may be blocking execution. Try adding an exception.");
                },
                _ => {
                    eprintln!("❌ Failed to run handle.exe: {}", e);
                    eprintln!("💡 This usually means the tool lacks permissions or was blocked.");
                }
            }
            pause_before_exit();
            exit(1);
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let processes = parse_handle_output(&stdout, &target_path);

    if processes.is_empty() {
        println!("✅ No processes found locking this file/folder");
        println!("   The file might be free to use now!");
        pause_before_exit();
        return;
    }

    println!("📋 Found {} process(es) locking the file:\n", processes.len());
    for (i, (name, pid)) in processes.iter().enumerate() {
        println!("   {}. {} (PID: {})", i + 1, name, pid);
    }

    let system_processes: Vec<_> = processes
        .iter()
        .filter(|(name, _)| is_system_process(name))
        .collect();

    if !system_processes.is_empty() {
        println!("⚠️  ⚠️  ⚠️  SYSTEM PROCESS WARNING  ⚠️  ⚠️  ⚠️");
        println!("The following process(es) are part of the Windows operating system:");
        for (name, pid) in &system_processes {
            println!("   - {} (PID: {})", name, pid);
        }
        println!();
        println!("💀 Terminating system processes can cause:");
        println!("   • Immediate system crash (BSOD)");
        println!("   • Forced user logout");
        println!("   • Data loss or corruption");
        println!("   • Unstable desktop or frozen UI");
        println!();

        if force {
            println!("🚨 You are using --force. Proceeding despite the risks...");
            println!("   Continuing in 3 seconds... (Press Ctrl+C to abort)");
            thread::sleep(Duration::from_secs(3));
            kill_processes(processes);
        } else {
            println!("🛑 Killing system processes is DISABLED by default.");
            println!("   If you are certain this is safe, rerun with --force");
            println!("❌ Action cancelled. No processes were killed.");
            pause_before_exit();
        }
    } else {
        println!("\n⚠️  Do you want to kill these processes? (y/n): ");
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            if input.trim().to_lowercase() == "y" {
                kill_processes(processes);
            } else {
                println!("❌ Cancelled. No processes were killed.");
                pause_before_exit();
            }
        } else {
            println!("❌ Failed to read input.");
            pause_before_exit();
        }
    }
    // TempFileGuard automatically cleans up handle.exe here
}

fn is_system_process(name: &str) -> bool {
    const SYSTEM_PROCESSES: &[&str] = &[
        "System",
        "smss.exe",
        "csrss.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "registry",
        "explorer.exe",
        "dwm.exe",
        "svchost.exe",
        "dllhost.exe",
        "taskhostw.exe",
        "conhost.exe",
        "sihost.exe",
        "RuntimeBroker.exe",
        "spoolsv.exe",
        "SearchIndexer.exe",
    ];
    SYSTEM_PROCESSES
        .iter()
        .any(|&proc| proc.eq_ignore_ascii_case(name))
}

fn extract_handle_exe() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let temp_dir = env::temp_dir();
    let handle_exe_path = temp_dir.join("lockfinder_handle.exe");

    if !handle_exe_path.exists() || fs::metadata(&handle_exe_path)?.len() != HANDLE_EXE.len() as u64 {
        let mut file = fs::File::create(&handle_exe_path)?;
        file.write_all(HANDLE_EXE)?;
        file.flush()?;
        println!("📦 Extracted handle.exe to temporary directory\n");
    }

    Ok(handle_exe_path)
}

fn parse_handle_output(output: &str, target_path: &str) -> Vec<(String, u32)> {
    let mut processes = Vec::new();
    let mut seen_pids = HashSet::new();
    let target_lower = target_path.to_lowercase();

    let re = match Regex::new(r"^(.+?)\s+pid:\s*(\d+)") {
        Ok(r) => r,
        Err(_) => return processes,
    };

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.to_lowercase().contains(&target_lower) {
            continue;
        }

        if let Some(caps) = re.captures(trimmed) {
            let name = caps.get(1).map_or("", |m| m.as_str()).trim().to_string();
            if let Some(pid_str) = caps.get(2) {
                if let Ok(pid) = pid_str.as_str().parse::<u32>() {
                    if !name.is_empty() && seen_pids.insert(pid) {
                        processes.push((name, pid));
                    }
                }
            }
        }
    }

    processes
}

fn kill_processes(processes: Vec<(String, u32)>) {
    println!("\n💀 Attempting to terminate processes...\n");

    for (name, pid) in &processes {
        println!("   Killing {} (PID: {})...", name, pid);

        // Spawn taskkill with timeout
        let child = Command::new("taskkill")
            .arg("/F")
            .arg("/T")  // Kill process tree
            .arg("/PID")
            .arg(pid.to_string())
            .spawn();

        match child {
            Ok(mut process) => {
                // Wait up to 5 seconds for taskkill to complete
                let timeout = Duration::from_secs(5);
                let start = std::time::Instant::now();
                
                loop {
                    match process.try_wait() {
                        Ok(Some(status)) => {
                            if status.success() {
                                println!("   ✅ Successfully killed {} (PID: {})", name, pid);
                            } else {
                                println!("   ❌ Failed to kill {} (PID: {})", name, pid);
                            }
                            break;
                        }
                        Ok(None) => {
                            // Process still running
                            if start.elapsed() >= timeout {
                                let _ = process.kill();
                                println!("   ⚠️  Timeout killing {} (PID: {}) - forcefully terminated taskkill", name, pid);
                                break;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        Err(e) => {
                            println!("   ❌ Error checking taskkill status: {}", e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                println!("   ❌ Error spawning taskkill: {}", e);
            }
        }
    }

    println!("\n✅ Process termination complete!");
}

fn print_usage() {
    println!("🔒 File Lock Finder (lockfinder-rs)");
    println!();
    println!("Usage: lockfinder-rs [OPTIONS] <path>");
    println!();
    println!("Options:");
    println!("  --force    Force-kill even system processes (use with extreme caution)");
    println!();
    println!("Examples:");
    println!("  lockfinder-rs \"C:\\temp\\locked.txt\"");
    println!("  lockfinder-rs --force \"D:\\MyFolder\"");
    println!();
    println!("This tool finds processes locking a file or folder,");
    println!("preventing you from renaming, deleting, or moving it.");
    println!();
    println!("💡 Note: The tool will automatically request Administrator privileges if needed.");
}
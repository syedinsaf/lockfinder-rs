use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, exit};
use std::time::Duration;
use regex::Regex;

// Embed handle.exe (which is actually handle64.exe renamed)
const HANDLE_EXE: &[u8] = include_bytes!("../assets/handle.exe");

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    // Parse arguments: support --force anywhere, exactly one path
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
            exit(1);
        }
    }

    if target_path.is_empty() {
        print_usage();
        return;
    }

    let handle_exe_path = match extract_handle_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("❌ Failed to extract handle.exe: {}", e);
            exit(1);
        }
    };

    println!("🔍 Searching for processes locking: {}\n", target_path);

    let output = match Command::new(&handle_exe_path)
        .arg("-accepteula")
        .arg("-nobanner")
        .arg(&target_path)
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            eprintln!("❌ Failed to run handle.exe: {}", e);
            eprintln!("💡 You may need to run this program as Administrator");
            exit(1);
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output — now correctly matches path on same line as PID
    let processes = parse_handle_output(&stdout, &target_path);

    if processes.is_empty() {
        println!("✅ No processes found locking this file/folder");
        println!("   The file might be free to use now!");
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
            std::thread::sleep(Duration::from_secs(3));
            kill_processes(processes);
        } else {
            println!("🛑 Killing system processes is DISABLED by default.");
            println!("   If you are certain this is safe, rerun with --force");
            println!("❌ Action cancelled. No processes were killed.");
        }
    } else {
        // Only non-system processes
        println!("\n⚠️  Do you want to kill these processes? (y/n): ");
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            if input.trim().to_lowercase() == "y" {
                kill_processes(processes);
            } else {
                println!("❌ Cancelled. No processes were killed.");
            }
        }
    }
}

fn is_system_process(name: &str) -> bool {
    const SYSTEM_PROCESSES: &[&str] = &[
        // Core critical processes
        "System",
        "smss.exe",
        "csrss.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "registry",

        // High-risk user-facing system processes
        "explorer.exe",
        "dwm.exe",

        // System service hosts (often lock files)
        "svchost.exe",
        "dllhost.exe",
        "taskhostw.exe",

        // Console & security
        "conhost.exe",
        "sihost.exe",
        "RuntimeBroker.exe",

        // Print & search (common file lockers)
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

    // Re-extract if missing or size doesn't match (simple cache)
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
    let target_lower = target_path.to_lowercase();

    // Regex to capture process name and PID from lines like:
    // "WINWORD.EXE        pid: 24568  type: File ..."
    let re = match Regex::new(r"^(.+?)\s+pid:\s*(\d+)") {
        Ok(r) => r,
        Err(_) => return processes,
    };

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Only consider lines that mention the target path
        if !trimmed.to_lowercase().contains(&target_lower) {
            continue;
        }

        // Try to extract process name and PID from the same line
        if let Some(caps) = re.captures(trimmed) {
            let name = caps.get(1).map_or("", |m| m.as_str()).trim().to_string();
            let pid: u32 = caps.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));

            if pid > 0 && !name.is_empty() {
                // Avoid duplicates
                if !processes.iter().any(|(_, p)| p == &pid) {
                    processes.push((name, pid));
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

        let output = Command::new("taskkill")
            .arg("/F")
            .arg("/PID")
            .arg(pid.to_string())
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    println!("   ✅ Successfully killed {} (PID: {})", name, pid);
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    println!("   ❌ Failed to kill {}: {}", name, stderr.trim());
                }
            }
            Err(e) => {
                println!("   ❌ Error running taskkill: {}", e);
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
    println!("  lockfinder-rs \"C:\\Users\\Documents\\locked_file.txt\"");
    println!("  lockfinder-rs --force \"D:\\MyFolder\"");
    println!();
    println!("This tool finds processes that are locking a file or folder,");
    println!("preventing you from renaming, deleting, or moving it.");
    println!();
    println!("💡 Note: You may need Administrator privileges to see all processes.");
}
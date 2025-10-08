<div align="center">
  
# lockfinder-rs

A Windows command-line tool to identify and terminate processes that are locking files or folders.

</div>

---

## Description

lockfinder-rs helps you resolve situations where Windows prevents you from deleting, renaming, or moving files because they are in use by another process. The tool identifies which processes have handles on the specified file or folder and provides options to terminate those processes.

## Features

- Automatically detects processes locking a file or folder
- Displays process names and PIDs
- Interactive confirmation before terminating processes
- Special protection for system-critical processes
- Automatic elevation to Administrator privileges when needed
- Embedded handle.exe (no external dependencies)

## Installation

### Prerequisites

- Windows operating system
- Rust toolchain (for building from source)

### Building from Source

```bash
cargo build --release
```

The compiled executable will be located at `target/release/lockfinder-rs.exe`

## Usage

### Basic Usage

```bash
lockfinder-rs "C:\path\to\locked\file.txt"
```

### Force Mode

```bash
lockfinder-rs --force "C:\path\to\locked\file.txt"
```

## WARNING - Read Before Use

### General Warnings

**DATA LOSS RISK**: Terminating processes will close applications without saving. Any unsaved work in the terminated application will be lost.

**SYSTEM INSTABILITY**: Killing the wrong process can cause system instability, application crashes, or require a system restart.

**ADMINISTRATOR PRIVILEGES**: This tool requires administrator privileges to function. It will automatically request elevation via UAC prompt.

### System Process Warnings

**CRITICAL**: The tool includes protection against terminating system-critical processes. Attempting to kill system processes without the `--force` flag will result in a warning and cancellation.

**DANGER**: Using `--force` to kill system processes can result in:
- Immediate system crash (Blue Screen of Death)
- Forced user logout
- Data loss or corruption across all running applications
- Unstable desktop environment or frozen UI
- Need to force-restart the computer

### Processes Protected by Default

The following system processes are protected and require `--force` to terminate:

- System
- smss.exe
- csrss.exe
- winlogon.exe
- services.exe
- lsass.exe
- registry
- explorer.exe
- dwm.exe
- svchost.exe
- dllhost.exe
- taskhostw.exe
- conhost.exe
- sihost.exe
- RuntimeBroker.exe
- spoolsv.exe
- SearchIndexer.exe

**DO NOT** use `--force` unless you fully understand the consequences and are prepared for potential system instability.

## How It Works

1. The tool extracts an embedded copy of Sysinternals handle.exe to your temporary directory
2. It queries handle.exe for processes holding handles to the specified file or folder
3. Results are displayed with process names and PIDs
4. You are prompted to confirm before any processes are terminated
5. If confirmed, the tool uses `taskkill /F /T` to forcefully terminate the processes and their child processes
6. Temporary files are automatically cleaned up on exit

## Examples

### Example 1: Unlock a Document

```bash
lockfinder-rs "C:\Documents\report.docx"
```

Output:
```
Searching for processes locking: C:\Documents\report.docx

Found 1 process(es) locking the file:

   1. WINWORD.EXE (PID: 12345)

Do you want to kill these processes? (y/n):
```

### Example 2: Protected System Process

```bash
lockfinder-rs "C:\Windows\System32\some-file.dll"
```

Output:
```
SYSTEM PROCESS WARNING
The following process(es) are part of the Windows operating system:
   - svchost.exe (PID: 1234)

Terminating system processes can cause:
   - Immediate system crash (BSOD)
   - Forced user logout
   - Data loss or corruption
   - Unstable desktop or frozen UI

Killing system processes is DISABLED by default.
If you are certain this is safe, rerun with --force
Action cancelled. No processes were killed.
```

## Limitations

- Windows only (uses Windows-specific APIs)
- Requires Administrator privileges
- Cannot terminate protected system processes without `--force`
- Will close applications without saving (use with caution)
- May require system restart if critical processes are terminated

## License

This tool embeds handle.exe from Sysinternals Suite. Please ensure compliance with Microsoft's Sysinternals Software License Terms.

## Disclaimer

**USE AT YOUR OWN RISK**. This tool can terminate processes and cause data loss. The authors are not responsible for any damage, data loss, system instability, or other issues that may result from using this tool. Always ensure you have backups of important data before using this tool.

## Support

For issues, bugs, or feature requests, please create an issue in the project repository.

## Technical Details

### Dependencies

- `regex`: Pattern matching for handle.exe output
- `windows-sys`: Windows API bindings for privilege elevation

### Architecture

The tool uses a three-stage approach:
1. **Detection**: Uses Sysinternals handle.exe to enumerate file handles
2. **Analysis**: Parses output and identifies process names and PIDs
3. **Termination**: Uses Windows taskkill command with force flag

### Cleanup

The tool automatically cleans up temporary files (extracted handle.exe) when exiting, even if terminated unexpectedly through Rust's Drop trait implementation.

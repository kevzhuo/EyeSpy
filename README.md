# EyeSpy

```
    .-"""-.
   /        \
  |  O    O  |
  |    __    |
   \  \__/  /
    '-.__.-'
```

A visual file system watcher with a spy theme. Monitor directories for changes with colorful output, pattern matching, and suspicious activity detection.

## Installation

```bash
# Clone and build
git clone https://github.com/yourusername/eyespy.git
cd eyespy
cargo build --release

# Binary will be at ./target/release/eyespy
```

## Quick Start

```bash
# Watch current directory
eyespy

# Watch specific directories
eyespy /path/to/dir1 /path/to/dir2

# Stealth mode (ignore noise like .DS_Store, node_modules)
eyespy --stealth

# Watch for specific files
eyespy --spy "*.env" --spy "*.secret"
```

## Features

### Core Watching
- Real-time file system monitoring
- Recursive directory watching (default)
- Color-coded event types:
  - `✨ CREATED` (green)
  - `📝 MODIFIED` (yellow)
  - `🗑️ DELETED` (red)
  - `👀 ACCESSED` (blue)

### Stealth Mode (`--stealth`)
Filters out common noise files automatically:
- `.DS_Store`, `Thumbs.db`
- `.git/`, `node_modules/`, `target/`
- `__pycache__/`, `*.pyc`
- `.idea/`, `.vscode/`
- Swap files (`*.swp`, `*.swo`, `*~`)

### I Spy Patterns (`--spy <PATTERN>`)
Highlight files matching glob patterns with `🎯 ★ SPY HIT ★`:

```bash
eyespy --spy "*.env" --spy "*.secret" --spy "config.*"
```

### Suspicious Activity Detection (`--suspicious`)
Alerts on potentially concerning file system activity:
- Hidden files being created (files starting with `.`)
- Executable files (`.exe`, `.sh`, `.bat`, `.ps1`)
- Sensitive file names (`credentials`, `password`, `private_key`, `.pem`)
- Rapid file changes (5+ events in 2 seconds)

```bash
eyespy --suspicious
```

### Mission Log (`--log <FILE>`)
Save all activity to a timestamped log file:

```bash
eyespy --log mission.log
```

Log format:
```
[2024-01-15 14:23:45.123] Create(File) - /path/to/file.txt
[2024-01-15 14:23:46.456] Modify(Data) - /path/to/file.txt [SPY HIT]
```

### Event Filtering (`--only <TYPE>`)
Only show specific event types:

```bash
# Only show creates and deletes
eyespy --only create --only delete

# Only show modifications
eyespy --only modify
```

### Custom Ignore Patterns (`--ignore <PATTERN>`)
Add your own patterns to ignore:

```bash
eyespy --ignore "**/test_*" --ignore "**/*.tmp"
```

### Mission Summary
Press `Ctrl+C` to end the mission and see a summary:

```
  ╔═══════════════════════════════════════╗
  ║        📋 MISSION SUMMARY 📋          ║
  ╚═══════════════════════════════════════╝

  ⏱️  Duration: 5m 23s
  📊 Total Events: 142

  ✨ Created: 12
  📝 Modified: 118
  🗑️  Deleted: 8
  👀 Accessed: 4

  🎯 Spy Pattern Hits: 6
  🚨 Suspicious Events: 2
```

## Options Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--recursive` | `-r` | Watch directories recursively (default: true) |
| `--stealth` | `-s` | Ignore common noise files |
| `--spy <PATTERN>` | | Highlight files matching pattern |
| `--log <FILE>` | `-l` | Save activity to log file |
| `--suspicious` | | Detect suspicious activity |
| `--ignore <PATTERN>` | `-i` | Additional patterns to ignore |
| `--only <TYPE>` | | Only show specific event types |
| `--debug` | `-d` | Show detailed event information |
| `--banner` | | Show welcome banner (default: true) |
| `--help` | `-h` | Print help |
| `--version` | `-V` | Print version |

## Examples

### Development Workflow
Watch a project, ignoring build artifacts and highlighting config changes:
```bash
eyespy --stealth --spy "*.json" --spy "*.toml" --spy "*.yaml" ~/myproject
```

### Security Monitoring
Watch for suspicious file activity in a directory:
```bash
eyespy --suspicious --spy "*.env" --spy "*.pem" --spy "*.key" --log security.log /var/www
```

### Focused Monitoring
Only watch for new files and deletions:
```bash
eyespy --only create --only delete --stealth .
```

### Debug Mode
See raw events from the file system:
```bash
eyespy --debug /tmp
```

## Event Symbols

| Symbol | Meaning |
|--------|---------|
| `◉` | File created |
| `◎` | File modified |
| `○` | File deleted |
| `●` | File accessed |
| `🎯` | Spy pattern matched |
| `🚨` | Suspicious activity |

## License

MIT

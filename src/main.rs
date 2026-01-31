use chrono::Local;
use clap::Parser;
use colored::*;
use glob_match::glob_match;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::{Duration, Instant};

const EYE_OPEN: &str = r#"
    .-"""-.
   /        \
  |  O    O  |
  |    __    |
   \  \__/  /
    '-.__.-'
"#;

const EYE_ALERT: &str = r#"
    .-"""-.
   /        \
  |  !    ! |
  |    ^^   |
   \  \__/  /
    '-.__.-'
"#;

const EYE_WINK: &str = r#"
    .-"""-.
   /        \
  |  O    - |
  |    __   |
   \  \__/  /
    '-.__.-'
"#;

// Default patterns to ignore in stealth mode
const STEALTH_PATTERNS: &[&str] = &[
    "**/.DS_Store",
    "**/.git/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/target/**",
    "**/.idea/**",
    "**/.vscode/**",
    "**/*.swp",
    "**/*.swo",
    "**/*~",
    "**/Thumbs.db",
];

#[derive(Parser)]
#[command(name = "eyespy")]
#[command(about = "👁️  EyeSpy - A visual file system watcher", long_about = None)]
#[command(version)]
struct Args {
    /// Path(s) to watch
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    /// Watch recursively
    #[arg(short, long, default_value_t = true)]
    recursive: bool,

    /// Show the welcome banner
    #[arg(long, default_value_t = true)]
    banner: bool,

    /// Debug mode - show detailed event information
    #[arg(short, long)]
    debug: bool,

    /// Stealth mode - ignore common noise files (.DS_Store, node_modules, etc.)
    #[arg(short, long)]
    stealth: bool,

    /// "I Spy" - patterns to highlight (e.g., "*.secret", "*.env")
    #[arg(long = "spy", value_name = "PATTERN")]
    spy_patterns: Vec<String>,

    /// Save activity to a spy log file
    #[arg(short, long, value_name = "FILE")]
    log: Option<PathBuf>,

    /// Detect suspicious activity (hidden files, rapid changes)
    #[arg(long)]
    suspicious: bool,

    /// Additional patterns to ignore
    #[arg(short, long = "ignore", value_name = "PATTERN")]
    ignore_patterns: Vec<String>,

    /// Only show specific event types (create, modify, delete, access)
    #[arg(long = "only", value_name = "TYPE")]
    only_events: Vec<String>,
}

#[derive(Default)]
struct MissionStats {
    creates: u64,
    modifies: u64,
    deletes: u64,
    accesses: u64,
    spy_hits: u64,
    suspicious_events: u64,
    start_time: Option<Instant>,
}

impl MissionStats {
    fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    fn record_event(&mut self, kind: &EventKind) {
        match kind {
            EventKind::Create(_) => self.creates += 1,
            EventKind::Modify(_) => self.modifies += 1,
            EventKind::Remove(_) => self.deletes += 1,
            EventKind::Access(_) => self.accesses += 1,
            _ => {}
        }
    }

    fn total(&self) -> u64 {
        self.creates + self.modifies + self.deletes + self.accesses
    }

    fn print_summary(&self) {
        let duration = self.start_time.map(|s| s.elapsed()).unwrap_or_default();
        let mins = duration.as_secs() / 60;
        let secs = duration.as_secs() % 60;

        println!();
        println!("{}", EYE_WINK.bright_cyan());
        println!(
            "{}",
            "  ╔═══════════════════════════════════════╗"
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "  ║        📋 MISSION SUMMARY 📋          ║"
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "  ╚═══════════════════════════════════════╝"
                .bright_white()
                .bold()
        );
        println!();
        println!(
            "  {} {}",
            "⏱️  Duration:".bright_white(),
            format!("{}m {}s", mins, secs).bright_cyan()
        );
        println!(
            "  {} {}",
            "📊 Total Events:".bright_white(),
            self.total().to_string().bright_cyan().bold()
        );
        println!();
        println!(
            "  {} {}",
            "✨ Created:".bright_green(),
            self.creates.to_string().green()
        );
        println!(
            "  {} {}",
            "📝 Modified:".bright_yellow(),
            self.modifies.to_string().yellow()
        );
        println!(
            "  {} {}",
            "🗑️  Deleted:".bright_red(),
            self.deletes.to_string().red()
        );
        println!(
            "  {} {}",
            "👀 Accessed:".bright_blue(),
            self.accesses.to_string().blue()
        );

        if self.spy_hits > 0 {
            println!();
            println!(
                "  {} {}",
                "🎯 Spy Pattern Hits:".bright_magenta().bold(),
                self.spy_hits.to_string().magenta().bold()
            );
        }

        if self.suspicious_events > 0 {
            println!();
            println!(
                "  {} {}",
                "🚨 Suspicious Events:".bright_red().bold(),
                self.suspicious_events.to_string().red().bold()
            );
        }
        println!();
    }
}

struct SuspiciousDetector {
    recent_events: HashMap<PathBuf, Vec<Instant>>,
    rapid_threshold: Duration,
    rapid_count: usize,
}

impl SuspiciousDetector {
    fn new() -> Self {
        Self {
            recent_events: HashMap::new(),
            rapid_threshold: Duration::from_secs(2),
            rapid_count: 5,
        }
    }

    fn check(&mut self, path: &PathBuf, kind: &EventKind) -> Vec<String> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Check for hidden files (starting with .)
        if let Some(name) = path.file_name() {
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') && name_str != ".." && name_str != "." {
                if matches!(kind, EventKind::Create(_)) {
                    alerts.push(format!("Hidden file created: {}", name_str));
                }
            }
        }

        // Check for rapid changes
        let events = self.recent_events.entry(path.clone()).or_default();
        events.push(now);
        events.retain(|t| now.duration_since(*t) < self.rapid_threshold);

        if events.len() >= self.rapid_count {
            alerts.push(format!(
                "Rapid changes detected: {} events in {:?}",
                events.len(),
                self.rapid_threshold
            ));
            events.clear();
        }

        // Check for suspicious extensions
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            let suspicious_exts = ["exe", "dll", "bat", "sh", "ps1", "vbs", "cmd"];
            if suspicious_exts.contains(&ext_str.as_str()) {
                if matches!(kind, EventKind::Create(_)) {
                    alerts.push(format!("Executable file created: .{}", ext_str));
                }
            }
        }

        // Check for potential sensitive files
        if let Some(name) = path.file_name() {
            let name_str = name.to_string_lossy().to_lowercase();
            let sensitive_names = [
                ".env",
                ".secret",
                "credentials",
                "password",
                "private_key",
                "id_rsa",
                ".pem",
            ];
            for sensitive in sensitive_names {
                if name_str.contains(sensitive) {
                    alerts.push(format!("Sensitive file activity: {}", name_str));
                    break;
                }
            }
        }

        alerts
    }
}

fn print_banner(spy_patterns: &[String], stealth: bool, suspicious: bool) {
    println!("{}", EYE_OPEN.bright_cyan());
    println!(
        "{}",
        "  ╔═══════════════════════════════════════╗"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "  ║     👁️  E Y E S P Y  v0.2 👁️          ║"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "  ║   Watching your files silently...     ║"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "  ╚═══════════════════════════════════════╝"
            .bright_white()
            .bold()
    );
    println!();

    // Show active modes
    if stealth || suspicious || !spy_patterns.is_empty() {
        println!("  {} ", "Active Modes:".bright_white().bold());
        if stealth {
            println!("    {} Stealth Mode (filtering noise)", "🥷".bright_black());
        }
        if suspicious {
            println!(
                "    {} Suspicious Activity Detection",
                "🚨".bright_red()
            );
        }
        if !spy_patterns.is_empty() {
            println!(
                "    {} I Spy: {}",
                "🎯".bright_magenta(),
                spy_patterns.join(", ").bright_magenta()
            );
        }
        println!();
    }
}

fn format_event_kind(kind: &EventKind) -> ColoredString {
    match kind {
        EventKind::Create(_) => "✨ CREATED".bright_green().bold(),
        EventKind::Modify(_) => "📝 MODIFIED".bright_yellow().bold(),
        EventKind::Remove(_) => "🗑️  DELETED".bright_red().bold(),
        EventKind::Access(_) => "👀 ACCESSED".bright_blue(),
        EventKind::Any => "❓ UNKNOWN".white(),
        EventKind::Other => "🔮 OTHER".bright_magenta(),
    }
}

fn get_mini_eye(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::Create(_) => "◉",
        EventKind::Modify(_) => "◎",
        EventKind::Remove(_) => "○",
        EventKind::Access(_) => "●",
        _ => "◌",
    }
}

fn should_ignore(path: &PathBuf, stealth: bool, ignore_patterns: &[String]) -> bool {
    let path_str = path.to_string_lossy();

    if stealth {
        for pattern in STEALTH_PATTERNS {
            if glob_match(pattern, &path_str) {
                return true;
            }
        }
    }

    for pattern in ignore_patterns {
        if glob_match(pattern, &path_str) {
            return true;
        }
    }

    false
}

fn matches_spy_pattern(path: &PathBuf, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    let path_str = path.to_string_lossy();
    for pattern in patterns {
        // Try matching with and without ** prefix
        if glob_match(pattern, &path_str) {
            return true;
        }
        let prefixed = format!("**/{}", pattern);
        if glob_match(&prefixed, &path_str) {
            return true;
        }
    }
    false
}

fn event_matches_filter(kind: &EventKind, filters: &[String]) -> bool {
    if filters.is_empty() {
        return true;
    }

    let event_type = match kind {
        EventKind::Create(_) => "create",
        EventKind::Modify(_) => "modify",
        EventKind::Remove(_) => "delete",
        EventKind::Access(_) => "access",
        _ => "other",
    };

    filters.iter().any(|f| f.to_lowercase() == event_type)
}

fn write_to_log(log_file: &mut Option<File>, message: &str) {
    if let Some(ref mut file) = log_file {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Setup Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let mut stats = MissionStats::new();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    if args.banner {
        print_banner(&args.spy_patterns, args.stealth, args.suspicious);
    }

    // Open log file if specified
    let mut log_file = if let Some(ref log_path) = args.log {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        println!(
            "  {} {}",
            "📝 Logging to:".bright_white(),
            log_path.display().to_string().bright_cyan()
        );
        Some(file)
    } else {
        None
    };

    // Create a channel to receive events
    let (tx, rx) = channel();

    // Create a watcher
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

    // Watch all specified paths
    let mode = if args.recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };

    for path in &args.paths {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        println!(
            "{} {} {}",
            "👁️ ".bright_cyan(),
            "Watching:".bright_white().bold(),
            canonical.display().to_string().bright_cyan()
        );
        watcher.watch(path, mode)?;
    }

    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bright_black()
    );
    println!(
        "{}",
        "  Press Ctrl+C to end mission and see summary..."
            .bright_black()
            .italic()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bright_black()
    );
    println!();

    write_to_log(&mut log_file, "=== EyeSpy Mission Started ===");

    let mut suspicious_detector = SuspiciousDetector::new();

    // Process events
    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                // Check each path in the event
                for path in &event.paths {
                    // Skip ignored patterns
                    if should_ignore(path, args.stealth, &args.ignore_patterns) {
                        continue;
                    }

                    // Check event type filter
                    if !event_matches_filter(&event.kind, &args.only_events) {
                        continue;
                    }

                    stats.record_event(&event.kind);

                    let timestamp = Local::now().format("%H:%M:%S%.3f");
                    let eye = get_mini_eye(&event.kind);

                    // Check for spy pattern match
                    let is_spy_hit = matches_spy_pattern(path, &args.spy_patterns);
                    if is_spy_hit {
                        stats.spy_hits += 1;
                    }

                    // Check for suspicious activity
                    let suspicious_alerts = if args.suspicious {
                        suspicious_detector.check(path, &event.kind)
                    } else {
                        vec![]
                    };

                    if !suspicious_alerts.is_empty() {
                        stats.suspicious_events += suspicious_alerts.len() as u64;
                    }

                    if args.debug {
                        println!(
                            "{} {} {:?}",
                            "🔍 DEBUG:".bright_magenta().bold(),
                            format!("[{}]", timestamp).bright_black(),
                            event
                        );
                    }

                    // Print with spy highlight if matched
                    if is_spy_hit {
                        println!(
                            "{} {} {} {}",
                            "🎯".bright_magenta().bold(),
                            format!("[{}]", timestamp).bright_black(),
                            format_event_kind(&event.kind),
                            "★ SPY HIT ★".bright_magenta().bold().on_black()
                        );
                    } else {
                        println!(
                            "{} {} {}",
                            eye.bright_cyan(),
                            format!("[{}]", timestamp).bright_black(),
                            format_event_kind(&event.kind),
                        );
                    }

                    // Print path
                    let path_str = path.display().to_string();
                    let (dir, file) = if let Some(parent) = path.parent() {
                        (
                            format!("{}/", parent.display()),
                            path.file_name()
                                .map(|f| f.to_string_lossy().to_string())
                                .unwrap_or_default(),
                        )
                    } else {
                        (String::new(), path_str.clone())
                    };

                    let file_display = if is_spy_hit {
                        file.bright_magenta().bold().underline()
                    } else {
                        file.bright_white().bold()
                    };

                    println!(
                        "   {} {}{}",
                        "└──".bright_black(),
                        dir.bright_black(),
                        file_display
                    );

                    // Print suspicious alerts
                    for alert in &suspicious_alerts {
                        println!("{}", EYE_ALERT.bright_red());
                        println!(
                            "   {} {} {}",
                            "🚨".bright_red(),
                            "SUSPICIOUS:".bright_red().bold(),
                            alert.bright_red()
                        );
                    }

                    println!();

                    // Log to file
                    let log_msg = format!(
                        "{:?} - {}{}{}",
                        event.kind,
                        path_str,
                        if is_spy_hit { " [SPY HIT]" } else { "" },
                        if !suspicious_alerts.is_empty() {
                            format!(" [SUSPICIOUS: {}]", suspicious_alerts.join(", "))
                        } else {
                            String::new()
                        }
                    );
                    write_to_log(&mut log_file, &log_msg);
                }
            }
            Ok(Err(e)) => {
                println!(
                    "{} {} {}",
                    "⚠️ ".bright_red(),
                    "Error:".bright_red().bold(),
                    e.to_string().red()
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Just continue, allows us to check running flag
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    write_to_log(&mut log_file, "=== EyeSpy Mission Ended ===");
    stats.print_summary();

    Ok(())
}

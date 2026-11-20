use std::collections::{HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use std::fs;

macro_rules! outln {
    ($out:expr, $($arg:tt)*) => {{
        if let Err(e) = writeln!($out, $($arg)*) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }
        }
    }};
}

// Reporting variant for the kill path. A closed pipe (`lport kill 3000 8080 | head -1`)
// must not abort the run: the remaining ports still have to be signaled, and the exit
// code still has to reflect what happened. Kill output is best-effort; the signals are not.
macro_rules! outln_soft {
    ($out:expr, $($arg:tt)*) => {{
        let _ = writeln!($out, $($arg)*);
    }};
}

#[derive(Default, Clone)]
struct Stats {
    cpu: String,
    mem: String,
    uptime: String,
    // Raw values behind the display strings, used by --sort.
    // None when unknown (e.g. docker rows outside info mode, foreign processes).
    cpu_pct: Option<f64>,
    mem_bytes: Option<u64>,
    uptime_secs: Option<u64>,
    threads: Option<u32>,
    user: Option<String>,
}

#[derive(Clone)]
struct DockerInfo {
    name: String,
    image: String,
    running_for: String,
    work_dir: Option<String>,
    container_port: u32,
    // Host address the port is published on ("0.0.0.0", "::", "192.168.1.10").
    // A container published on one address must not claim a listener bound to a
    // different one on the same port.
    host_ip: String,
    // `com.docker.compose.project` label. Used to group sibling containers of
    // the same compose project (e.g. all `supabase_*_helchang` rows) under one
    // visual block.
    compose_project: Option<String>,
}

struct Entry {
    proto: &'static str,
    port: u32,
    pid: Option<u32>,
    process: String,
    // Bind address for display, scope suffix kept ("127.0.0.1", "::", "*",
    // "0.0.0.0%virbr0"). Distinct from the match key in `split_bind_addr`, which
    // strips the scope.
    addr: String,
    cwd: String,
    cmdline: String,
    // Parent (ppid, cmdline). Filled only in info mode — see enrich_parent_info —
    // so the dashboard and kill paths pay nothing for it.
    parent: Option<(u32, String)>,
    docker: Option<DockerInfo>,
    stats: Stats,
    user_launched: bool,
}

#[derive(Debug, PartialEq)]
enum Mode {
    Dashboard { dev: bool },
    Info { ports: Vec<u32> },
    Kill { ports: Vec<u32>, force: bool, yes: bool },
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum SortKey {
    Port,
    Pid,
    Process,
    Cpu,
    Mem,
    Uptime,
}

#[derive(Debug, PartialEq)]
struct Cli {
    mode: Mode,
    sort: Option<SortKey>,
}

fn main() {
    // args_os + lossy: `std::env::args()` panics on non-UTF8 arguments, which is
    // a crash where an "unknown argument" error is the right answer.
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("lport {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let cli = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(2);
        }
    };
    let docker_map = load_docker_ports();

    let mut entries = collect_listening(&docker_map, true);

    entries.sort_by(|a, b| {
        (a.port, a.proto, a.pid.unwrap_or(0)).cmp(&(b.port, b.proto, b.pid.unwrap_or(0)))
    });
    // Only dedup rows whose PID is known. `None == None` is not "the same process",
    // it is "two processes lport cannot see" (root-owned listeners without sudo) —
    // each row is a distinct socket, and merging them hides a listener.
    //
    // Docker rows are the exception: a container published on both stacks (docker's
    // default: `0.0.0.0:P` + `[::]:P`) yields two listeners carrying identical
    // container information and a docker-proxy PID that only differs under sudo, so
    // merging by container identity hides nothing, and docker rows are never kill
    // targets.
    //
    // A merged row must still carry every address it now stands for: `127.0.0.1`-only
    // and `[::]` (all interfaces) have very different exposure, and collapsing them to
    // the first address alone would misreport a public listener as loopback-only. So
    // `dedup_by` accumulates the removed row's addr onto the kept row (`b`).
    entries.dedup_by(|a, b| {
        let same = a.port == b.port
            && a.proto == b.proto
            && match (&a.docker, &b.docker) {
                (Some(da), Some(db)) => da.name == db.name && da.container_port == db.container_port,
                _ => a.pid.is_some() && a.pid == b.pid,
            };
        if same && !a.addr.is_empty() && !b.addr.split(", ").any(|s| s == a.addr) {
            if !b.addr.is_empty() {
                b.addr.push_str(", ");
            }
            b.addr.push_str(&a.addr);
        }
        same
    });

    // Info / Kill modes are single-port queries, so filter before the per-PID
    // enrich steps. Otherwise `lport info 8080` pays the cost of reading /proc
    // (or calling ps/lsof) for every listener on the box.
    if let Mode::Info { ports } | Mode::Kill { ports, .. } = &cli.mode {
        entries.retain(|e| ports.contains(&e.port));
    }

    // Pass 1 (cheap, every listener): tty + exe only, to decide user_launched.
    // The default dashboard filters on this, so it must run before the filter.
    enrich_user_launched(&mut entries);

    if let Mode::Dashboard { dev: false } = &cli.mode {
        entries.retain(|e| e.docker.is_some() || e.user_launched);
    }

    // Pass 2: cwd for the rows that survived the filter (dashboard JOB column,
    // kill prompt identity, info CWD row). Reading cwd for every system daemon
    // just to hide it again in the default view is wasted work.
    enrich_cwd(&mut entries);

    if let Mode::Kill { ports, force, yes } = &cli.mode {
        let code = run_kill(&entries, ports, *force, *yes, &docker_map);
        maybe_print_update_notice();
        std::process::exit(code);
    }

    enrich_local_stats(&mut entries);
    let with_docker_cpu_mem = matches!(cli.mode, Mode::Info { .. });
    enrich_docker_stats(&mut entries, with_docker_cpu_mem);

    // Sort AFTER the stats passes: --sort cpu/mem/uptime reads the raw Stats
    // values, which are only populated above. Default order is by visual group
    // key (compose project if present, else container name for docker, else cwd
    // for local), then container name for determinism within a group, then
    // port/proto — keeps docker [ project ] blocks adjacent. `--sort KEY`
    // replaces this with a global row sort.
    match cli.sort {
        Some(key) => sort_entries(&mut entries, key),
        None => entries.sort_by(|a, b| {
            let group_a = group_key(a);
            let group_b = group_key(b);
            let name_a = a.docker.as_ref().map(|d| d.name.as_str()).unwrap_or("");
            let name_b = b.docker.as_ref().map(|d| d.name.as_str()).unwrap_or("");
            (group_a, name_a, a.port, a.proto).cmp(&(group_b, name_b, b.port, b.proto))
        }),
    }

    match &cli.mode {
        Mode::Info { ports } => {
            // cmdline + parent are info-only: the dashboard never displays them,
            // so paying for them on every run would be pure waste.
            enrich_cmdline(&mut entries);
            enrich_parent_info(&mut entries);
            let code = print_info(&entries, ports);
            maybe_print_update_notice();
            std::process::exit(code);
        }
        Mode::Dashboard { dev } => print_table(&entries, *dev, cli.sort.is_none()),
        // Kill mode already exited via `run_kill` above; this arm exists only
        // to satisfy exhaustiveness.
        Mode::Kill { .. } => unreachable!(),
    }

    maybe_print_update_notice();
}

fn print_help() {
    println!("Usage: lport [--dev] [--sort KEY]");
    println!("       lport PORT [PORT ...]");
    println!("       lport info PORT [PORT ...]");
    println!("       lport kill PORT [PORT ...] [-9|--force] [-y|--yes]");
    println!();
    println!("  (default)        Show user-launched servers and Docker containers only");
    println!("                   (PROTO PORT ADDR PID PROCESS JOB CPU MEM UPTIME)");
    println!("  --dev            Show every listening port, including system daemons");
    println!("  --sort KEY       Sort dashboard rows by KEY: port, pid, process, cpu, mem,");
    println!("                   uptime (cpu/mem/uptime largest first; disables the docker");
    println!("                   [ project ] group headers)");
    println!("  PORT...          Shorthand for `lport info PORT...`");
    println!("  info PORT...     Show full details for the given port(s),");
    println!("                   including Docker container CPU/MEM");
    println!("                   example: lport info 8080 5432");
    println!("  kill PORT...     Terminate the process(es) listening on the given port(s).");
    println!("                   Sends SIGTERM by default; pass -9 / --force for SIGKILL.");
    println!("                   Prompts [y/N] for each process before signaling.");
    println!("                   Pass -y / --yes to skip the prompt (non-interactive).");
    println!("                   Verifies the process actually exited; offers SIGKILL");
    println!("                   escalation if it survives SIGTERM.");
    println!("                   Docker-backed ports are not killed; lport offers");
    println!("                   `docker stop` interactively (or prints the command");
    println!("                   when non-interactive).");
    println!("                   example: lport kill 3000 8080");
    println!("  -V, --version    Print version and exit");
    println!("  -h, --help       Print this help and exit");
    println!();
    println!("Permissions:");
    println!("  Processes owned by other users require elevated privileges to inspect");
    println!("  or kill:");
    println!("    Linux:  PID/PROCESS appear as '?' without sudo.");
    println!("    macOS:  other users' listeners are hidden entirely without sudo.");
    println!("  Run with `sudo lport` for full visibility across users.");
}

enum Confirm {
    Yes,
    No,
    NoTty,
}

/// Prompt the user to confirm killing a single process. Returns `Yes` only on an
/// explicit "y"/"yes". A non-interactive stdin (pipe, no TTY) cannot answer, so
/// it returns `NoTty` and refuses rather than killing silently — same instinct
/// as `rm -i`.
///
/// The prompt goes to stderr: stdout carries the result lines and may be piped,
/// which would otherwise leave the caller staring at a silent read.
fn confirm_kill(entry: &Entry, port: u32, signal_name: &str) -> Confirm {
    if !io::stdin().is_terminal() {
        return Confirm::NoTty;
    }
    let pid = entry.pid.unwrap_or(0);
    let cwd = if entry.cwd.is_empty() { "-" } else { &entry.cwd };
    match prompt_yes_no(&format!(
        "Kill pid {} ({}) on {}/{} [cwd: {}] with {}? [y/N] ",
        pid, entry.process, entry.proto, port, cwd, signal_name
    )) {
        Some(true) => Confirm::Yes,
        Some(false) => Confirm::No,
        // A stderr that cannot be written to is a stderr the user cannot read: consent
        // is unobtainable, exactly as with no TTY. Refuse through the same path.
        None => Confirm::NoTty,
    }
}

/// `None` means the question could not be asked. Never exits: a dead prompt must not
/// cut the kill run short with a success code — the caller decides, and its answer is
/// always to refuse.
fn prompt_yes_no(prompt: &str) -> Option<bool> {
    let mut err = io::stderr();
    if write!(err, "{}", prompt).is_err() {
        return None;
    }
    let _ = err.flush();
    let mut answer = String::new();
    Some(
        io::stdin().read_line(&mut answer).is_ok()
            && matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES"),
    )
}

// A signal is only *delivered*, never *obeyed*: a process can ignore SIGTERM, and
// even SIGKILL cannot reap one stuck in uninterruptible I/O. So `lport kill` waits
// for the PID to actually disappear before it claims the port is free.
const KILL_WAIT_MS: u64 = 3000;
const ESCALATE_WAIT_MS: u64 = 2000;

#[cfg(target_os = "linux")]
fn pid_alive(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid)) else {
        return false;
    };
    let Some(rparen) = stat.rfind(')') else {
        return false;
    };
    let state = stat[rparen + 1..].split_whitespace().next().unwrap_or("");
    // A zombie (or dying) process has already released its sockets — the port is
    // free even though the /proc entry lingers until the parent reaps it.
    !matches!(state, "Z" | "X")
}

#[cfg(target_os = "macos")]
fn pid_alive(pid: u32) -> bool {
    // Not `kill -0`: that succeeds for a zombie, and a zombie has already released
    // its sockets — the port is free even though the entry lingers until the parent
    // reaps it. BSD `ps` reports zombies with a state starting in 'Z'.
    let Ok(output) = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let state = String::from_utf8_lossy(&output.stdout);
    let state = state.trim();
    !state.is_empty() && !state.starts_with('Z')
}

/// Poll until the PID is gone. Returns true if the exit was observed.
fn wait_for_exit(pid: u32, timeout_ms: u64) -> bool {
    let mut waited = 0;
    while waited < timeout_ms {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
        waited += 100;
    }
    !pid_alive(pid)
}

// `kill` writes its own diagnostic ("Operation not permitted", "No such process")
// to stderr. It is captured rather than inherited so it cannot interleave with
// lport's output, then replayed under the failing port.
fn report_kill_failure(
    err: &mut impl Write,
    proto: &str,
    port: u32,
    pid: u32,
    signal_flag: &str,
    status: std::process::ExitStatus,
    stderr_bytes: &[u8],
) {
    outln_soft!(
        err,
        "port {}/{}: `kill {} {}` exited with status {}.",
        proto,
        port,
        signal_flag,
        pid,
        status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "?".into())
    );
    let detail = String::from_utf8_lossy(stderr_bytes);
    let detail = detail.trim();
    if !detail.is_empty() {
        outln_soft!(err, "  {}", detail);
        if detail.to_ascii_lowercase().contains("not permitted") {
            outln_soft!(err, "hint: try `sudo lport kill {}`", port);
        }
    }
}

fn run_kill(
    entries: &[Entry],
    ports: &[u32],
    force: bool,
    yes: bool,
    docker_map: &DockerMap,
) -> i32 {
    let signal_flag = if force { "-KILL" } else { "-TERM" };
    let signal_name = if force { "SIGKILL" } else { "SIGTERM" };
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let mut any_error = false;
    // Dedup across ports: a single PID listening on tcp+udp or on multiple
    // ports given on one command line should only receive one signal. Only
    // PIDs actually signaled (or confirmed already exited) belong here.
    let mut signaled: HashSet<u32> = HashSet::new();
    // PIDs the user declined at the prompt: skip them on later ports without
    // claiming they were handled — no signal was ever sent.
    let mut declined: HashSet<u32> = HashSet::new();
    // PIDs whose first signal could not be delivered (EPERM, `kill` failed to spawn).
    // Same reason as `declined`: nothing reached the process, so "already handled"
    // would be a lie on the next port.
    let mut failed: HashSet<u32> = HashSet::new();
    // Ports whose owner was confirmed dead — the only ones worth re-scanning for
    // a supervisor-spawned replacement.
    let mut freed_ports: HashSet<u32> = HashSet::new();
    // PIDs confirmed dead. A PID holding several of the requested ports is signaled once,
    // so the later ports never reach a `freed_ports.insert` of their own — but they were
    // freed too, and a supervisor can take any of them back.
    let mut dead: HashSet<u32> = HashSet::new();
    // Containers already `docker stop`ped / skipped this run: the same container can back
    // several requested ports (or tcp+udp), and each decision is made once.
    let mut stopped_containers: HashSet<String> = HashSet::new();
    let mut skipped_containers: HashSet<String> = HashSet::new();

    for &port in ports {
        let matches: Vec<&Entry> = entries.iter().filter(|e| e.port == port).collect();
        if matches.is_empty() {
            outln_soft!(err, "port {}: no listening process found.", port);
            any_error = true;
            continue;
        }

        for entry in &matches {
            if let Some(d) = &entry.docker {
                if stopped_containers.contains(&d.name) {
                    outln_soft!(out, "container '{}' already stopped.", d.name);
                    continue;
                }
                if skipped_containers.contains(&d.name) {
                    outln_soft!(out, "skipped container '{}' earlier.", d.name);
                    continue;
                }
                // A container is not killed like a process — stopping it is a container
                // lifecycle action. Offer it interactively; `-y` deliberately does NOT
                // auto-stop containers, since a script clearing a port should not tear
                // down a container as a side effect.
                let interactive = !yes && io::stdin().is_terminal();
                if !interactive {
                    outln_soft!(
                        err,
                        "port {}/{}: owned by Docker container '{}'. Use: docker stop {}",
                        entry.proto,
                        port,
                        d.name,
                        d.name
                    );
                    any_error = true;
                    continue;
                }
                match prompt_yes_no(&format!(
                    "port {}/{} is owned by Docker container '{}'. Stop the container? [y/N] ",
                    entry.proto, port, d.name
                )) {
                    Some(true) => {
                        match Command::new("docker").args(["stop", &d.name]).output() {
                            Ok(o) if o.status.success() => {
                                stopped_containers.insert(d.name.clone());
                                outln_soft!(
                                    out,
                                    "stopped container '{}' ({}/{}).",
                                    d.name,
                                    entry.proto,
                                    port
                                );
                            }
                            Ok(o) => {
                                outln_soft!(
                                    err,
                                    "port {}/{}: `docker stop {}` exited with status {}.",
                                    entry.proto,
                                    port,
                                    d.name,
                                    o.status
                                        .code()
                                        .map(|c| c.to_string())
                                        .unwrap_or_else(|| "?".into())
                                );
                                let detail = String::from_utf8_lossy(&o.stderr);
                                let detail = detail.trim();
                                if !detail.is_empty() {
                                    outln_soft!(err, "  {}", detail);
                                }
                                any_error = true;
                            }
                            Err(e) => {
                                outln_soft!(
                                    err,
                                    "port {}/{}: failed to spawn `docker`: {}.",
                                    entry.proto,
                                    port,
                                    e
                                );
                                any_error = true;
                            }
                        }
                    }
                    Some(false) => {
                        skipped_containers.insert(d.name.clone());
                        outln_soft!(out, "skipped container '{}'. Use: docker stop {}", d.name, d.name);
                    }
                    None => {
                        outln_soft!(
                            err,
                            "port {}/{}: owned by Docker container '{}'. Use: docker stop {}",
                            entry.proto,
                            port,
                            d.name,
                            d.name
                        );
                        any_error = true;
                    }
                }
                continue;
            }
            let Some(pid) = entry.pid else {
                outln_soft!(
                    err,
                    "port {}/{}: PID unknown (insufficient privileges?). Try `sudo lport kill {}`.",
                    entry.proto,
                    port,
                    port
                );
                any_error = true;
                continue;
            };
            if signaled.contains(&pid) {
                // Same PID, another requested port: it was freed by the same signal, so it
                // belongs in the restart re-scan even though nothing was signaled here.
                if dead.contains(&pid) {
                    freed_ports.insert(port);
                }
                outln_soft!(
                    out,
                    "pid {} already handled (also listens on {}/{}).",
                    pid,
                    entry.proto,
                    port
                );
                continue;
            }
            if declined.contains(&pid) {
                outln_soft!(out, "pid {} declined earlier; skipping {}/{}.", pid, entry.proto, port);
                continue;
            }
            if failed.contains(&pid) {
                outln_soft!(
                    out,
                    "pid {} could not be signaled earlier; skipping {}/{}.",
                    pid,
                    entry.proto,
                    port
                );
                continue;
            }
            // Confirm before signaling so a mistyped port cannot take down the
            // wrong process. Show enough identity (pid, name, cwd) to verify.
            // `-y`/`--yes` skips the prompt for non-interactive callers (scripts,
            // service managers) that cannot answer a TTY question.
            let decision = if yes {
                Confirm::Yes
            } else {
                confirm_kill(entry, port, signal_name)
            };
            match decision {
                Confirm::Yes => {}
                Confirm::No => {
                    declined.insert(pid);
                    outln_soft!(out, "skipped pid {} ({}).", pid, entry.process);
                    continue;
                }
                Confirm::NoTty => {
                    declined.insert(pid);
                    outln_soft!(
                        err,
                        "port {}/{}: refusing to kill pid {} ({}) without confirmation (no TTY).",
                        entry.proto,
                        port,
                        pid,
                        entry.process
                    );
                    any_error = true;
                    continue;
                }
            }
            // The prompt above blocks indefinitely; the process may have exited while
            // the user was deciding. Signaling a dead PID fails with "No such process",
            // which would report a failure for a port that is in fact free.
            if !pid_alive(pid) {
                signaled.insert(pid);
                outln_soft!(out, "pid {} ({}) already exited.", pid, entry.process);
                freed_ports.insert(port);
                dead.insert(pid);
                continue;
            }
            signaled.insert(pid);
            let output = Command::new("kill")
                .args([signal_flag, &pid.to_string()])
                .output();
            match output {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    signaled.remove(&pid);
                    failed.insert(pid);
                    report_kill_failure(
                        &mut err,
                        entry.proto,
                        port,
                        pid,
                        signal_flag,
                        o.status,
                        &o.stderr,
                    );
                    any_error = true;
                    continue;
                }
                Err(spawn_err) => {
                    signaled.remove(&pid);
                    failed.insert(pid);
                    outln_soft!(
                        err,
                        "port {}/{}: failed to spawn `kill`: {}.",
                        entry.proto,
                        port,
                        spawn_err
                    );
                    any_error = true;
                    continue;
                }
            }

            if wait_for_exit(pid, KILL_WAIT_MS) {
                outln_soft!(
                    out,
                    "killed pid {} ({}) on {}/{} [{}]",
                    pid,
                    entry.process,
                    entry.proto,
                    port,
                    signal_name
                );
                freed_ports.insert(port);
                dead.insert(pid);
                continue;
            }

            if force {
                outln_soft!(
                    err,
                    "port {}/{}: pid {} ({}) still alive {}s after SIGKILL (uninterruptible I/O?).",
                    entry.proto,
                    port,
                    pid,
                    entry.process,
                    KILL_WAIT_MS / 1000
                );
                any_error = true;
                continue;
            }

            outln_soft!(
                err,
                "port {}/{}: pid {} ({}) still alive {}s after SIGTERM.",
                entry.proto,
                port,
                pid,
                entry.process,
                KILL_WAIT_MS / 1000
            );
            if yes || !io::stdin().is_terminal() {
                outln_soft!(err, "hint: retry with `lport kill -9 {}`", port);
                any_error = true;
                continue;
            }
            if !matches!(prompt_yes_no("Escalate to SIGKILL? [y/N] "), Some(true)) {
                outln_soft!(out, "skipped escalation for pid {} ({}).", pid, entry.process);
                any_error = true;
                continue;
            }
            // A slow-but-obedient process can finish shutting down while the escalation
            // prompt waits — SIGTERM worked, it just took longer than KILL_WAIT_MS.
            if !pid_alive(pid) {
                outln_soft!(
                    out,
                    "pid {} ({}) exited on its own after SIGTERM.",
                    pid,
                    entry.process
                );
                freed_ports.insert(port);
                dead.insert(pid);
                continue;
            }
            let output = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .output();
            match output {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    report_kill_failure(
                        &mut err,
                        entry.proto,
                        port,
                        pid,
                        "-KILL",
                        o.status,
                        &o.stderr,
                    );
                    any_error = true;
                    continue;
                }
                Err(spawn_err) => {
                    outln_soft!(
                        err,
                        "port {}/{}: failed to spawn `kill`: {}.",
                        entry.proto,
                        port,
                        spawn_err
                    );
                    any_error = true;
                    continue;
                }
            }
            if wait_for_exit(pid, ESCALATE_WAIT_MS) {
                outln_soft!(
                    out,
                    "killed pid {} ({}) on {}/{} [SIGKILL]",
                    pid,
                    entry.process,
                    entry.proto,
                    port
                );
                freed_ports.insert(port);
                dead.insert(pid);
            } else {
                outln_soft!(
                    err,
                    "port {}/{}: pid {} ({}) still alive {}s after SIGKILL (uninterruptible I/O?).",
                    entry.proto,
                    port,
                    pid,
                    entry.process,
                    ESCALATE_WAIT_MS / 1000
                );
                any_error = true;
            }
        }
    }

    warn_on_restart(&mut err, &freed_ports, &signaled, &declined, &failed, docker_map);

    if any_error {
        1
    } else {
        0
    }
}

// A freed port that is listening again seconds later was not freed for the user:
// something (nodemon, a systemd unit, docker restart policy) put a new process
// there. The kill itself succeeded, so this warns without failing the exit code.
fn warn_on_restart(
    err: &mut impl Write,
    freed_ports: &HashSet<u32>,
    signaled: &HashSet<u32>,
    declined: &HashSet<u32>,
    failed: &HashSet<u32>,
    docker_map: &DockerMap,
) {
    if freed_ports.is_empty() {
        return;
    }
    std::thread::sleep(Duration::from_millis(500));
    let mut warned: HashSet<(&'static str, u32, u32)> = HashSet::new();
    for e in collect_listening(docker_map, false) {
        if e.docker.is_some() || !freed_ports.contains(&e.port) {
            continue;
        }
        let Some(pid) = e.pid else { continue };
        // A declined PID — or one whose signal never got delivered — was on the port all
        // along. Neither is a supervisor reviving anything, so neither deserves a restart
        // warning; the port simply still belongs to whoever already had it.
        if signaled.contains(&pid)
            || declined.contains(&pid)
            || failed.contains(&pid)
            || !warned.insert((e.proto, e.port, pid))
        {
            continue;
        }
        outln_soft!(
            err,
            "warning: port {}/{} is listening again (pid {}, {}) — likely restarted by a supervisor (dev server, systemd). Inspect with `lport info {}`.",
            e.proto,
            e.port,
            pid,
            e.process,
            e.port
        );
    }
}

const SORT_KEYS_HINT: &str = "port, pid, process, cpu, mem, uptime";

// Split the global flag `--sort KEY` out of the argument list first, so it may
// appear in any position (`lport --sort mem`, `lport --dev --sort mem`).
// What remains is parsed as before.
fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut sort = None;
    let mut rest: Vec<String> = Vec::with_capacity(args.len());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--sort" => {
                let Some(key) = it.next() else {
                    return Err(format!("--sort requires a key ({})", SORT_KEYS_HINT));
                };
                sort = Some(match key.as_str() {
                    "port" => SortKey::Port,
                    "pid" => SortKey::Pid,
                    "process" => SortKey::Process,
                    "cpu" => SortKey::Cpu,
                    "mem" => SortKey::Mem,
                    "uptime" => SortKey::Uptime,
                    _ => {
                        return Err(format!(
                            "invalid sort key '{}' (expected {})",
                            key, SORT_KEYS_HINT
                        ));
                    }
                });
            }
            _ => rest.push(a.clone()),
        }
    }
    let mode = parse_mode(&rest)?;
    if let Mode::Kill { .. } = &mode
        && sort.is_some()
    {
        return Err("--sort cannot be used with kill".to_string());
    }
    Ok(Cli { mode, sort })
}

fn parse_mode(args: &[String]) -> Result<Mode, String> {
    // A subcommand is only a subcommand in first position. Matching it anywhere
    // turns `lport kill 8080 info` into "unknown argument 'kill'" instead of the
    // real complaint, which is the stray `info`.
    let subcommand = args.first().map(String::as_str);

    // `lport 8080` is shorthand for `lport info 8080`: if the first argument is a
    // port number, treat every argument as a port. `--dev` / `info` / `kill` still
    // win because they do not parse as a port.
    let shorthand_info = args
        .first()
        .and_then(|a| a.parse::<u32>().ok())
        .is_some_and(|p| (1..=65535).contains(&p));

    if subcommand == Some("info") || shorthand_info {
        let port_args = if shorthand_info { args } else { &args[1..] };
        let mut ports: Vec<u32> = Vec::new();
        for a in port_args {
            match a.parse::<u32>() {
                Ok(p) if (1..=65535).contains(&p) => ports.push(p),
                _ => return Err(format!("invalid port '{}'", a)),
            }
        }
        if ports.is_empty() {
            return Err("'lport info' requires at least one port number.".to_string());
        }
        return Ok(Mode::Info { ports });
    }

    if subcommand == Some("kill") {
        let mut ports: Vec<u32> = Vec::new();
        let mut force = false;
        let mut yes = false;
        for a in &args[1..] {
            match a.as_str() {
                "-9" | "--force" => force = true,
                "-y" | "--yes" => yes = true,
                _ => match a.parse::<u32>() {
                    Ok(p) if (1..=65535).contains(&p) => ports.push(p),
                    _ => return Err(format!("invalid port '{}'", a)),
                },
            }
        }
        if ports.is_empty() {
            return Err("'lport kill' requires at least one port number.".to_string());
        }
        return Ok(Mode::Kill { ports, force, yes });
    }

    let mut dev = false;
    for a in args {
        match a.as_str() {
            "--dev" => dev = true,
            _ => return Err(format!("unknown argument '{}'", a)),
        }
    }
    Ok(Mode::Dashboard { dev })
}

// Global row sort for `--sort KEY`. port/pid/process ascend; cpu/mem/uptime put
// the largest first (the "who is eating my machine" question), unknowns last.
fn sort_entries(entries: &mut [Entry], key: SortKey) {
    entries.sort_by(|a, b| {
        match key {
            SortKey::Port => a.port.cmp(&b.port).then_with(|| a.proto.cmp(b.proto)),
            SortKey::Pid => cmp_opt(a.pid, b.pid, false).then_with(|| a.port.cmp(&b.port)),
            SortKey::Process => a
                .process
                .cmp(&b.process)
                .then_with(|| a.port.cmp(&b.port)),
            SortKey::Cpu => cmp_opt(a.stats.cpu_pct, b.stats.cpu_pct, true)
                .then_with(|| a.port.cmp(&b.port)),
            SortKey::Mem => cmp_opt(a.stats.mem_bytes, b.stats.mem_bytes, true)
                .then_with(|| a.port.cmp(&b.port)),
            SortKey::Uptime => cmp_opt(a.stats.uptime_secs, b.stats.uptime_secs, true)
                .then_with(|| a.port.cmp(&b.port)),
        }
    });
}

// Option comparison: Some < None always (unknowns last), direction flips the
// value order for `desc`.
fn cmp_opt<T: PartialOrd>(a: Option<T>, b: Option<T>, desc: bool) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Some(x), Some(y)) => {
            let ord = x.partial_cmp(&y).unwrap_or(Ordering::Equal);
            if desc { ord.reverse() } else { ord }
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn is_interpreter_exe(name: &str) -> bool {
    // Strip trailing version digits / dots (e.g. "python3.11" -> "python")
    let stem: String = name
        .chars()
        .take_while(|c| !c.is_ascii_digit() && *c != '.')
        .collect();
    matches!(
        stem.as_str(),
        "python"
            | "node"
            | "deno"
            | "bun"
            | "ruby"
            | "java"
            | "php"
            | "php-fpm"
            | "perl"
            | "dotnet"
            | "erl"
            | "beam"
            | "uvicorn"
            | "gunicorn"
            | "hypercorn"
            | "daphne"
            | "puma"
            | "unicorn"
            | "rails"
    )
}

// One host (proto, port) can carry several publishes — `-p 127.0.0.1:8080:80`
// and `-p 192.168.1.10:8080:80` on different containers coexist — so the value
// is a list and the bind address decides which one owns a given listener.
type DockerMap = HashMap<(&'static str, u32), Vec<DockerInfo>>;

// Bind address of a socket string: "0.0.0.0:8080" -> "0.0.0.0",
// "[::]:8080" -> "::", "*:5353" -> "*".
//
// `ss` appends a scope/interface to addresses bound to one link ("0.0.0.0%virbr0:67",
// "[fe80::1%eth0]:8080"). Docker never reports it, so the suffix is dropped —
// otherwise "0.0.0.0%virbr0" fails the wildcard test and no address ever compares equal.
fn split_bind_addr(local: &str) -> &str {
    match local.rfind(':') {
        Some(i) => {
            let addr = local[..i].trim_start_matches('[').trim_end_matches(']');
            addr.split('%').next().unwrap_or(addr)
        }
        None => "",
    }
}

// Bind address for display: like `split_bind_addr` but keeps the `%scope` suffix,
// since which interface a socket is bound to is information the user wants to see.
fn display_bind_addr(local: &str) -> &str {
    match local.rfind(':') {
        Some(i) => local[..i].trim_start_matches('[').trim_end_matches(']'),
        None => "",
    }
}

fn is_wildcard_addr(a: &str) -> bool {
    matches!(a, "" | "0.0.0.0" | "::" | "*")
}

// A socket bound to a v4-mapped v6 address is reported as "::ffff:127.0.0.1"
// while docker reports the plain "127.0.0.1"; compare them on equal terms.
fn normalize_addr(a: &str) -> &str {
    a.strip_prefix("::ffff:").unwrap_or(a)
}

fn ip_matches(docker_ip: &str, local_addr: &str) -> bool {
    let d = normalize_addr(docker_ip);
    let l = normalize_addr(local_addr);
    // "*" / empty carry no stack information (macOS lsof prints "*:port").
    if d.is_empty() || d == "*" || l.is_empty() || l == "*" {
        return true;
    }
    // A v4 publish must not claim a v6 listener (or vice versa): they are
    // different sockets that merely share a port number.
    if d.contains(':') != l.contains(':') {
        return false;
    }
    d == l || is_wildcard_addr(d) || is_wildcard_addr(l)
}

// Known limit: with `userland-proxy: false` there is no docker-proxy listener behind a
// published port (iptables does the routing), so an unrelated local process on that port
// matches the publish and is shown as the container. Verifying the listener's comm would
// fix that case but break the legitimate ones (rootless docker, Docker Desktop), so the
// mismatch is documented in the README rather than guessed at here.
fn docker_lookup(
    map: &DockerMap,
    proto: &'static str,
    port: u32,
    local_addr: &str,
) -> Option<DockerInfo> {
    map.get(&(proto, port))?
        .iter()
        .find(|d| ip_matches(&d.host_ip, local_addr))
        .cloned()
}

fn load_docker_ports() -> DockerMap {
    let mut map: DockerMap = HashMap::new();
    let output = match Command::new("docker")
        .args([
            "ps",
            "--format",
            "{{.Names}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project.working_dir\"}}\t{{.Image}}\t{{.RunningFor}}\t{{.Label \"com.docker.compose.project\"}}",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return map,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let mut parts = line.splitn(6, '\t');
        let Some(name) = parts.next() else { continue };
        let Some(ports) = parts.next() else { continue };
        let work_dir = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let image = parts.next().unwrap_or("-").to_string();
        let running_for = parts.next().unwrap_or("-").to_string();
        let compose_project = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        for segment in ports.split(',') {
            let seg = segment.trim();
            let Some(arrow) = seg.find("->") else { continue };
            let left = &seg[..arrow];
            let right = &seg[arrow + 2..];
            // right looks like "80/tcp" or "80-82/udp"
            let mut right_parts = right.split('/');
            let cport_str = right_parts.next().unwrap_or("");
            let proto: &'static str = match right_parts.next().unwrap_or("") {
                "tcp" => "tcp",
                "udp" => "udp",
                _ => continue,
            };
            let Some(colon) = left.rfind(':') else { continue };
            let port_str = &left[colon + 1..];
            let host_ip = split_bind_addr(left);
            let (start, end) = match parse_port_range(port_str) {
                Some(r) => r,
                None => continue,
            };
            let (cstart, _cend) = parse_port_range(cport_str).unwrap_or((start, end));
            for (i, p) in (start..=end).enumerate() {
                let cp = cstart + i as u32;
                map.entry((proto, p)).or_default().push(DockerInfo {
                    name: name.to_string(),
                    image: image.clone(),
                    running_for: running_for.clone(),
                    work_dir: work_dir.clone(),
                    container_port: cp,
                    host_ip: host_ip.to_string(),
                    compose_project: compose_project.clone(),
                });
            }
        }
    }
    map
}

fn parse_port_range(s: &str) -> Option<(u32, u32)> {
    if let Some(dash) = s.find('-') {
        let a = s[..dash].parse::<u32>().ok()?;
        let b = s[dash + 1..].parse::<u32>().ok()?;
        Some((a, b))
    } else {
        let p = s.parse::<u32>().ok()?;
        Some((p, p))
    }
}

// ================================================================
// Listening port collection (platform-specific)
// ================================================================

// `strict` distinguishes the primary collection — where a failing `ss` must fail
// loudly rather than masquerade as "no ports" — from the best-effort re-scan
// `warn_on_restart` runs after a kill: that re-scan is only there to add a warning,
// so a transient `ss` failure must not flip an already-successful kill to exit 1.
#[cfg(target_os = "linux")]
fn collect_listening(docker_map: &DockerMap, strict: bool) -> Vec<Entry> {
    let mut entries = Vec::new();
    // One `ss` invocation for both stacks instead of two. With -tul combined the
    // Netid column appears ("tcp"/"udp" in field 0) and the local address moves
    // from field 3 to field 4 — parse_ss_line reads the proto from the line.
    collect_ss(&["-tulnpH"], docker_map, &mut entries, strict);
    entries
}

#[cfg(target_os = "linux")]
fn collect_ss(
    args: &[&str],
    docker_map: &DockerMap,
    out: &mut Vec<Entry>,
    strict: bool,
) {
    let output = match Command::new("ss").args(args).output() {
        Ok(o) => o,
        Err(e) => {
            if strict {
                eprintln!("error: failed to run `ss`: {}. Install iproute2 (provides `ss`).", e);
                std::process::exit(1);
            }
            return;
        }
    };
    // busybox `ss` does not support `-H` and exits non-zero instead of printing
    // rows. Parsing its empty stdout would report "no listening ports" — a wrong
    // answer that looks like a right one.
    if !output.status.success() {
        if strict {
            eprintln!(
                "error: `ss {}` failed (exit {}): {}",
                args.join(" "),
                output
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "?".into()),
                String::from_utf8_lossy(&output.stderr).trim()
            );
            std::process::exit(1);
        }
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        parse_ss_line(line, docker_map, out);
    }
}

#[cfg(target_os = "linux")]
fn parse_ss_line(
    line: &str,
    docker_map: &DockerMap,
    out: &mut Vec<Entry>,
) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    // Netid State Recv-Q Send-Q Local Peer [users]
    if fields.len() < 5 {
        return;
    }
    let proto: &'static str = match fields[0] {
        "tcp" => "tcp",
        "udp" => "udp",
        _ => return,
    };
    let local = fields[4];
    let Some(port_str) = local.rsplit(':').next() else {
        return;
    };
    let port_str = port_str.trim_end_matches(']');
    let Some(port) = port_str.parse::<u32>().ok().filter(|&p| p > 0) else {
        return;
    };

    let docker = docker_lookup(docker_map, proto, port, split_bind_addr(local));
    let addr = display_bind_addr(local).to_string();

    // `users:(...)` is the trailing column. Locate it in the raw line instead
    // of in whitespace-split tokens, because the process name inside the
    // parens can itself contain spaces (e.g. comm `next-server (v1`), which
    // would otherwise tear the token apart and hide the PID.
    let users_field = line.find("users:").map(|i| &line[i..]);
    let pairs = match users_field {
        Some(s) => parse_users(s),
        None => Vec::new(),
    };

    if pairs.is_empty() {
        out.push(Entry {
            proto,
            port,
            pid: None,
            process: "?".to_string(),
            addr,
            cwd: String::new(),
            cmdline: String::new(),
            parent: None,
            docker,
            stats: Stats::default(),
            user_launched: false,
        });
        return;
    }

    for (name, pid) in pairs {
        out.push(Entry {
            proto,
            port,
            pid: Some(pid),
            process: name,
            addr: addr.clone(),
            cwd: String::new(),
            cmdline: String::new(),
            parent: None,
            docker: docker.clone(),
            stats: Stats::default(),
            user_launched: false,
        });
    }
}

#[cfg(target_os = "linux")]
fn parse_users(s: &str) -> Vec<(String, u32)> {
    // users field looks like: users:(("name1",pid=123,fd=10),("name2",pid=456,fd=11))
    // Each entry is ("comm",pid=N,fd=M). ss does not escape quotes inside comm, so the
    // next `"` is not a reliable terminator — the literal `",pid=` sequence is. A comm
    // containing that sequence itself is unparseable and accepted as such.
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(open) = rest.find("(\"") {
        let after = &rest[open + 2..];
        let Some(end) = after.find("\",pid=") else { break };
        let name = &after[..end];
        let digits = &after[end + 6..];
        let digits_end = digits
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(digits.len());
        if let Ok(pid) = digits[..digits_end].parse::<u32>() {
            out.push((name.to_string(), pid));
        }
        rest = &digits[digits_end..];
    }
    out
}

// `_strict` is unused on macOS: `lsof` exits non-zero when nothing matches, which is
// normal, so this path never exits on a non-zero status to begin with.
//
// The `f` (fd) field is requested not for its value but as a per-socket delimiter: the
// state machine flushes one Entry per `f` record. lsof 4.94+ (the lsof-org fork, what
// Homebrew ships) only emits fields named in `-F`, so `f` must be listed explicitly —
// without it every listener is silently dropped.
#[cfg(target_os = "macos")]
fn collect_listening(docker_map: &DockerMap, _strict: bool) -> Vec<Entry> {
    let mut entries = Vec::new();
    collect_lsof(
        "tcp",
        &["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcnf"],
        docker_map,
        &mut entries,
    );
    collect_lsof("udp", &["-nP", "-iUDP", "-Fpcnf"], docker_map, &mut entries);
    entries
}

#[cfg(target_os = "macos")]
fn collect_lsof(
    proto: &'static str,
    args: &[&str],
    docker_map: &DockerMap,
    out: &mut Vec<Entry>,
) {
    let output = match Command::new("lsof").args(args).output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: failed to run `lsof`: {}.", e);
            std::process::exit(1);
        }
    };
    // lsof exits non-zero when nothing matches; that's fine, parse whatever is there.
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut cur_pid: Option<u32> = None;
    let mut cur_cmd: String = "?".to_string();
    let mut has_file = false;
    let mut cur_name: Option<String> = None;

    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        // A value with an embedded newline spills untagged continuation lines;
        // drop them (a multi-byte first char would make split_at(1) panic).
        let Some((tag, val)) = line.split_at_checked(1) else { continue };
        match tag {
            "p" => {
                if has_file {
                    flush_lsof(proto, cur_pid, &cur_cmd, &cur_name, docker_map, out);
                }
                has_file = false;
                cur_name = None;
                cur_pid = val.parse().ok();
                cur_cmd = "?".to_string();
            }
            "c" => {
                cur_cmd = val.to_string();
            }
            "f" => {
                if has_file {
                    flush_lsof(proto, cur_pid, &cur_cmd, &cur_name, docker_map, out);
                }
                has_file = true;
                cur_name = None;
            }
            "n" => {
                cur_name = Some(val.to_string());
            }
            _ => {}
        }
    }
    if has_file {
        flush_lsof(proto, cur_pid, &cur_cmd, &cur_name, docker_map, out);
    }
}

#[cfg(target_os = "macos")]
fn flush_lsof(
    proto: &'static str,
    pid: Option<u32>,
    cmd: &str,
    name: &Option<String>,
    docker_map: &DockerMap,
    out: &mut Vec<Entry>,
) {
    let Some(name) = name else { return };
    // Strip trailing " (LISTEN)" or similar parenthetical suffixes
    let name_first = name.split_whitespace().next().unwrap_or(name);
    // A connected socket looks like "local:port->remote:port"; that is not a
    // listener. `lsof -iUDP` (which has no LISTEN filter) can surface those,
    // and their trailing segment would be parsed as a local port otherwise.
    if name_first.contains("->") {
        return;
    }
    // For UDP with an idle state (e.g. "*:5353" or "*:5353 (IDLE)") we still want the addr part.
    let Some(port_str) = name_first.rsplit(':').next() else {
        return;
    };
    let port_str = port_str.trim_end_matches(']');
    let Ok(port) = port_str.parse::<u32>() else {
        return;
    };
    if port == 0 {
        return;
    }
    let docker = docker_lookup(docker_map, proto, port, split_bind_addr(name_first));
    out.push(Entry {
        proto,
        port,
        pid,
        process: cmd.to_string(),
        addr: display_bind_addr(name_first).to_string(),
        cwd: String::new(),
        cmdline: String::new(),
        parent: None,
        docker,
        stats: Stats::default(),
        user_launched: false,
    });
}

// ================================================================
// CWD / cmdline / user-launched detection (platform-specific)
// ================================================================

// Pass 1: user_launched only (tty + exe basename). The default dashboard filters
// on this, so it must cover every listener — but it costs just the two cheapest
// /proc reads per PID, not the full cwd/cmdline set.
#[cfg(target_os = "linux")]
fn enrich_user_launched(entries: &mut [Entry]) {
    let pids: HashSet<u32> = entries.iter().filter_map(|e| e.pid).collect();
    if pids.is_empty() {
        return;
    }
    let mut map: HashMap<u32, bool> = HashMap::with_capacity(pids.len());
    for pid in &pids {
        map.insert(*pid, read_user_launched_proc(*pid));
    }
    for e in entries.iter_mut() {
        if let Some(pid) = e.pid
            && let Some(&launched) = map.get(&pid)
        {
            e.user_launched = launched;
        }
    }
}

// Pass 2: cwd, read once per PID (a reverse proxy listens on many ports; reading
// per-entry would repeat the syscalls). Runs after the default-mode filter, so
// only surviving rows pay for it.
#[cfg(target_os = "linux")]
fn enrich_cwd(entries: &mut [Entry]) {
    for e in entries.iter_mut() {
        if e.pid.is_none() {
            e.cwd = "-".to_string();
        }
    }
    let pids: HashSet<u32> = entries.iter().filter_map(|e| e.pid).collect();
    if pids.is_empty() {
        return;
    }
    let mut map: HashMap<u32, String> = HashMap::with_capacity(pids.len());
    for pid in &pids {
        map.insert(*pid, read_cwd_proc(*pid));
    }
    for e in entries.iter_mut() {
        if let Some(pid) = e.pid
            && let Some(cwd) = map.get(&pid)
        {
            e.cwd = cwd.clone();
        }
    }
}

// Pass 3 (info mode only): full cmdline. The dashboard never displays it.
#[cfg(target_os = "linux")]
fn enrich_cmdline(entries: &mut [Entry]) {
    for e in entries.iter_mut() {
        if e.pid.is_none() {
            e.cmdline = "-".to_string();
        }
    }
    let pids: HashSet<u32> = entries.iter().filter_map(|e| e.pid).collect();
    if pids.is_empty() {
        return;
    }
    let mut map: HashMap<u32, String> = HashMap::with_capacity(pids.len());
    for pid in &pids {
        map.insert(*pid, read_cmdline_proc(*pid));
    }
    for e in entries.iter_mut() {
        if let Some(pid) = e.pid
            && let Some(cmd) = map.get(&pid)
        {
            e.cmdline = cmd.clone();
        }
    }
}

#[cfg(target_os = "linux")]
fn read_cwd_proc(pid: u32) -> String {
    fs::read_link(format!("/proc/{}/cwd", pid))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".to_string())
}

#[cfg(target_os = "linux")]
fn read_cmdline_proc(pid: u32) -> String {
    match fs::read(format!("/proc/{}/cmdline", pid)) {
        Ok(mut bytes) => {
            for b in bytes.iter_mut() {
                if *b == 0 {
                    *b = b' ';
                }
            }
            let s = String::from_utf8_lossy(&bytes).trim().to_string();
            if s.is_empty() {
                "-".to_string()
            } else {
                s
            }
        }
        Err(_) => "?".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn read_has_tty_proc(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid)) else {
        return false;
    };
    let Some(rparen) = stat.rfind(')') else {
        return false;
    };
    let rest = &stat[rparen + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
    let Some(tty) = fields.get(4).and_then(|s| s.parse::<i32>().ok()) else {
        return false;
    };
    tty != 0
}

#[cfg(target_os = "linux")]
fn read_exe_basename_proc(pid: u32) -> Option<String> {
    let path = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
    let name = path.file_name()?.to_string_lossy().into_owned();
    // The kernel appends " (deleted)" once the binary is unlinked (a rebuild or a
    // package upgrade under a running server); the marker is not part of the name.
    Some(
        name.strip_suffix(" (deleted)")
            .map(str::to_string)
            .unwrap_or(name),
    )
}

#[cfg(target_os = "linux")]
fn read_user_launched_proc(pid: u32) -> bool {
    if read_has_tty_proc(pid) {
        return true;
    }
    read_exe_basename_proc(pid)
        .as_deref()
        .map(is_interpreter_exe)
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn read_ppid_proc(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // comm can contain spaces/parens, so start after the last ')': state(0) ppid(1) ...
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse::<u32>().ok()
}

// (ppid, parent's cmdline). Reads /proc directly; only called in info mode.
#[cfg(target_os = "linux")]
fn read_parent_info(pid: u32) -> Option<(u32, String)> {
    let ppid = read_ppid_proc(pid)?;
    let cmd = read_cmdline_proc(ppid);
    // cmdline is empty for kernel threads and unreadable across privilege boundaries;
    // comm is a usable fallback in both cases.
    let cmd = if matches!(cmd.as_str(), "-" | "?") {
        fs::read_to_string(format!("/proc/{}/comm", ppid))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or(cmd)
    } else {
        cmd
    };
    Some((ppid, cmd))
}

#[cfg(target_os = "linux")]
fn enrich_parent_info(entries: &mut [Entry]) {
    let pids: HashSet<u32> = entries.iter().filter_map(|e| e.pid).collect();
    let mut info: HashMap<u32, (u32, String)> = HashMap::with_capacity(pids.len());
    for pid in &pids {
        if let Some(p) = read_parent_info(*pid) {
            info.insert(*pid, p);
        }
    }
    for e in entries.iter_mut() {
        if let Some(pid) = e.pid {
            e.parent = info.get(&pid).cloned();
        }
    }
}

#[cfg(target_os = "macos")]
fn enrich_parent_info(entries: &mut [Entry]) {
    let pids: HashSet<u32> = entries.iter().filter_map(|e| e.pid).collect();
    if pids.is_empty() {
        return;
    }
    let pid_list = pids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");

    // pid -> ppid
    let mut ppid_of: HashMap<u32, u32> = HashMap::new();
    if let Ok(output) = Command::new("ps")
        .args(["-o", "pid=,ppid=", "-p", &pid_list])
        .output()
    {
        let s = String::from_utf8_lossy(&output.stdout);
        for line in s.lines() {
            let mut it = line.split_whitespace();
            if let (Some(p), Some(pp)) = (it.next(), it.next())
                && let (Ok(p), Ok(pp)) = (p.parse::<u32>(), pp.parse::<u32>())
            {
                ppid_of.insert(p, pp);
            }
        }
    }
    if ppid_of.is_empty() {
        return;
    }

    // ppid -> command line
    let ppid_list = ppid_of
        .values()
        .collect::<HashSet<_>>()
        .into_iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut cmd_of: HashMap<u32, String> = HashMap::new();
    if let Ok(output) = Command::new("ps")
        .args(["-ww", "-o", "pid=,command=", "-p", &ppid_list])
        .output()
    {
        let s = String::from_utf8_lossy(&output.stdout);
        for line in s.lines() {
            let trimmed = line.trim_start();
            let Some(sp) = trimmed.find(char::is_whitespace) else {
                continue;
            };
            let (pid_s, rest) = trimmed.split_at(sp);
            if let Ok(pp) = pid_s.parse::<u32>() {
                cmd_of.insert(pp, rest.trim().to_string());
            }
        }
    }

    for e in entries.iter_mut() {
        if let Some(pid) = e.pid
            && let Some(&ppid) = ppid_of.get(&pid)
        {
            let cmd = cmd_of
                .get(&ppid)
                .filter(|c| !c.is_empty())
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            e.parent = Some((ppid, cmd));
        }
    }
}

// macOS pass 1: user_launched only, via one batched `ps` (tty + comm). BSD ps
// uses "??" to mean "no controlling tty".
#[cfg(target_os = "macos")]
fn enrich_user_launched(entries: &mut [Entry]) {
    let pids: HashSet<u32> = entries.iter().filter_map(|e| e.pid).collect();
    if pids.is_empty() {
        return;
    }
    let pid_list = pids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    let mut tty_exe: HashMap<u32, (bool, String)> = HashMap::new();
    if let Ok(output) = Command::new("ps")
        .args(["-ww", "-o", "pid=,tty=,comm=", "-p", &pid_list])
        .output()
    {
        let s = String::from_utf8_lossy(&output.stdout);
        for line in s.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let Ok(pid) = parts[0].parse::<u32>() else {
                continue;
            };
            let tty = parts[1];
            let has_tty = tty != "??" && tty != "?" && tty != "-";
            // comm may contain spaces (paths with spaces); join the remainder.
            let comm = parts[2..].join(" ");
            let basename = comm.rsplit('/').next().unwrap_or(&comm).to_string();
            tty_exe.insert(pid, (has_tty, basename));
        }
    }
    for e in entries.iter_mut() {
        if let Some(pid) = e.pid
            && let Some((has_tty, exe)) = tty_exe.get(&pid)
        {
            e.user_launched = *has_tty || is_interpreter_exe(exe);
        }
    }
}

// macOS pass 2: cwd via one batched lsof, after the default-mode filter.
#[cfg(target_os = "macos")]
fn enrich_cwd(entries: &mut [Entry]) {
    for e in entries.iter_mut() {
        if e.pid.is_none() {
            e.cwd = "-".to_string();
        }
    }
    let pids: HashSet<u32> = entries.iter().filter_map(|e| e.pid).collect();
    if pids.is_empty() {
        return;
    }
    let pid_list = pids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    let mut cwd_map: HashMap<u32, String> = HashMap::new();
    if let Ok(output) = Command::new("lsof")
        .args(["-a", "-p", &pid_list, "-d", "cwd", "-Fn"])
        .output()
    {
        let s = String::from_utf8_lossy(&output.stdout);
        let mut cur_pid: Option<u32> = None;
        for line in s.lines() {
            if line.is_empty() {
                continue;
            }
            // A value with an embedded newline spills untagged continuation lines;
            // drop them (a multi-byte first char would make split_at(1) panic).
            let Some((tag, val)) = line.split_at_checked(1) else { continue };
            match tag {
                "p" => cur_pid = val.parse().ok(),
                "n" => {
                    if let Some(pid) = cur_pid {
                        cwd_map.entry(pid).or_insert_with(|| val.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    for e in entries.iter_mut() {
        if let Some(pid) = e.pid
            && let Some(cwd) = cwd_map.get(&pid)
        {
            e.cwd = cwd.clone();
        }
    }
}

// macOS pass 3 (info mode only): full command line via one batched `ps`.
#[cfg(target_os = "macos")]
fn enrich_cmdline(entries: &mut [Entry]) {
    for e in entries.iter_mut() {
        if e.pid.is_none() {
            e.cmdline = "-".to_string();
        }
    }
    let pids: HashSet<u32> = entries.iter().filter_map(|e| e.pid).collect();
    if pids.is_empty() {
        return;
    }
    let pid_list = pids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    let mut cmdline_map: HashMap<u32, String> = HashMap::new();
    if let Ok(output) = Command::new("ps")
        .args(["-ww", "-o", "pid=,command=", "-p", &pid_list])
        .output()
    {
        let s = String::from_utf8_lossy(&output.stdout);
        for line in s.lines() {
            let trimmed = line.trim_start();
            let Some(sp) = trimmed.find(char::is_whitespace) else {
                continue;
            };
            let (pid_s, rest) = trimmed.split_at(sp);
            let Ok(pid) = pid_s.parse::<u32>() else {
                continue;
            };
            let cmd = rest.trim();
            let value = if cmd.is_empty() { "-".to_string() } else { cmd.to_string() };
            cmdline_map.insert(pid, value);
        }
    }
    for e in entries.iter_mut() {
        if let Some(pid) = e.pid
            && let Some(cmd) = cmdline_map.get(&pid)
        {
            e.cmdline = cmd.clone();
        }
    }
}

// ================================================================
// Stats enrichment (ps; cross-platform with cfg-gated format)
// ================================================================

fn enrich_local_stats(entries: &mut [Entry]) {
    let pids: Vec<u32> = entries
        .iter()
        .filter(|e| e.docker.is_none())
        .filter_map(|e| e.pid)
        .collect();
    if pids.is_empty() {
        return;
    }
    let pid_arg = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");

    // BSD ps on macOS does not have `nlwp` (thread count); skip that column.
    let fmt = if cfg!(target_os = "macos") {
        "pid=,pcpu=,rss=,etime=,user="
    } else {
        "pid=,pcpu=,rss=,nlwp=,etime=,user="
    };
    let output = match Command::new("ps").args(["-o", fmt, "-p", &pid_arg]).output() {
        Ok(o) => o,
        _ => return,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map: HashMap<u32, Stats> = HashMap::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let min_len = if cfg!(target_os = "macos") { 5 } else { 6 };
        if parts.len() < min_len {
            continue;
        }
        let Ok(pid) = parts[0].parse::<u32>() else {
            continue;
        };
        let cpu_pct = parts[1].parse::<f64>().ok();
        let cpu = format!("{}%", parts[1]);
        let rss_kb: u64 = parts[2].parse().unwrap_or(0);
        let mem_bytes = rss_kb * 1024;
        let mem = format_mem(mem_bytes);
        let (threads, etime_idx, user_idx) = if cfg!(target_os = "macos") {
            (None::<u32>, 3usize, 4usize)
        } else {
            (parts[3].parse::<u32>().ok(), 4usize, 5usize)
        };
        let uptime_secs = etime_to_secs(parts[etime_idx]);
        let uptime = uptime_secs
            .map(format_uptime)
            .unwrap_or_else(|| parts[etime_idx].to_string());
        let user = Some(parts[user_idx].to_string());
        map.insert(
            pid,
            Stats {
                cpu,
                mem,
                uptime,
                cpu_pct,
                mem_bytes: Some(mem_bytes),
                uptime_secs,
                threads,
                user,
            },
        );
    }
    for e in entries.iter_mut() {
        if e.docker.is_none()
            && let Some(pid) = e.pid
            && let Some(s) = map.get(&pid)
        {
            e.stats = s.clone();
        }
    }
}

fn enrich_docker_stats(entries: &mut [Entry], include_cpu_mem: bool) {
    for e in entries.iter_mut() {
        if let Some(d) = &e.docker {
            e.stats.uptime = d.running_for.trim_end_matches(" ago").to_string();
        }
    }
    if !include_cpu_mem {
        return;
    }
    let mut seen: HashSet<String> = HashSet::new();
    let names: Vec<String> = entries
        .iter()
        .filter_map(|e| e.docker.as_ref().map(|d| d.name.clone()))
        .filter(|n| seen.insert(n.clone()))
        .collect();
    if names.is_empty() {
        return;
    }
    let run_stats = |names: &[String]| {
        let mut cmd = Command::new("docker");
        cmd.args([
            "stats",
            "--no-stream",
            "--format",
            "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}",
        ]);
        for n in names {
            cmd.arg(n);
        }
        match cmd.output() {
            Ok(o) if o.status.success() => Some(o),
            _ => None,
        }
    };
    // `docker stats` fails as a batch — exit 1, empty stdout — when any name in it is
    // already gone, which is a live possibility in the second between our `docker ps`
    // and this call. Losing CPU/MEM for every container because one died is worse than
    // one extra `docker ps`, so retry once with the names that are still up.
    let output = match run_stats(&names) {
        Some(o) => o,
        None => {
            let live: HashSet<String> = match Command::new("docker")
                .args(["ps", "--format", "{{.Names}}"])
                .output()
            {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(str::to_string)
                    .collect(),
                _ => return,
            };
            let still_up: Vec<String> = names.into_iter().filter(|n| live.contains(n)).collect();
            if still_up.is_empty() {
                return;
            }
            match run_stats(&still_up) {
                Some(o) => o,
                None => return,
            }
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map: HashMap<String, (String, Option<f64>, String, Option<u64>)> = HashMap::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let name = parts[0].to_string();
        let cpu = parts[1].to_string();
        let cpu_pct = parts[1].trim_end_matches('%').parse::<f64>().ok();
        let mem = parts[2]
            .split('/')
            .next()
            .unwrap_or("-")
            .trim()
            .to_string();
        let mem_bytes = parse_size(&mem);
        map.insert(name, (cpu, cpu_pct, mem, mem_bytes));
    }
    for e in entries.iter_mut() {
        if let Some(d) = &e.docker
            && let Some((cpu, cpu_pct, mem, mem_bytes)) = map.get(&d.name)
        {
            e.stats.cpu = cpu.clone();
            e.stats.cpu_pct = *cpu_pct;
            e.stats.mem = mem.clone();
            e.stats.mem_bytes = *mem_bytes;
        }
    }
}

// Parse a docker stats size like "123.4MiB" into bytes. Docker uses 1024-based
// units (KiB/MiB/GiB/TiB); a bare number is bytes.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let split = s
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let value: f64 = num.trim().parse().ok()?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kib" | "kb" => 1024,
        "mib" | "mb" => 1024 * 1024,
        "gib" | "gb" => 1024 * 1024 * 1024,
        "tib" | "tb" => 1024 * 1024 * 1024 * 1024,
        _ => return None,
    };
    Some((value * mult as f64) as u64)
}

fn format_mem(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.0}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{}K", bytes / KB)
    } else {
        format!("{}B", bytes)
    }
}

// ps etime ("[[DD-]hh:]mm:ss") to seconds. None when the shape is unrecognized,
// in which case the caller keeps the raw string for display.
fn etime_to_secs(et: &str) -> Option<u64> {
    let (days, rest) = match et.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, et),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let (h, m, s): (u64, u64, u64) = match parts.len() {
        3 => (
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
        ),
        2 => (0, parts[0].parse().ok()?, parts[1].parse().ok()?),
        1 => (0, 0, parts[0].parse().ok()?),
        _ => return None,
    };
    Some(days * 86400 + h * 3600 + m * 60 + s)
}

fn format_uptime(total: u64) -> String {
    if total >= 86400 {
        format!("{}d{}h", total / 86400, (total % 86400) / 3600)
    } else if total >= 3600 {
        format!("{}h{}m", total / 3600, (total % 3600) / 60)
    } else if total >= 60 {
        format!("{}m{}s", total / 60, total % 60)
    } else {
        format!("{}s", total)
    }
}

// Visual group key: compose project for docker rows in the same project,
// container name when no compose label, cwd for local rows. Two entries with
// the same key sit in the same visual block in the table.
fn group_key(e: &Entry) -> &str {
    if let Some(d) = &e.docker {
        d.compose_project.as_deref().unwrap_or(d.name.as_str())
    } else {
        e.cwd.as_str()
    }
}

// ================================================================
// Update notice (best-effort, never blocks the dashboard)
// ================================================================
//
// Strategy: cache the latest upstream version under
// `${XDG_CACHE_HOME:-$HOME/.cache}/lport/update-check`. On every run:
//   1. Read the cache. If a newer version is recorded, print a one-line
//      notice to stderr (after the table).
//   2. If the cache is older than 24h (or missing), spawn a detached `sh`
//      that re-fetches `Cargo.toml` from main and rewrites the cache. The
//      result is observable on the *next* run, not this one — so startup
//      stays fast.
// `LPORT_NO_UPDATE_CHECK=1` disables both halves.

const UPDATE_CACHE_TTL_SECS: u64 = 24 * 3600;
const UPDATE_REPO: &str = "https://github.com/Changroro/lport";
const UPDATE_RAW_CARGO_TOML: &str =
    "https://raw.githubusercontent.com/Changroro/lport/main/Cargo.toml";

fn maybe_print_update_notice() {
    if std::env::var_os("LPORT_NO_UPDATE_CHECK").is_some() {
        return;
    }
    let Some(cache_path) = update_cache_path() else {
        return;
    };
    let current = env!("CARGO_PKG_VERSION");

    let cached = std::fs::read_to_string(&cache_path).ok();
    let mut cache_fresh = false;
    let mut latest: Option<String> = None;
    if let Some(s) = cached.as_deref() {
        let mut lines = s.lines();
        let ts_line = lines.next().unwrap_or("").trim();
        let ver_line = lines.next().unwrap_or("").trim();
        if let (Ok(ts), Some(now)) = (ts_line.parse::<u64>(), unix_now())
            && now >= ts
            && now - ts < UPDATE_CACHE_TTL_SECS
        {
            cache_fresh = true;
        }
        if !ver_line.is_empty() && version_gt(ver_line, current) {
            latest = Some(ver_line.to_string());
        }
    }
    if let Some(latest) = latest {
        prompt_or_print_update(current, &latest);
    }
    if !cache_fresh {
        spawn_update_cache_refresh(&cache_path);
    }
}

// Show the update notice. If the session is fully interactive (stdin, stdout,
// stderr all attached to a TTY), also prompt `[y/N]` and run
// `cargo install --git ... --force` on `y`. Default is N so an unattended
// Enter does not silently kick off a heavy rebuild.
fn prompt_or_print_update(current: &str, latest: &str) {
    let stderr_tty = io::stderr().is_terminal();
    let interactive =
        stderr_tty && io::stdout().is_terminal() && io::stdin().is_terminal();
    let dot = if stderr_tty { "\x1b[33m●\x1b[0m" } else { "*" };
    let bold = |s: &str| -> String {
        if stderr_tty {
            format!("\x1b[1m{}\x1b[0m", s)
        } else {
            s.to_string()
        }
    };

    if interactive {
        eprintln!();
        eprint!(
            "{}  update available: lport {} → {}   install now? {} ",
            dot,
            current,
            latest,
            bold("[y/N]"),
        );
        let _ = io::stderr().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let answer = input.trim();
            if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
                run_cargo_install();
            }
        }
    } else {
        eprintln!();
        eprintln!(
            "{}  update available: lport {} → {}",
            dot, current, latest
        );
        eprintln!(
            "   install: cargo install --git {} --force",
            UPDATE_REPO
        );
    }
}

fn run_cargo_install() {
    eprintln!();
    eprintln!("==> cargo install --git {} --force", UPDATE_REPO);
    match Command::new("cargo")
        .args(["install", "--git", UPDATE_REPO, "--force"])
        .status()
    {
        Ok(s) if s.success() => {
            eprintln!("==> lport updated. Re-run to use the new version.");
        }
        Ok(s) => {
            eprintln!(
                "==> cargo install exited with status {}.",
                s.code().map(|c| c.to_string()).unwrap_or_else(|| "?".into())
            );
        }
        Err(e) => {
            eprintln!("==> failed to spawn cargo: {}.", e);
            eprintln!("    is the Rust toolchain installed and on PATH?");
        }
    }
}

fn update_cache_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("lport").join("update-check"))
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

// Numeric semver-ish comparison. `0.10.0` > `0.9.0`. Pre-release suffixes
// after `-` are stripped before comparison.
fn version_gt(a: &str, b: &str) -> bool {
    fn parse(v: &str) -> Vec<u32> {
        v.trim()
            .trim_start_matches('v')
            .split('-')
            .next()
            .unwrap_or("")
            .split('.')
            .map(|s| s.parse::<u32>().unwrap_or(0))
            .collect()
    }
    let mut pa = parse(a);
    let mut pb = parse(b);
    // Pad to equal length: a bare lexicographic Vec comparison treats
    // [0,9] < [0,9,0], which would report a phantom update from 0.9 to 0.9.0.
    let len = pa.len().max(pb.len());
    pa.resize(len, 0);
    pb.resize(len, 0);
    pa > pb
}

fn spawn_update_cache_refresh(cache_path: &std::path::Path) {
    let dir = match cache_path.parent() {
        Some(d) => d.to_string_lossy().into_owned(),
        None => return,
    };
    let cache_str = cache_path.to_string_lossy().into_owned();
    // Both paths are quoted with single quotes; embedded single quotes get
    // the standard `'\''` escape so the shell receives the literal path.
    let dir_q = dir.replace('\'', r"'\''");
    let cache_q = cache_str.replace('\'', r"'\''");
    let script = format!(
        "v=$(curl -fsSL --max-time 5 {url} 2>/dev/null \
            | awk -F'\"' '/^version[[:space:]]*=/ {{print $2; exit}}'); \
         if [ -n \"$v\" ]; then \
            mkdir -p '{dir}' && printf '%s\\n%s\\n' \"$(date +%s)\" \"$v\" > '{cache}'; \
         fi",
        url = UPDATE_RAW_CARGO_TOML,
        dir = dir_q,
        cache = cache_q,
    );
    // Detach: stdio piped to /dev/null. When this process exits, the child
    // is reparented to init and continues. No wait() is needed.
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

// Terminal cells occupied by `s`. The wide set below is an approximation of the
// East Asian Wide/Fullwidth ranges (plus the emoji blocks and the Emoji_Presentation
// defaults), not a full UAX #11 table — enough to keep columns aligned for the paths,
// process names and container names lport prints.
fn display_width(s: &str) -> usize {
    s.chars().map(|c| if is_wide_char(c) { 2 } else { 1 }).sum()
}

fn is_wide_char(c: char) -> bool {
    matches!(
        c as u32,
        0x1100..=0x115F
            | 0x2E80..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE6F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1F64F
            | 0x1F680..=0x1F6FF
            | 0x1F7E0..=0x1F7EB
            | 0x1F900..=0x1F9FF
            | 0x1FA70..=0x1FAFF
            | 0x20000..=0x2FFFD
            | 0x30000..=0x3FFFD
            // Emoji_Presentation defaults scattered through U+2xxx: listed one by one
            // because their neighbours (☑ ⚠ …) default to text presentation and stay narrow.
            | 0x231A..=0x231B
            | 0x23E9..=0x23EC
            | 0x23F0
            | 0x23F3
            | 0x25FD..=0x25FE
            | 0x2614..=0x2615
            | 0x2648..=0x2653
            | 0x267F
            | 0x2693
            | 0x26A1
            | 0x26AA..=0x26AB
            | 0x26BD..=0x26BE
            | 0x26C4..=0x26C5
            | 0x26CE
            | 0x26D4
            | 0x26EA
            | 0x26F2..=0x26F3
            | 0x26F5
            | 0x26FA
            | 0x26FD
            | 0x2705
            | 0x270A..=0x270B
            | 0x2728
            | 0x274C
            | 0x274E
            | 0x2753..=0x2755
            | 0x2757
            | 0x2795..=0x2797
            | 0x27B0
            | 0x27BF
            | 0x2B1B..=0x2B1C
            | 0x2B50
            | 0x2B55
    )
}

fn nz(s: &str) -> String {
    if s.is_empty() {
        "-".to_string()
    } else {
        s.to_string()
    }
}

fn shorten_path(s: &str, home: Option<&str>) -> String {
    // Truncation is intentionally absent: the CWD is the feature, clipping it
    // to `…` would defeat the point. Only the `$HOME -> ~` substitution is
    // applied here for readability; columns expand to whatever width is needed.
    if matches!(s, "" | "-" | "?" | "/") {
        return s.to_string();
    }
    if let Some(h) = home {
        if s == h {
            return "~".to_string();
        }
        let prefix = format!("{}/", h);
        if let Some(rest) = s.strip_prefix(&prefix) {
            return format!("~/{}", rest);
        }
    }
    s.to_string()
}

// Report each requested port that has no listener, the way `kill` does. A single
// "(no matching port found)" hid which port of `lport info 5432 59321` was empty.
// Returns 1 when anything missed.
fn report_missing_ports(entries: &[Entry], ports: &[u32]) -> i32 {
    let mut missing = false;
    for &port in ports {
        if !entries.iter().any(|e| e.port == port) {
            eprintln!("port {}: no listening process found.", port);
            missing = true;
        }
    }
    if missing { 1 } else { 0 }
}

fn print_info(entries: &[Entry], ports: &[u32]) -> i32 {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let code = report_missing_ports(entries, ports);

    // Soft writes: `info` owes the caller an exit code (a missing port is 1), and exiting
    // 0 on a closed pipe would silently break that contract. There is nothing to gain from
    // bailing out early either — `info` prints a handful of rows, not a whole system.
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            outln_soft!(out, "");
        }
        outln_soft!(out, "─────────────────────────────────────────────");
        let rows: Vec<(&str, String)> = match &e.docker {
            Some(d) => docker_info_rows(e, d),
            None => local_info_rows(e),
        };
        let label_w = rows.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
        for (label, value) in &rows {
            outln_soft!(out, "  {:<width$}  {}", label, value, width = label_w);
        }
    }
    code
}

fn local_info_rows(e: &Entry) -> Vec<(&'static str, String)> {
    let mut rows: Vec<(&'static str, String)> = vec![
        ("PORT", format!("{}/{}", e.proto, e.port)),
        ("ADDR", nz(&e.addr)),
        ("PROCESS", e.process.clone()),
        (
            "PID",
            e.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        ),
    ];
    if let Some(u) = &e.stats.user {
        rows.push(("USER", u.clone()));
    }
    rows.push(("CPU", nz(&e.stats.cpu)));
    rows.push(("MEM", nz(&e.stats.mem)));
    if let Some(t) = e.stats.threads {
        rows.push(("THREADS", t.to_string()));
    }
    rows.push(("UPTIME", nz(&e.stats.uptime)));
    if let Some((ppid, cmd)) = &e.parent {
        rows.push(("PARENT", format!("pid {} ({})", ppid, cmd)));
    }
    rows.push(("CWD", e.cwd.clone()));
    rows.push(("CMD", e.cmdline.clone()));
    rows
}

fn docker_info_rows(e: &Entry, d: &DockerInfo) -> Vec<(&'static str, String)> {
    let mut rows: Vec<(&'static str, String)> = vec![
        (
            "PORT",
            format!("{}/{} → {} (in container)", e.proto, e.port, d.container_port),
        ),
        ("ADDR", nz(&e.addr)),
        ("TYPE", "docker container".to_string()),
        ("CONTAINER", d.name.clone()),
        ("IMAGE", d.image.clone()),
    ];
    if let Some(w) = &d.work_dir {
        rows.push(("WORKDIR", w.clone()));
    }
    rows.push(("CPU", nz(&e.stats.cpu)));
    rows.push(("MEM", nz(&e.stats.mem)));
    rows.push(("UPTIME", nz(&e.stats.uptime)));
    rows
}

fn print_table(entries: &[Entry], dev_mode: bool, group_headers: bool) {
    let headers: &[&str] = &[
        "PROTO", "PORT", "ADDR", "PID", "PROCESS", "JOB", "CPU", "MEM", "UPTIME",
    ];

    let home = std::env::var("HOME").ok();

    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            let (process, job) = match &e.docker {
                Some(d) => ("docker".to_string(), d.name.clone()),
                None => (e.process.clone(), shorten_path(&e.cwd, home.as_deref())),
            };
            vec![
                e.proto.to_string(),
                e.port.to_string(),
                nz(&e.addr),
                e.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
                process,
                job,
                nz(&e.stats.cpu),
                nz(&e.stats.mem),
                nz(&e.stats.uptime),
            ]
        })
        .collect();

    let mut widths: Vec<usize> = headers.iter().map(|h| display_width(h)).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(display_width(cell));
        }
    }

    // `{:<width$}` pads by char count, which under-pads CJK cells (a Hangul path
    // component occupies two terminal cells per char). Pad by display width.
    let fmt_row = |cells: &[String]| -> String {
        cells
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{}{}", c, " ".repeat(w.saturating_sub(display_width(c)))))
            .collect::<Vec<_>>()
            .join("  ")
    };
    let stdout = io::stdout();
    let tty = stdout.is_terminal();
    let mut out = stdout.lock();
    // Bold header / group labels on a TTY only; piped output stays plain.
    let bold = |s: String| -> String {
        if tty {
            format!("\x1b[1m{}\x1b[0m", s)
        } else {
            s
        }
    };
    let header_cells: Vec<String> = headers.iter().map(|s| s.to_string()).collect();
    outln!(out, "{}", bold(fmt_row(&header_cells)));
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    outln!(out, "{}", sep.join("  "));
    // Every docker block (whether the group has one row or many) gets the
    // same `[ name ]` header treatment, preceded by a blank line so it reads
    // as a distinct block from neighbouring rows. Group key is the compose
    // project label if present, else the container name. Local rows stay
    // compact and are never given a separator among themselves.
    // Suppressed under `--sort`, where rows are ordered globally and a block's
    // rows may not be adjacent — a repeated header would mislead.
    let mut prev_docker_group: Option<&str> = None;
    for (i, (e, row)) in entries.iter().zip(rows.iter()).enumerate() {
        let cur_docker_group: Option<&str> = if e.docker.is_some() {
            Some(group_key(e))
        } else {
            None
        };
        if group_headers && cur_docker_group.is_some() && cur_docker_group != prev_docker_group {
            if i > 0 {
                outln!(out, "");
            }
            if let Some(name) = cur_docker_group {
                outln!(out, "{}", bold(format!("[ {} ]", name)));
            }
        }
        outln!(out, "{}", fmt_row(row));
        prev_docker_group = cur_docker_group;
    }

    if entries.is_empty() {
        if dev_mode {
            eprintln!("\n(no listening ports found — try running with sudo)");
        } else {
            eprintln!("\n(no user servers to display — run `lport --dev` to see everything)");
        }
    }
}

// ================================================================
// Tests — pure functions only; nothing here spawns processes or
// touches /proc, so the suite runs anywhere.
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ---- port / address parsing ------------------------------------

    #[test]
    fn port_range_single_and_range() {
        assert_eq!(parse_port_range("80"), Some((80, 80)));
        assert_eq!(parse_port_range("80-82"), Some((80, 82)));
        assert_eq!(parse_port_range(""), None);
        assert_eq!(parse_port_range("abc"), None);
        assert_eq!(parse_port_range("80-"), None);
        assert_eq!(parse_port_range("-82"), None);
    }

    #[test]
    fn bind_addr_splits_host_and_port() {
        assert_eq!(split_bind_addr("0.0.0.0:8080"), "0.0.0.0");
        assert_eq!(split_bind_addr("[::]:8080"), "::");
        assert_eq!(split_bind_addr("*:5353"), "*");
        assert_eq!(split_bind_addr("127.0.0.1:3101"), "127.0.0.1");
        // Scope suffix (link-local binds) is dropped for matching...
        assert_eq!(split_bind_addr("0.0.0.0%virbr0:67"), "0.0.0.0");
        assert_eq!(split_bind_addr("[fe80::1%eth0]:8080"), "fe80::1");
        // ...but kept for display.
        assert_eq!(display_bind_addr("0.0.0.0%virbr0:67"), "0.0.0.0%virbr0");
        assert_eq!(display_bind_addr("[::]:8080"), "::");
    }

    #[test]
    fn wildcard_and_normalized_addrs() {
        for a in ["", "0.0.0.0", "::", "*"] {
            assert!(is_wildcard_addr(a), "{a} should be wildcard");
        }
        assert!(!is_wildcard_addr("127.0.0.1"));
        assert_eq!(normalize_addr("::ffff:127.0.0.1"), "127.0.0.1");
        assert_eq!(normalize_addr("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn ip_matching_respects_stack_and_wildcards() {
        // wildcard publish claims any listener on the port
        assert!(ip_matches("0.0.0.0", "127.0.0.1"));
        assert!(ip_matches("::", "[::1]".trim_start_matches('[').trim_end_matches(']')));
        // v4 publish must not claim a v6 listener and vice versa
        assert!(!ip_matches("0.0.0.0", "::"));
        assert!(!ip_matches("::", "0.0.0.0"));
        // exact match, and v4-mapped v6 equals plain v4
        assert!(ip_matches("127.0.0.1", "127.0.0.1"));
        assert!(ip_matches("::ffff:127.0.0.1", "127.0.0.1"));
        // a specific publish does not claim a different address
        assert!(!ip_matches("192.168.1.10", "127.0.0.1"));
        // lsof's "*" carries no stack info
        assert!(ip_matches("*", "127.0.0.1"));
        assert!(ip_matches("127.0.0.1", "*"));
    }

    // parse_users only exists on Linux (it parses `ss` output).
    #[cfg(target_os = "linux")]
    #[test]
    fn ss_users_field_parses_comms_with_spaces_and_quotes() {
        let s = "users:((\"nginx\",pid=123,fd=6),(\"nginx\",pid=124,fd=7))";
        assert_eq!(
            parse_users(s),
            vec![("nginx".to_string(), 123), ("nginx".to_string(), 124)]
        );
        // comm containing a space and an open paren (seen in the wild: "next-server (v1")
        let s = "users:((\"next-server (v1\",pid=99,fd=5))";
        assert_eq!(parse_users(s), vec![("next-server (v1".to_string(), 99)]);
        assert!(parse_users("").is_empty());
        assert!(parse_users("users:()").is_empty());
    }

    // ---- formatting -------------------------------------------------

    #[test]
    fn mem_formatting() {
        assert_eq!(format_mem(0), "0B");
        assert_eq!(format_mem(512), "512B");
        assert_eq!(format_mem(2048), "2K");
        assert_eq!(format_mem(5 * 1024 * 1024), "5M");
        assert_eq!(format_mem(2 * 1024 * 1024 * 1024), "2.0G");
    }

    #[test]
    fn etime_parsing_and_display() {
        assert_eq!(etime_to_secs("45"), Some(45));
        assert_eq!(etime_to_secs("05:32"), Some(332));
        assert_eq!(etime_to_secs("01:02:03"), Some(3723));
        assert_eq!(etime_to_secs("9-06:00:00"), Some(9 * 86400 + 6 * 3600));
        assert_eq!(etime_to_secs("garbage:extra:fields:here"), None);
        assert_eq!(format_uptime(45), "45s");
        assert_eq!(format_uptime(332), "5m32s");
        assert_eq!(format_uptime(3723), "1h2m");
        assert_eq!(format_uptime(9 * 86400 + 6 * 3600), "9d6h");
    }

    #[test]
    fn docker_size_parsing() {
        assert_eq!(parse_size("123B"), Some(123));
        assert_eq!(parse_size("2KiB"), Some(2048));
        assert_eq!(parse_size("189MiB"), Some(189 * 1024 * 1024));
        assert_eq!(parse_size("2.0GiB"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("1.5TiB"), Some((1.5 * 1024f64.powi(4)) as u64));
        assert_eq!(parse_size("-"), None);
        assert_eq!(parse_size("abc"), None);
    }

    #[test]
    fn display_width_counts_cjk_and_emoji_double() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("프로젝트"), 8);
        assert_eq!(display_width("a😀b"), 4);
        assert_eq!(display_width("~/프로젝트/데모"), 2 + 8 + 1 + 4);
    }

    #[test]
    fn path_shortening_only_touches_home() {
        let home = Some("/home/bch");
        assert_eq!(shorten_path("/home/bch", home), "~");
        assert_eq!(shorten_path("/home/bch/proj", home), "~/proj");
        assert_eq!(shorten_path("/etc/nginx", home), "/etc/nginx");
        assert_eq!(shorten_path("", home), "");
        assert_eq!(shorten_path("-", home), "-");
        assert_eq!(shorten_path("/home/bch2/x", home), "/home/bch2/x");
        assert_eq!(shorten_path("/home/bch/proj", None), "/home/bch/proj");
    }

    // ---- version comparison -----------------------------------------

    #[test]
    fn version_comparison_pads_and_strips() {
        assert!(version_gt("0.10.0", "0.9.0"));
        assert!(version_gt("1.0.0", "0.99.99"));
        assert!(version_gt("v0.10.0", "0.9.0"));
        assert!(!version_gt("0.9.0", "0.9.0"));
        // padding: 0.9.0 is NOT newer than 0.9
        assert!(!version_gt("0.9.0", "0.9"));
        assert!(!version_gt("0.9", "0.9.0"));
        // pre-release suffix stripped: 0.9.0-beta == 0.9.0, not greater
        assert!(!version_gt("0.9.0-beta", "0.9.0"));
        assert!(version_gt("0.9.1", "0.9.0-beta"));
    }

    // ---- argument parsing -------------------------------------------

    #[test]
    fn parse_dashboard_defaults_and_dev() {
        let cli = parse_args(&args(&[])).unwrap();
        assert_eq!(cli.mode, Mode::Dashboard { dev: false });
        assert_eq!(cli.sort, None);
        let cli = parse_args(&args(&["--dev"])).unwrap();
        assert_eq!(cli.mode, Mode::Dashboard { dev: true });
    }

    #[test]
    fn parse_sort_flag_in_any_position() {
        let cli = parse_args(&args(&["--sort", "mem"])).unwrap();
        assert_eq!(cli.mode, Mode::Dashboard { dev: false });
        assert_eq!(cli.sort, Some(SortKey::Mem));
        let cli = parse_args(&args(&["--dev", "--sort", "cpu"])).unwrap();
        assert_eq!(cli.mode, Mode::Dashboard { dev: true });
        assert_eq!(cli.sort, Some(SortKey::Cpu));
    }

    #[test]
    fn parse_sort_rejects_bad_key_or_missing_value() {
        assert!(parse_args(&args(&["--sort"])).unwrap_err().contains("requires a key"));
        assert!(parse_args(&args(&["--sort", "bogus"]))
            .unwrap_err()
            .contains("invalid sort key 'bogus'"));
    }

    #[test]
    fn parse_info_shorthand_and_subcommand() {
        let cli = parse_args(&args(&["8080"])).unwrap();
        assert_eq!(cli.mode, Mode::Info { ports: vec![8080] });
        let cli = parse_args(&args(&["info", "8080", "5432"])).unwrap();
        assert_eq!(cli.mode, Mode::Info { ports: vec![8080, 5432] });
        // out-of-range port is not a shorthand and not a valid port
        assert!(parse_args(&args(&["99999"])).is_err());
        assert!(parse_args(&args(&["info", "abc"])).unwrap_err().contains("invalid port 'abc'"));
        assert!(parse_args(&args(&["info"])).unwrap_err().contains("at least one port"));
    }

    #[test]
    fn parse_kill_flags_and_errors() {
        let cli = parse_args(&args(&["kill", "3000"])).unwrap();
        assert_eq!(
            cli.mode,
            Mode::Kill { ports: vec![3000], force: false, yes: false }
        );
        let cli = parse_args(&args(&["kill", "-9", "-y", "3000", "8080"])).unwrap();
        assert_eq!(
            cli.mode,
            Mode::Kill { ports: vec![3000, 8080], force: true, yes: true }
        );
        assert!(parse_args(&args(&["kill"])).unwrap_err().contains("at least one port"));
        assert!(parse_args(&args(&["kill", "abc"])).unwrap_err().contains("invalid port 'abc'"));
        // --sort is meaningless (and refused) for kill
        assert!(parse_args(&args(&["kill", "3000", "--sort", "mem"]))
            .unwrap_err()
            .contains("--sort"));
    }

    #[test]
    fn parse_unknown_argument() {
        assert!(parse_args(&args(&["--bogus"]))
            .unwrap_err()
            .contains("unknown argument '--bogus'"));
    }

    // ---- sorting ------------------------------------------------------

    fn entry(port: u32, pid: Option<u32>, cpu: Option<f64>, mem: Option<u64>, up: Option<u64>) -> Entry {
        Entry {
            proto: "tcp",
            port,
            pid,
            process: format!("p{port}"),
            addr: "0.0.0.0".to_string(),
            cwd: String::new(),
            cmdline: String::new(),
            parent: None,
            docker: None,
            stats: Stats {
                cpu_pct: cpu,
                mem_bytes: mem,
                uptime_secs: up,
                ..Stats::default()
            },
            user_launched: false,
        }
    }

    #[test]
    fn sort_by_mem_largest_first_unknowns_last() {
        let mut v = vec![
            entry(1, Some(1), None, None, None),
            entry(2, Some(2), None, Some(100), None),
            entry(3, Some(3), None, Some(900), None),
        ];
        sort_entries(&mut v, SortKey::Mem);
        let ports: Vec<u32> = v.iter().map(|e| e.port).collect();
        assert_eq!(ports, vec![3, 2, 1]);
    }

    #[test]
    fn sort_by_port_ascending() {
        let mut v = vec![entry(8080, None, None, None, None), entry(80, None, None, None, None)];
        sort_entries(&mut v, SortKey::Port);
        let ports: Vec<u32> = v.iter().map(|e| e.port).collect();
        assert_eq!(ports, vec![80, 8080]);
    }
}

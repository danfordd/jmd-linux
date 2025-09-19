// jmd-linux — CLI-tool for detecting JVMTI/JNI injections on Linux
// Copyright (C) 2025 danfordd
// Licensed under the GNU General Public License v3.0 or later.
// See the LICENSE file for details.


use std::fs::File;
use std::io::{BufRead, Read, Seek, SeekFrom};
use nix::sys::ptrace;
use nix::unistd::Pid;
use anyhow::{Result, Context};
use memmem::{Searcher, TwoWaySearcher};

fn main() -> Result<()> {
    let pid = find_java().context("Failed to find Java process")?;
    println!("{}", pid);
    scan_memory(pid)?;
    Ok(())
}

fn find_java() -> Result<i32> {
    let processes = procfs::process::all_processes()?;
    let mut java_candidates = Vec::new();

    for proc in processes {
        if let Ok(status) = proc.status() {
            let is_java_name = status.name.contains("java");
            let is_java_cmd = if let Ok(cmdline) = proc.cmdline() {
                !cmdline.is_empty() && cmdline[0].contains("java")
            } else {
                false
            };

            if is_java_name || is_java_cmd {
                if let Ok(stat) = proc.stat() {
                    let rss_bytes = stat.rss as u64 * 4096;
                    java_candidates.push((proc.pid, rss_bytes));
                }
            }
        }
    }

    if java_candidates.is_empty() {
        return Err(anyhow::anyhow!("No Java processes found"));
    }

    let (pid, _) = java_candidates.into_iter().max_by_key(|(_, rss)| *rss).unwrap();
    Ok(pid)
}

fn scan_memory(pid: i32) -> Result<()> {
    let nix_pid = Pid::from_raw(pid);
    ptrace::attach(nix_pid)?;

    const S1: [u32; 4] = [4242546329, 4601, 0, 0];
    const S2: [u32; 4] = [4242546329, 505, 0, 0];

    let s1: Vec<u8> = S1.iter().flat_map(|n| n.to_le_bytes()).collect();
    let s2: Vec<u8> = S2.iter().flat_map(|n| n.to_le_bytes()).collect();

    loop {
        match nix::sys::wait::waitpid(nix_pid, None) {
            Ok(nix::sys::wait::WaitStatus::Stopped(_, _)) => break,
            Ok(_) => continue,
            Err(e) => return Err(anyhow::anyhow!("Wait error: {}", e)),
        }
    }

    let mut mem_file = File::open(format!("/proc/{}/mem", pid))?;
    let maps_file = File::open(format!("/proc/{}/maps", pid))?;
    let maps_reader = std::io::BufReader::new(maps_file);

    let mut found_s1 = false;
    let mut found_s2 = false;

    for line in maps_reader.lines() {
        let line = line?;

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 { continue; }

        let range = parts[0];
        let perms = parts[1];

        if !perms.contains('r') { continue; }

        let addresses: Vec<&str> = range.split('-').collect();
        if addresses.len() != 2 { continue; }

        let start = match u64::from_str_radix(addresses[0], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end = match u64::from_str_radix(addresses[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let region_size = (end - start) as usize;
        if region_size == 0 { continue; }

        let mut buffer = vec![0u8; region_size];

        if mem_file.seek(SeekFrom::Start(start)).is_err() {
            continue;
        }

        if mem_file.read_exact(&mut buffer).is_err() {
            continue;
        }

        let search_s = |data: &[u8], sig: &[u8]| -> bool {
            if sig.is_empty() || data.len() < sig.len() {
                return false;
            }
            TwoWaySearcher::new(sig).search_in(data).is_some()
        };

        if !found_s1 && search_s(&buffer, &s1) {
            found_s1 = true;
        }

        if !found_s1 && !found_s2 && search_s(&buffer, &s2) {
            found_s2 = true;
        }

        if found_s1 || found_s2 {
            break;
        }
    }

    ptrace::detach(nix_pid, None)?;

    if found_s1 {
        println!("[+] Injection detected (#S1).");
    } else if found_s2 {
        println!("[+] Injection detected (#S2).");
    } else {
        println!("[-] No suspicious manipulations with JVM detected.");
    }

    Ok(())
}
// Copyright (c) Kiran Ayyagari. All rights reserved.
// Copyright (c) Diridium Technologies Inc. All rights reserved.
// Licensed under the MPL-2.0 License. See LICENSE file in the project root.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use anyhow::Error;
use openssl::x509::store::X509StoreRef;
use openssl::x509::X509;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::Url;
use roxmltree::Node;
use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};
use tauri::ipc::Channel;

use crate::connection::ConnectionEntry;
use crate::errors::VerificationError;
use crate::verify::verify_jar;

/// How long a cached WebstartFile remains valid before re-fetching (seconds)
const WEBSTART_CACHE_TTL_SECS: u64 = 120;

/// Maximum concurrent download threads for JAR retrieval
const DOWNLOAD_THREADS: usize = 4;

/// Windows: CREATE_NO_WINDOW flag to suppress console window
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug)]
#[allow(dead_code)]
pub struct WebstartFile {
    url: String,
    main_class: String,
    args: Vec<String>,
    j2ses: Option<Vec<J2se>>,
    jar_dir: PathBuf,
    loaded_at: SystemTime,
}

/// from jnlp -> resources -> j2se
#[derive(Debug)]
pub struct J2se {
    java_vm_args: Option<String>,
    version: String,
}

pub struct WebstartCache {
    cache: Mutex<FxHashMap<String, Arc<WebstartFile>>>,
}

impl WebstartCache {
    pub fn init() -> Self {
        let cache = Mutex::new(FxHashMap::default());
        WebstartCache { cache }
    }

    pub fn get(&self, url: &str) -> Option<Arc<WebstartFile>> {
        let cache = self.cache.lock().expect("webstart cache lock poisoned");
        let wf = cache.get(url);
        if let Some(wf) = wf {
            let now = SystemTime::now();
            let elapsed = now
                .duration_since(wf.loaded_at)
                .expect("failed to calculate the duration");
            if elapsed.as_secs() < WEBSTART_CACHE_TTL_SECS {
                return Some(Arc::clone(wf));
            }
        }
        None
    }

    pub fn put(&self, url: &str, wf: Arc<WebstartFile>) {
        let mut cache = self.cache.lock().expect("webstart cache lock poisoned");
        cache.insert(url.to_string(), wf);
    }
}

impl WebstartFile {
    pub fn load(base_url: &str, cache_dir: &PathBuf, donotcache: bool, conn_id: &str, conn_name: &str, on_progress: &Channel<serde_json::Value>) -> Result<WebstartFile, Error> {
        let (base_url, _host) = normalize_url(base_url)?;
        let webstart = format!("{}/webstart.jnlp", base_url); // base_url will never contain a / at the end after normalization
        let _ = on_progress.send(serde_json::json!({"message": "Fetching server configuration..."}));
        let cb = ClientBuilder::default()
            // in certain network environments client is failing with error message "connection closed before message completed"
            // disabling the pooling resolved the issue
            .pool_max_idle_per_host(0)
            // accept any cert presented by the MC server
            .danger_accept_invalid_certs(true);
        let client = cb.build()?;

        let r = client.get(&webstart).send()?;
        let data = r.text()?;
        let doc = roxmltree::Document::parse(&data)?;

        let root = doc.root();
        let main_class_node = get_node(&root, "application-desc").ok_or(Error::msg(
            "Got something from MC that was not an application-desc node in a JNLP XML",
        ))?;
        let main_class = main_class_node
            .attribute("main-class")
            .ok_or(Error::msg("missing main-class attribute"))?
            .to_string();
        let args = get_client_args(&main_class_node);

        let resources_node = get_node(&root, "resources");

        let mut version = "default".to_string();
        if let Some(jnlp_node) = get_node(&root, "jnlp") {
            if let Some(v) = jnlp_node.attribute("version") {
                // Sanitize to prevent path traversal (e.g. "../../.ssh")
                version = v.replace(['/', '\\', '.'], "_");
            }
        }

        let sanitized_name = conn_name
            .to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>();
        let id_prefix = &conn_id[..conn_id.len().min(8)];
        let cache_folder = format!("{}_{}", sanitized_name, id_prefix);
        let jar_dir = cache_dir.join(cache_folder).join(&version);
        if donotcache && jar_dir.exists() {
            println!("removing directory {:?}", jar_dir);
            std::fs::remove_dir_all(&jar_dir)?;
        }

        let dir_path = jar_dir.as_path();
        if !jar_dir.exists() {
            println!("creating directory {:?}", jar_dir);
            std::fs::create_dir_all(dir_path)?;
        }

        let mut j2ses = None;
        if let Some(resources_node) = resources_node {
            j2ses = get_j2ses(&resources_node);
            download_jars(&resources_node, &client, dir_path, &base_url, on_progress)?;
        }

        let loaded_at = SystemTime::now();
        let ws = WebstartFile {
            url: base_url.to_string(),
            main_class,
            jar_dir,
            args,
            loaded_at,
            j2ses,
        };

        Ok(ws)
    }

    pub fn run(&self, ce: Arc<ConnectionEntry>, console_jar: Option<PathBuf>) -> Result<(), Error> {
        let itr = self.jar_dir.read_dir()?;
        let mut mirth_jars = Vec::new();
        let mut other_jars = Vec::new();
        for e in itr {
            let e = e?;
            if e.metadata()?.is_dir() {
                continue;
            }
            let file_path = e.path();
            if file_path.extension().and_then(|e| e.to_str()) != Some("jar") {
                continue;
            }
            let file_name = match file_path.file_name().and_then(|f| f.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };
            let file_path_str = match file_path.to_str() {
                Some(p) => p.to_string(),
                None => continue,
            };

            // MirthConnect's own jars contain some overridden classes
            // of the dependent libraries and hence must be loaded first
            // https://forums.mirthproject.io/forum/mirth-connect/support/15524-using-com-mirth-connect-client-core-client
            if file_name.starts_with("mirth") {
                mirth_jars.push(file_path_str);
            } else {
                other_jars.push(file_path_str);
            }
        }

        mirth_jars.sort();
        other_jars.sort();
        let classpath_separator = if cfg!(windows) { ";" } else { ":" };
        mirth_jars.extend(other_jars);
        let classpath = mirth_jars.join(classpath_separator);

        let mut cmd;
        let java_home = ce.java_home.trim();
        if java_home.is_empty() {
            cmd = Command::new("java")
        } else {
            let java_bin = PathBuf::from(java_home).join("bin").join("java");
            cmd = Command::new(java_bin);
        }

        println!("using java from: {:?}", cmd.get_program().to_str());

        if let Some(ref vm_args) = self.j2ses {
            for va in vm_args {
                // if there are VM args for java version >= 1.9
                // then set the JDK_JAVA_OPTIONS environment variable
                // this will be ignored by java version <= 1.8
                if va.version.contains("1.9") {
                    if let Some(java_vm_args) = &va.java_vm_args {
                        let filtered = sanitize_vm_args(java_vm_args);
                        if !filtered.is_empty() {
                            println!("setting JDK_JAVA_OPTIONS environment variable with the java-vm-args given for version {} in JNLP file", va.version);
                            cmd.env("JDK_JAVA_OPTIONS", &filtered);
                        }
                    }
                }
            }
        }

        let heap = ce.heap_size.trim();
        if !heap.is_empty() {
            cmd.arg(format!("-Xmx{}", heap));
        }

        if let Some(args) = ce.java_args.as_deref() {
            let sanitized = sanitize_vm_args(args);
            if !sanitized.is_empty() {
                cmd.args(sanitized.split_whitespace());
            }
        }

        cmd.arg("-cp")
            .arg(classpath)
            .arg(&self.main_class)
            .args(&self.args);

        if let Some(ref username) = ce.username {
            cmd.arg(username);
            if let Some(ref password) = ce.password {
                cmd.arg(password);
            }
        }

        if ce.show_console {
            let console_jar = console_jar
                .ok_or(Error::msg("Java console jar path not provided"))?;

            // Launch the Java Console as a separate Java Swing process
            let java_bin = if java_home.is_empty() {
                PathBuf::from("java")
            } else {
                PathBuf::from(java_home).join("bin").join("java")
            };

            let mut console_cmd = Command::new(&java_bin);
            console_cmd
                .arg("-Xmx256m")
                .arg("-cp")
                .arg(console_jar.to_str().ok_or_else(|| Error::msg("console jar path is not valid UTF-8"))?)
                .arg("com.innovarhealthcare.launcher.JavaConsoleDialog")
                .stdin(Stdio::piped());
            #[cfg(windows)]
            console_cmd.creation_flags(CREATE_NO_WINDOW);
            let mut console_proc = console_cmd.spawn()?;

            // Launch the target process with stdout piped to the console
            // stderr inherits (default) so it doesn't block the process
            cmd.stdout(Stdio::piped());
            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);
            let mut target_proc = cmd.spawn()?;

            // Pipe target stdout → console stdin in a background thread
            let target_stdout = target_proc.stdout.take();
            let console_stdin = console_proc.stdin.take();
            if let (Some(stdout), Some(stdin)) = (target_stdout, console_stdin) {
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let mut stdout = stdout;
                    let mut stdin = stdin;
                    let mut buf = [0u8; 1024];
                    loop {
                        match stdout.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let _ = stdin.write_all(&buf[..n]);
                                let _ = stdin.flush();
                            }
                            Err(_) => break,
                        }
                    }
                    // Target process exited — kill the console window
                    let _ = console_proc.kill();
                });
            }
        } else {
            let log_path = self.jar_dir.join("launch.log");
            let log_file = File::create(&log_path);
            match log_file {
                Ok(log_file) => {
                    let stderr_log = log_file.try_clone().unwrap_or_else(|_| File::create(&log_path).expect("failed to create log file"));
                    cmd.stdout(Stdio::from(log_file));
                    cmd.stderr(Stdio::from(stderr_log));
                }
                Err(_) => {
                    cmd.stdout(Stdio::inherit());
                    cmd.stderr(Stdio::inherit());
                }
            }
            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);
            println!("launching: {:?}", cmd);
            cmd.spawn()?;
        }

        Ok(())
    }

    pub fn verify(&self, cert_store: &X509StoreRef, trusted_certs: &[X509]) -> Result<(), VerificationError> {
        let mut jar_files = Vec::with_capacity(128);
        let itr = self
            .jar_dir
            .read_dir()
            .map_err(|e| VerificationError {
                cert: None,
                msg: format!("failed to read jar files directory: {}", e),
            })?;
        for e in itr {
            let e = e.map_err(|e| VerificationError {
                cert: None,
                msg: format!("failed to list directory entry: {}", e),
            })?;
            let file_path = e.path();
            if file_path.extension().and_then(|e| e.to_str()) == Some("jar") {
                jar_files.push(file_path);
            }
        }

        jar_files.sort_unstable();
        println!("{:?}", jar_files);

        let mut verified_count = 0usize;
        let mut skipped_count = 0usize;
        for jf in &jar_files {
            let file_path = jf.to_str().ok_or_else(|| VerificationError {
                cert: None,
                msg: format!("jar file path is not valid UTF-8: {:?}", jf),
            })?;
            // Read the JAR into memory once — used for both hashing and verification
            let jar_data = std::fs::read(jf).map_err(|e| VerificationError {
                cert: None,
                msg: format!("failed to read jar file {:?}: {}", jf, e),
            })?;
            let mut hasher = Sha256::new();
            hasher.update(&jar_data);
            let hash = openssl::base64::encode_block(hasher.finalize().as_slice());

            let sidecar = jf.with_extension("jar.verified");
            if let Ok(stored) = std::fs::read_to_string(&sidecar) {
                if stored.trim() == hash {
                    skipped_count += 1;
                    println!("skipping verification of {} (already verified)", file_path);
                    continue;
                }
            }

            verify_jar(file_path, &jar_data, cert_store, trusted_certs)?;
            let _ = std::fs::write(&sidecar, &hash);
            verified_count += 1;
        }
        println!("verification complete: {} verified, {} skipped (unchanged)", verified_count, skipped_count);
        Ok(())
    }
}

struct JarTask {
    url: String,
    file_path: PathBuf,
    file_name: String,
    hash: Option<String>,
}

fn download_jars(
    resources_node: &Node,
    client: &Client,
    dir_path: &Path,
    base_url: &str,
    on_progress: &Channel<serde_json::Value>,
) -> Result<(), Error> {
    // Phase 1: collect all JAR tasks, resolving extensions sequentially
    let mut tasks = Vec::new();
    collect_jar_tasks(resources_node, client, dir_path, base_url, &mut tasks, on_progress)?;

    // Phase 2: check cache and build download list
    let mut to_download = Vec::new();
    for task in &tasks {
        let _ = on_progress.send(serde_json::json!({
            "message": format!("Verifying cache file {}", task.file_name),
        }));
        if has_file_changed(&task.file_path, task.hash.as_deref())? {
            to_download.push(task);
        }
    }

    if to_download.is_empty() {
        return Ok(());
    }

    let total = to_download.len();
    let _ = on_progress.send(serde_json::json!({
        "message": format!("Downloading {} JARs...", total),
    }));

    // Phase 3: download in parallel
    let completed = AtomicUsize::new(0);
    let first_error: Mutex<Option<Error>> = Mutex::new(None);

    std::thread::scope(|s| {
        let num_threads = to_download.len().min(DOWNLOAD_THREADS);
        let chunk_size = (to_download.len() + num_threads - 1) / num_threads;
        for chunk in to_download.chunks(chunk_size) {
            let client = client;
            let completed = &completed;
            let first_error = &first_error;
            let on_progress = on_progress;
            s.spawn(move || {
                for task in chunk {
                    // Stop if another thread hit an error
                    if first_error.lock().expect("error lock poisoned").is_some() {
                        return;
                    }
                    let result = (|| -> Result<(), Error> {
                        let mut resp = client.get(&task.url).send()?;
                        let mut f = File::create(&task.file_path)?;
                        resp.copy_to(&mut f)?;
                        let _ = std::fs::remove_file(task.file_path.with_extension("jar.verified"));
                        let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                        let _ = on_progress.send(serde_json::json!({
                            "message": format!("Downloaded {} ({}/{})", task.file_name, done, total),
                        }));
                        Ok(())
                    })();
                    if let Err(e) = result {
                        let mut err = first_error.lock().expect("error lock poisoned");
                        if err.is_none() {
                            *err = Some(e);
                        }
                        return;
                    }
                }
            });
        }
    });

    let err = first_error.into_inner().expect("error lock poisoned");
    if let Some(e) = err {
        return Err(e);
    }

    Ok(())
}

fn collect_jar_tasks(
    resources_node: &Node,
    client: &Client,
    dir_path: &Path,
    base_url: &str,
    tasks: &mut Vec<JarTask>,
    on_progress: &Channel<serde_json::Value>,
) -> Result<(), Error> {
    for n in resources_node.children() {
        let jar = n.has_tag_name("jar");
        let extension = n.has_tag_name("extension");

        if !jar && !extension {
            continue;
        }

        let href = match n.attribute("href") {
            Some(h) => h,
            None => continue,
        };
        let url = format!("{}/{}", base_url, href);

        if jar {
            let file_name = get_file_name_from_path(href).to_string();
            let file_path = dir_path.join(&file_name);
            let hash = n.attribute("sha256").map(|s| s.to_string());
            tasks.push(JarTask { url, file_path, file_name, hash });
        } else if extension {
            let ext_name = get_file_name_from_path(href);
            let ext_cache_path = dir_path.join(ext_name);
            let data = if ext_cache_path.exists() {
                let _ = on_progress.send(serde_json::json!({
                    "message": format!("Loading cached extension {}...", ext_name),
                }));
                std::fs::read_to_string(&ext_cache_path)?
            } else {
                let _ = on_progress.send(serde_json::json!({
                    "message": format!("Fetching extension {}...", ext_name),
                }));
                let r = client.get(url).send()?;
                let body = r.text()?;
                let _ = std::fs::write(&ext_cache_path, &body);
                body
            };
            let doc = roxmltree::Document::parse(&data)?;
            let root = doc.root();
            let resources_node = get_node(&root, "resources");
            let ext_base_url = format!("{}/webstart/extensions", base_url);
            if let Some(resources_node) = resources_node {
                collect_jar_tasks(&resources_node, client, dir_path, &ext_base_url, tasks, on_progress)?;
            }
        }
    }
    Ok(())
}

/// Filter JNLP java-vm-args to block flags that could execute arbitrary code.
fn sanitize_vm_args(args: &str) -> String {
    let dangerous_prefixes: &[&str] = &[
        "-javaagent:",
        "-agentpath:",
        "-agentlib:",
        "-xbootclasspath",
        "-xx:onoutofmemoryerror",
        "-xx:onoutofmemoryerror=",
        "-xx:onerror",
        "-xx:onerror=",
    ];

    args.split_whitespace()
        .filter(|arg| {
            let lower = arg.to_lowercase();
            let dominated = dangerous_prefixes.iter().any(|p| lower.starts_with(p));
            if dominated {
                println!("sanitize_vm_args: dropping dangerous flag: {}", arg);
            }
            !dominated
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn get_file_name_from_path(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn get_client_args(root: &Node) -> Vec<String> {
    let mut args = Vec::new();
    for n in root.descendants() {
        if n.has_tag_name("argument") {
            if let Some(text) = n.text() {
                args.push(text.to_string());
            }
        }
    }
    args
}

fn get_j2ses(resources: &Node) -> Option<Vec<J2se>> {
    let mut j2ses = Vec::new();
    for n in resources.descendants() {
        if n.has_tag_name("j2se") {
            // only consider those that have java-vm-args and version
            if let Some(java_vm_args) = n.attribute("java-vm-args") {
                if let Some(version) = n.attribute("version") {
                    let java_vm_args = Some(java_vm_args.to_string());
                    let j2se = J2se {
                        java_vm_args,
                        version: version.to_string(),
                    };
                    j2ses.push(j2se);
                }
            }
        }
    }
    if !j2ses.is_empty() {
        return Some(j2ses);
    }
    None
}

fn get_node<'a>(root: &'a Node, tag_name: &str) -> Option<Node<'a, 'a>> {
    root.descendants().find(|n| {
        if n.has_tag_name(tag_name) {
            return true;
        }
        return false;
    })
}

fn normalize_url(u: &str) -> Result<(String, String), Error> {
    let parsed_url = Url::parse(u)?;
    let mut reconstructed_url = String::with_capacity(u.len());
    reconstructed_url.push_str(parsed_url.scheme());
    reconstructed_url.push_str("://");
    let host = parsed_url.host_str().map_or("", |h| h);
    reconstructed_url.push_str(host);
    let port = parsed_url
        .port()
        .map_or("".to_string(), |p| format!(":{}", p));
    reconstructed_url.push_str(&port);
    reconstructed_url.push('/');
    let path_parts = parsed_url.path().split_terminator("/");
    for pp in path_parts {
        if !pp.is_empty() {
            reconstructed_url.push_str(pp);
            reconstructed_url.push('/');
        }
    }

    reconstructed_url.pop(); // remove the trailing /
    let host = format!("{}{}", host, port).replace(":", "_");
    Ok((reconstructed_url, host))
}

fn sha256_of_file(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(openssl::base64::encode_block(hasher.finalize().as_slice()))
}


fn has_file_changed(jar_file_path: &Path, hash_in_jnlp: Option<&str>) -> Result<bool, Error> {
    if let Some(hash_in_jnlp) = hash_in_jnlp {
        if let Some(current_hash) = sha256_of_file(jar_file_path) {
            return Ok(hash_in_jnlp != &current_hash);
        }
    }
    Ok(true)
}
#[cfg(test)]
mod tests {
    use crate::webstart::normalize_url;
    use anyhow::Error;

    #[test]
    pub fn test_normalize_url() -> Result<(), Error> {
        let candidates = [
            ("https://localhost:8443", "https://localhost:8443"),
            ("https://localhost:8443/", "https://localhost:8443"),
            ("https://localhost:8443//", "https://localhost:8443"),
            (
                "https://localhost:8443//a///bv",
                "https://localhost:8443/a/bv",
            ),
        ];

        for (src, expected) in candidates {
            let (reconstructed_url, _host) = normalize_url(src)?;
            assert_eq!(expected, &reconstructed_url);
        }
        Ok(())
    }
}

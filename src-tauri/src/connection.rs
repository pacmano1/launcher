// Copyright (c) Kiran Ayyagari. All rights reserved.
// Copyright (c) Diridium Technologies Inc. All rights reserved.
// Licensed under the MPL-2.0 License. See LICENSE file in the project root.

use anyhow::Error;
use home::env::Env;
use home::env::OS_ENV;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub address: String,
    #[serde(rename = "heapSize")]
    pub heap_size: String,
    pub id: String,
    #[serde(rename = "javaHome")]
    pub java_home: String,
    #[serde(rename = "javaArgs")]
    pub java_args: Option<String>,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default = "get_default_group")]
    pub group: String,
    #[serde(default = "get_default_notes")]
    pub notes: String,
    #[serde(default = "get_default_donotcache")]
    pub donotcache: bool,
    #[serde(default, rename = "lastConnected")]
    pub last_connected: Option<i64>,
    #[serde(default, rename = "showConsole")]
    pub show_console: bool,
    #[serde(default = "get_default_engine_type", rename = "engineType")]
    pub engine_type: String,
}

pub struct ConnectionStore {
    con_cache: Mutex<HashMap<String, Arc<ConnectionEntry>>>,
    con_location: PathBuf,
    pub cache_dir: PathBuf,
    pub logs_dir: PathBuf,
}

impl Default for ConnectionEntry {
    fn default() -> Self {
        ConnectionEntry {
            address: String::new(),
            heap_size: String::from("512m"),
            id: Uuid::new_v4().to_string(),
            java_home: find_java_home(),
            java_args: Some(String::new()),
            name: String::new(),
            username: None,
            password: None,
            group: get_default_group(),
            notes: get_default_notes(),
            donotcache: get_default_donotcache(),
            last_connected: None,
            show_console: false,
            engine_type: get_default_engine_type(),
        }
    }
}

impl ConnectionStore {
    pub fn init(data_dir_path: PathBuf) -> Result<Self, Error> {
        let con_location = data_dir_path.join("launcher-data.json");
        let mut con_location_file = File::open(&con_location);
        if let Err(_e) = con_location_file {
            con_location_file = File::create(&con_location);
        }
        let con_location_file = con_location_file?;

        let mut cache = HashMap::new();
        let data: serde_json::Result<HashMap<String, ConnectionEntry>> =
            serde_json::from_reader(con_location_file);
        match data {
            Ok(data) => {
                for (id, ce) in data {
                    cache.insert(id, Arc::new(ce));
                }
            }
            Err(e) => {
                info!("{}", e);
            }
        }

        let cache_dir = data_dir_path.join("cache");
        if !cache_dir.exists() {
            fs::create_dir(&cache_dir)?;
        }

        let logs_dir = data_dir_path.join("logs");
        if !logs_dir.exists() {
            fs::create_dir(&logs_dir)?;
        }

        Ok(ConnectionStore {
            con_location,
            con_cache: Mutex::new(cache),
            cache_dir,
            logs_dir,
        })
    }

    pub fn to_json_array_string(&self) -> String {
        let cache = self.con_cache.lock().expect("connection cache lock poisoned");
        let entries: Vec<&Arc<ConnectionEntry>> = cache.values().collect();
        serde_json::to_string(&entries).unwrap_or_else(|_| String::from("[]"))
    }

    pub fn get(&self, id: &str) -> Option<Arc<ConnectionEntry>> {
        let cs = self.con_cache.lock().expect("connection cache lock poisoned");
        cs.get(id).map(Arc::clone)
    }

    pub fn save(&self, mut ce: ConnectionEntry) -> Result<String, Error> {
        if ce.id.is_empty() {
            ce.id = uuid::Uuid::new_v4().to_string();
        }

        let mut jh = ce.java_home.trim().to_string();
        if jh.is_empty() {
            jh = find_java_home();
        }
        ce.java_home = jh;

        if let Some(ref username) = ce.username {
            let username = username.trim();
            if username.is_empty() {
                ce.username = None;
            }
        }

        if let Some(ref password) = ce.password {
            let password = password.trim();
            if password.is_empty() {
                ce.password = None;
            }
        }

        let data = serde_json::to_string(&ce)?;
        self.con_cache
            .lock()
            .expect("connection cache lock poisoned")
            .insert(ce.id.clone(), Arc::new(ce));
        self.write_connections_to_disk()?;
        Ok(data)
    }

    pub fn delete(&self, id: &str) -> Result<(), Error> {
        self.con_cache.lock().expect("connection cache lock poisoned").remove(id);
        self.write_connections_to_disk()?;
        Ok(())
    }

    pub fn import(&self, file_path: &str, overwrite: bool) -> Result<String, Error> {
        let f = File::open(file_path)?;
        let data: Vec<ConnectionEntry> = serde_json::from_reader(f)?;

        let mut cache = self.con_cache.lock().expect("connection cache lock poisoned");
        let duplicates: Vec<String> = data
            .iter()
            .filter(|ce| cache.contains_key(&ce.id))
            .map(|ce| ce.name.clone())
            .collect();

        if !duplicates.is_empty() && !overwrite {
            drop(cache);
            let result = serde_json::json!({
                "status": "duplicates",
                "names": duplicates,
                "total": data.len(),
            });
            return Ok(result.to_string());
        }

        let java_home = find_java_home();
        let count = data.len();
        for mut ce in data {
            ce.java_home = java_home.clone();
            cache.insert(ce.id.clone(), Arc::new(ce));
        }
        drop(cache);

        self.write_connections_to_disk()?;
        let result = serde_json::json!({
            "status": "ok",
            "total": count,
        });
        Ok(result.to_string())
    }

    fn write_connections_to_disk(&self) -> Result<(), Error> {
        let c = self.con_cache.lock().expect("connection cache lock poisoned");
        let val = serde_json::to_string_pretty(&*c)?;
        let mut f = File::create(&self.con_location).map_err(|e| {
            warn!("unable to open file for writing: {}", e);
            Error::new(e)
        })?;
        f.write_all(val.as_bytes())?;
        Ok(())
    }

    pub fn update_last_connected(&self, id: &str) -> Result<(), Error> {
        let mut cache = self.con_cache.lock().expect("connection cache lock poisoned");
        if let Some(entry) = cache.get(id) {
            let mut updated = (**entry).clone();
            updated.last_connected = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock is before UNIX epoch")
                    .as_millis() as i64,
            );
            cache.insert(id.to_string(), Arc::new(updated));
        }
        drop(cache);
        self.write_connections_to_disk()?;
        Ok(())
    }

    pub fn get_all_groups(&self) -> Result<HashSet<String>, Error> {
        let connections = self.con_cache
            .lock()
            .expect("connection cache lock poisoned");

        let mut groups: HashSet<String> = HashSet::new();
        groups.insert(get_default_group());
        groups.extend(connections.values().map(|ce| ce.group.clone()));
        Ok(groups)
    }

    pub fn get_all_engine_types(&self) -> Result<HashSet<String>, Error> {
        let connections = self.con_cache
            .lock()
            .expect("connection cache lock poisoned");

        let mut engine_types: HashSet<String> = HashSet::new();
        engine_types.insert(get_default_engine_type());
        engine_types.extend(connections.values().map(|ce| ce.engine_type.clone()));
        Ok(engine_types)
    }
}

pub fn find_java_home() -> String {
    let mut java_home = String::new();
    if let Some(jh) = OS_ENV.var_os("JAVA_HOME") {
        if let Some(jh_str) = jh.to_str() {
            java_home = String::from(jh_str);
            info!("JAVA_HOME is set to {}", java_home);
        } else {
            warn!("JAVA_HOME contains non-UTF-8 characters, ignoring");
        }
    }

    #[cfg(target_os = "macos")]
    if java_home.is_empty() {
        let out = Command::new("/usr/libexec/java_home")
            .args(["-v", "1.8"])
            .output();
        if let Ok(out) = out {
            if out.status.success() {
                match String::from_utf8(out.stdout) {
                    Ok(jh) => {
                        info!("/usr/libexec/java_home -v 1.8 returned {}", jh);
                        java_home = jh.trim().to_string();
                    }
                    Err(e) => {
                        warn!("java_home output was not valid UTF-8: {}", e);
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    if java_home.is_empty() {
        let out = Command::new("where")
            .arg("java")
            .output();
        if let Ok(out) = out {
            if out.status.success() {
                if let Ok(paths) = String::from_utf8(out.stdout) {
                    if let Some(first) = paths.lines().next() {
                        let java_path = PathBuf::from(first.trim());
                        if let Some(bin_dir) = java_path.parent() {
                            if let Some(home_dir) = bin_dir.parent() {
                                if let Some(home_str) = home_dir.to_str() {
                                    info!("derived JAVA_HOME from PATH: {}", home_str);
                                    java_home = home_str.to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    java_home
}

fn get_default_group() -> String {
    String::from("Default")
}

fn get_default_notes() -> String {
    String::new()
}

fn get_default_donotcache() -> bool {
    false
}

fn get_default_engine_type() -> String {
    String::from("Open Integration Engine")
}

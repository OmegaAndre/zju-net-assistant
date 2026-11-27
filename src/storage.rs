use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, path::PathBuf};
use windows_sys::Win32::{
    Foundation::*,
    Security::Credentials::*,
    System::{Registry::*, SystemInformation::*},
};
use zeroize::{Zeroize, Zeroizing};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("ZJU_ASSISTANT_DATA_DIR") {
        return PathBuf::from(p);
    }
    PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_else(|| ".".into()))
        .join("ZjuNetAssistant")
}
pub fn time() -> String {
    unsafe {
        let mut t = std::mem::zeroed::<SYSTEMTIME>();
        GetLocalTime(&mut t);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub username: String,
    pub remember: bool,
    pub auto: bool,
    pub interval: u64,
    pub adapter: String,
    pub portal: String,
    pub startup: bool,
    pub cached_hosts: BTreeMap<String, String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            username: String::new(),
            remember: true,
            auto: true,
            interval: 60,
            adapter: String::new(),
            portal: String::new(),
            startup: false,
            cached_hosts: BTreeMap::new(),
        }
    }
}
pub fn load() -> Result<Config, String> {
    match fs::read(data_dir().join("config.json")) {
        Ok(b) => {
            let mut c: Config =
                serde_json::from_slice(&b).map_err(|_| "配置文件损坏，已使用默认设置")?;
            c.interval = c.interval.clamp(15, 3600);
            if !c.portal.is_empty() && !crate::protocol::HOSTS.contains(&c.portal.as_str()) {
                c.portal.clear();
            }
            c.cached_hosts
                .retain(|_, v| crate::protocol::HOSTS.contains(&v.as_str()));
            Ok(c)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(_) => Err("无法读取配置文件".into()),
    }
}
pub fn save(c: &Config) -> Result<(), String> {
    fs::create_dir_all(data_dir()).map_err(|_| "无法创建配置目录")?;
    let temp = data_dir().join("config.tmp");
    let mut file = fs::File::create(&temp).map_err(|_| "无法写入配置")?;
    file.write_all(&serde_json::to_vec_pretty(c).map_err(|_| "配置序列化失败")?)
        .map_err(|_| "无法写入配置")?;
    file.sync_all().map_err(|_| "无法同步配置")?;
    drop(file);
    // Windows rename cannot replace; use atomic MoveFileExW through a tiny FFI.
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    unsafe {
        if MoveFileExW(
            wide(&temp.to_string_lossy()).as_ptr(),
            wide(&data_dir().join("config.json").to_string_lossy()).as_ptr(),
            1 | 8,
        ) == 0
        {
            return Err("无法替换配置文件".into());
        }
    }
    Ok(())
}
fn credential_target() -> String {
    // Isolate test instances from the real account vault.
    if std::env::var_os("ZJU_ASSISTANT_DATA_DIR").is_some() {
        format!("ZjuNetAssistant/test/{}", data_dir().display())
    } else {
        "ZjuNetAssistant/campus-network".into()
    }
}
pub fn read_password(username: &str) -> Result<Zeroizing<String>, String> {
    unsafe {
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        if CredReadW(
            wide(&credential_target()).as_ptr(),
            CRED_TYPE_GENERIC,
            0,
            &mut cred,
        ) == 0
        {
            return if GetLastError() == ERROR_NOT_FOUND {
                Ok(Zeroizing::new(String::new()))
            } else {
                Err("无法读取 Windows 凭据".into())
            };
        }
        let c = &*cred;
        let mut len = 0;
        while *c.UserName.add(len) != 0 {
            len += 1;
        }
        let stored_user = String::from_utf16_lossy(std::slice::from_raw_parts(c.UserName, len));
        let result = if stored_user == username && c.CredentialBlobSize > 0 {
            let bytes = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize);
            String::from_utf8(bytes.to_vec())
                .map(Zeroizing::new)
                .map_err(|_| "保存的凭据格式异常".to_string())
        } else {
            Ok(Zeroizing::new(String::new()))
        };
        if c.CredentialBlobSize > 0 {
            std::slice::from_raw_parts_mut(c.CredentialBlob, c.CredentialBlobSize as usize)
                .zeroize();
        }
        CredFree(cred.cast());
        result
    }
}
pub fn write_password(username: &str, password: &str) -> Result<(), String> {
    unsafe {
        let mut target = wide(&credential_target());
        let mut user = wide(username);
        let mut blob = Zeroizing::new(password.as_bytes().to_vec());
        let cred = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            UserName: user.as_mut_ptr(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..std::mem::zeroed()
        };
        if CredWriteW(&cred, 0) == 0 {
            return Err(format!(
                "保存 Windows 凭据失败（系统错误 {}）",
                GetLastError()
            ));
        }
    }
    Ok(())
}
pub fn delete_password() -> Result<(), String> {
    unsafe {
        if CredDeleteW(wide(&credential_target()).as_ptr(), CRED_TYPE_GENERIC, 0) == 0
            && GetLastError() != ERROR_NOT_FOUND
        {
            return Err("移除 Windows 凭据失败".into());
        }
    }
    Ok(())
}
pub fn startup(enabled: bool) -> Result<(), String> {
    if std::env::var_os("ZJU_ASSISTANT_DATA_DIR").is_some() {
        return Ok(());
    }
    unsafe {
        let mut key = 0;
        if RegCreateKeyExW(
            HKEY_CURRENT_USER,
            wide("Software\\Microsoft\\Windows\\CurrentVersion\\Run").as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        ) != 0
        {
            return Err("无法访问当前用户启动设置".into());
        }
        let name = wide("ZjuNetAssistant");
        let result = if enabled {
            let exe = std::env::current_exe().map_err(|_| "无法获取程序位置")?;
            let value = wide(&format!("\"{}\" --background", exe.display()));
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            )
        } else {
            RegDeleteValueW(key, name.as_ptr())
        };
        RegCloseKey(key);
        if result != 0 && !(result == ERROR_FILE_NOT_FOUND && !enabled) {
            return Err("设置登录后启动失败".into());
        }
    }
    Ok(())
}

pub fn log(line: &str) -> std::io::Result<()> {
    let dir = data_dir();
    fs::create_dir_all(&dir)?;
    let path = dir.join("events.log");
    if fs::metadata(&path).is_ok_and(|m| m.len() >= 1024 * 1024) {
        let oldest = dir.join("events.4.log");
        if oldest.exists() {
            fs::remove_file(oldest)?;
        }
        for i in (1..4).rev() {
            let a = dir.join(format!("events.{i}.log"));
            if a.exists() {
                fs::rename(a, dir.join(format!("events.{}.log", i + 1)))?;
            }
        }
        fs::rename(&path, dir.join("events.1.log"))?;
    }
    writeln!(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?,
        "{line}"
    )
}

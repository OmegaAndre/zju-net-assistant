use crate::{
    http::{Direct, Transport},
    network::{self, Adapter},
    protocol::{self, LoginResult, Online},
    storage::{self, Config},
};
use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use url::Url;
use windows_sys::Win32::{
    Foundation::HANDLE, NetworkManagement::IpHelper::*, Networking::WinSock::AF_UNSPEC,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CredentialStorage {
    Checking,
    NotSaved,
    Saved,
    SessionOnly,
    Unavailable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SaveStatus {
    Idle,
    Saving,
    Saved,
    Failed,
}

#[derive(Clone)]
pub struct Model {
    pub config: Config,
    pub adapters: Vec<Adapter>,
    pub state: String,
    pub internet: String,
    pub adapter: String,
    pub ip: String,
    pub portal_ip: String,
    pub portal: String,
    pub checked: String,
    pub events: VecDeque<String>,
    pub busy: bool,
    pub credential_blocked: bool,
    pub credential_storage: CredentialStorage,
    pub save_status: SaveStatus,
}
impl Model {
    pub fn new(config: Config) -> Self {
        let credential_storage = if config.remember && !config.username.is_empty() {
            CredentialStorage::Checking
        } else {
            CredentialStorage::NotSaved
        };
        Self {
            config,
            adapters: Vec::new(),
            state: "等待检查".into(),
            internet: "尚未检查".into(),
            adapter: "—".into(),
            ip: "—".into(),
            portal_ip: "—".into(),
            portal: "自动选择".into(),
            checked: "—".into(),
            events: VecDeque::new(),
            busy: false,
            credential_blocked: false,
            credential_storage,
            save_status: SaveStatus::Idle,
        }
    }
}
pub type Shared = Arc<Mutex<Model>>;
pub enum Command {
    Check,
    Login,
    Save {
        config: Config,
        password: Option<Zeroizing<String>>,
        auto_override: Option<bool>,
    },
    Auto(bool),
    Network,
    Stop,
}
#[derive(Clone)]
pub struct Portal {
    pub host: String,
    pub acid: String,
    pub ip: Ipv4Addr,
    pub online: Online,
}

fn get_ok<T: Transport>(t: &T, url: &Url) -> Result<String, String> {
    let response = t.get(url)?;
    if response.status != 200 {
        return Err(format!("门户返回 HTTP {}", response.status));
    }
    Ok(response.body)
}
fn status<T: Transport>(t: &T, host: &str) -> Result<Online, String> {
    let u =
        Url::parse(&format!("https://{host}/cgi-bin/rad_user_info")).map_err(|_| "门户地址无效")?;
    Ok(protocol::online(&get_ok(t, &u)?))
}
pub fn inspect<T: Transport>(t: &T, host: &str, source: Ipv4Addr) -> Result<Portal, String> {
    let base = Url::parse(&format!("https://{host}/")).map_err(|_| "门户地址无效")?;
    if !protocol::trusted_url(&base) {
        return Err("认证入口不在信任列表".into());
    }
    // Checking an existing session does not require fetching the login page.
    if let Ok(Online::Yes(ip)) = status(t, host) {
        return Ok(Portal {
            host: host.into(),
            acid: String::new(),
            ip: ip.unwrap_or(source),
            online: Online::Yes(ip),
        });
    }
    let mut url = base;
    for _ in 0..4 {
        if !protocol::trusted_url(&url) {
            return Err("门户重定向至不受信任的地址，已停止".into());
        }
        let response = t.get(&url)?;
        if (300..400).contains(&response.status) {
            let location = response.location.ok_or("门户重定向缺少目标地址")?;
            url = url.join(&location).map_err(|_| "门户重定向地址异常")?;
            // Discovering HTTP locations is allowed, but credentials always use HTTPS.
            if url.scheme() == "http"
                && url.host_str().is_some_and(|h| protocol::HOSTS.contains(&h))
            {
                url.set_scheme("https").map_err(|_| "门户协议无效")?;
            }
            continue;
        }
        if response.status != 200 {
            return Err(format!("门户返回 HTTP {}", response.status));
        }
        if let Some(location) = protocol::meta_redirect(&response.body) {
            url = url.join(&location).map_err(|_| "门户跳转地址异常")?;
            continue;
        }
        let (acid, ip) = protocol::portal_fields(&response.body, &url)?;
        let actual_host = url.host_str().ok_or("门户无主机名")?.to_string();
        let online = status(t, &actual_host)?;
        return Ok(Portal {
            host: actual_host,
            acid,
            ip: ip.unwrap_or(source),
            online,
        });
    }
    Err("门户重定向次数过多".into())
}

pub fn authenticate<T: Transport>(
    t: &T,
    portal: &Portal,
    user: &str,
    pass: &str,
) -> Result<LoginResult, String> {
    if !protocol::HOSTS.contains(&portal.host.as_str()) {
        return Err("认证入口不受信任".into());
    }
    let mut challenge_url = Url::parse(&format!("https://{}/cgi-bin/get_challenge", portal.host))
        .map_err(|_| "门户地址无效")?;
    challenge_url.query_pairs_mut().extend_pairs([
        ("callback", "zju_cb"),
        ("username", user),
        ("ip", &portal.ip.to_string()),
    ]);
    let response = protocol::json_response(&get_ok(t, &challenge_url)?)?;
    let token = response["challenge"]
        .as_str()
        .ok_or("门户未返回有效挑战值")?;
    let query = protocol::login_query(user, pass, portal.ip, &portal.acid, token)?;
    let mut login = Url::parse(&format!("https://{}/cgi-bin/srun_portal", portal.host))
        .map_err(|_| "门户地址无效")?;
    login.set_query(Some(&query));
    // get_ok never follows redirects. A login redirect cannot leak parameters to another host.
    let result = protocol::login_result(&protocol::json_response(&get_ok(t, &login)?)?);
    Ok(result)
}

const INTERNET_PROBES: [(&str, &str); 3] = [
    ("小米", "https://connect.rom.miui.com/generate_204"),
    ("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"),
    ("Google", "https://www.google.com/generate_204"),
];

fn internet<T: Transport>(transport: &T, preferred: usize) -> Option<usize> {
    for offset in 0..INTERNET_PROBES.len() {
        let index = (preferred + offset) % INTERNET_PROBES.len();
        let (name, address) = INTERNET_PROBES[index];
        let url = Url::parse(address).expect("constant URL");
        let Ok(response) = transport.get(&url) else {
            continue;
        };
        if response.location.is_some() {
            continue;
        }
        let matches = if name == "Cloudflare" {
            response.status == 200
                && response
                    .body
                    .lines()
                    .any(|line| line == "h=www.cloudflare.com")
                && response.body.lines().any(|line| {
                    line.strip_prefix("colo=").is_some_and(|colo| {
                        colo.len() == 3 && colo.bytes().all(|b| b.is_ascii_uppercase())
                    })
                })
        } else {
            response.status == 204 && response.body.is_empty()
        };
        if matches {
            return Some(index);
        }
    }
    None
}
pub fn candidates(config: &Config, adapter: &Adapter) -> Vec<String> {
    if !config.portal.is_empty() {
        return vec![config.portal.clone()];
    }
    let mut out = Vec::new();
    if let Some(host) = config.cached_hosts.get(&adapter.key()) {
        if protocol::HOSTS.contains(&host.as_str()) {
            out.push(host.clone());
        }
    }
    for h in protocol::HOSTS {
        if !out.iter().any(|s| s == h) {
            out.push(h.into());
        }
    }
    out
}
struct Runner {
    shared: Shared,
    wake: Box<dyn Fn() + Send>,
    password: Zeroizing<String>,
    failures: u32,
    blocked: bool,
    preferred_probe: usize,
    last_outcome: String,
}
impl Runner {
    fn update(&self, f: impl FnOnce(&mut Model)) {
        f(&mut self.shared.lock().unwrap());
        (self.wake)();
    }
    fn event(&self, text: &str) {
        let line = format!("{}  {}", storage::time(), text);
        let failed = storage::log(&line).is_err();
        self.update(|m| {
            m.events.push_back(line);
            if m.events.len() > 200 {
                m.events.pop_front();
            }
            if failed
                && !m
                    .events
                    .back()
                    .is_some_and(|s| s.contains("无法写入日志文件"))
            {
                m.events
                    .push_back("无法写入日志文件，请检查目录权限或磁盘空间".into());
                if m.events.len() > 200 {
                    m.events.pop_front();
                }
            }
        });
    }
    fn state(&mut self, value: &str) {
        if self.last_outcome != value {
            self.event(value);
            self.last_outcome = value.into();
        }
        self.update(|m| m.state = value.into());
    }
    fn run(&mut self, manual: bool, check_only: bool) {
        self.update(|m| {
            m.busy = true;
            m.internet = "检查中".into();
        });
        let result = self.cycle(manual, check_only);
        if let Err(error) = result {
            self.state(&error);
            self.failures = self.failures.saturating_add(1);
        }
        // The public probe follows the current system path, including a TUN default route.
        let probe = internet(&Direct::system_route(), self.preferred_probe);
        if let Some(index) = probe {
            self.preferred_probe = index;
        }
        self.update(|m| {
            m.internet = match probe {
                Some(index) => format!("可访问（{} 探测通过）", INTERNET_PROBES[index].0),
                None => "探测未通过".into(),
            };
            m.busy = false;
            m.checked = storage::time();
            m.credential_blocked = self.blocked;
        });
    }
    fn cycle(&mut self, manual: bool, check_only: bool) -> Result<(), String> {
        let config = self.shared.lock().unwrap().config.clone();
        let all = network::adapters()?;
        self.update(|m| {
            m.adapters = all.clone();
            m.portal = "自动选择".into();
            m.portal_ip = "—".into();
        });
        let available: Vec<_> = all
            .iter()
            .filter(|a| config.adapter.is_empty() || a.id == config.adapter)
            .collect();
        if available.is_empty() {
            self.update(|m| {
                m.adapter = "—".into();
                m.ip = "—".into();
            });
            self.state(if config.adapter.is_empty() {
                "无可用物理网卡"
            } else {
                "所选网卡未连接"
            });
            self.failures = 0;
            return Ok(());
        }
        let mut found = None;
        let mut unknown = None;
        let mut last_error = String::from("门户不可达");
        for &adapter in &available {
            let transport = Direct::campus(adapter);
            self.update(|m| {
                m.adapter = adapter.name.clone();
                m.ip = adapter.ip.to_string();
            });
            for host in candidates(&config, adapter) {
                self.update(|m| m.portal = format!("https://{host}"));
                match inspect(&transport, &host, adapter.ip) {
                    Ok(p) if p.online == Online::Unknown => {
                        if unknown.is_none() {
                            unknown = Some((adapter, p));
                        }
                    }
                    Ok(p) => {
                        found = Some((adapter, p, transport));
                        break;
                    }
                    Err(e) => {
                        // Diagnostic details contain only host and predefined errors, never request query.
                        let _ = storage::log(&format!("{}  入口 {}：{}", storage::time(), host, e));
                        last_error = e;
                    }
                }
            }
            if found.is_some() {
                break;
            }
        }
        let Some((adapter, portal, transport)) = found else {
            if let Some((adapter, portal)) = unknown {
                self.show_portal(adapter, &portal);
                self.state("认证状态未知，暂不提交认证");
                return Ok(());
            }
            self.update(|m| {
                m.adapter = available[0].name.clone();
                m.ip = available[0].ip.to_string();
                m.portal = "未找到可用入口".into();
            });
            let _ = storage::log(&format!("{}  无可用入口：{}", storage::time(), last_error));
            return Err("未检测到可用校园网门户".into());
        };
        self.show_portal(adapter, &portal);
        let old = config.cached_hosts.get(&adapter.key());
        if old != Some(&portal.host) {
            self.event(&format!("选择认证入口 {}（{}）", portal.host, adapter.name));
            self.update(|m| {
                if m.config.cached_hosts.len() >= 32 {
                    m.config.cached_hosts.clear();
                }
                m.config
                    .cached_hosts
                    .insert(adapter.key(), portal.host.clone());
            });
            let cached_config = self.shared.lock().unwrap().config.clone();
            if let Err(e) = storage::save(&cached_config) {
                self.event(&e);
            }
        }
        match portal.online {
            Online::Yes(_) => {
                self.failures = 0;
                self.state("已认证");
            }
            Online::Unknown => {
                self.state("认证状态未知，暂不提交认证");
            }
            Online::No => {
                if check_only || (!manual && !config.auto) {
                    self.state("未认证");
                } else if self.blocked && !manual {
                    self.state("凭据错误，自动认证已暂停");
                } else if config.username.trim().is_empty() || self.password.is_empty() {
                    self.state("未认证，请填写账号和密码并保存");
                } else {
                    self.state("正在认证…");
                    match authenticate(&transport, &portal, &config.username, &self.password)? {
                        LoginResult::Accepted => match status(&transport, &portal.host)? {
                            Online::Yes(_) => {
                                self.blocked = false;
                                self.failures = 0;
                                self.state("已认证");
                                self.event("认证成功，已复查在线状态");
                            }
                            _ => return Err("认证请求已接受，尚未确认在线状态".into()),
                        },
                        LoginResult::Credentials => {
                            self.blocked = true;
                            self.state("账号或密码错误，自动认证已暂停");
                        }
                        LoginResult::Rejected(message) => return Err(message),
                    }
                }
            }
        }
        Ok(())
    }
    fn show_portal(&self, adapter: &Adapter, portal: &Portal) {
        self.update(|m| {
            m.adapter = adapter.name.clone();
            m.ip = adapter.ip.to_string();
            m.portal_ip = portal.ip.to_string();
            m.portal = format!("https://{}", portal.host);
        });
    }
    fn save(
        &mut self,
        mut config: Config,
        entered: Option<Zeroizing<String>>,
        auto_override: Option<bool>,
    ) -> Result<(), String> {
        let (old, previous_storage) = {
            let model = self.shared.lock().unwrap();
            (model.config.clone(), model.credential_storage)
        };
        let replacing_password = entered.is_some();
        let account_changed = old.username != config.username;
        let new_password = entered.unwrap_or_else(|| {
            if account_changed {
                Zeroizing::new(String::new())
            } else {
                self.password.clone()
            }
        });
        if config.username.contains('\0') || new_password.contains('\0') {
            return Err("账号或密码包含无效字符，未保存".into());
        }
        if config.username.is_empty() && !new_password.is_empty() {
            return Err("请输入账号后再保存密码".into());
        }
        let credentials_changed =
            account_changed || new_password.as_str() != self.password.as_str();
        config.auto = auto_override.unwrap_or(old.auto);
        config.interval = config.interval.clamp(15, 3600);
        config.cached_hosts.clone_from(&old.cached_hosts);
        let keep_unknown = previous_storage == CredentialStorage::Unavailable
            && config.remember
            && !account_changed
            && !replacing_password;
        let credential_storage = if keep_unknown {
            CredentialStorage::Unavailable
        } else if new_password.is_empty() {
            CredentialStorage::NotSaved
        } else if config.remember {
            CredentialStorage::Saved
        } else {
            CredentialStorage::SessionOnly
        };

        if config.startup || old.startup {
            storage::startup(config.startup)?;
        }
        let persist = storage::save(&config).and_then(|()| {
            if credential_storage == CredentialStorage::Saved
                && (previous_storage != CredentialStorage::Saved
                    || account_changed
                    || replacing_password)
            {
                storage::write_password(&config.username, &new_password)
            } else if matches!(
                previous_storage,
                CredentialStorage::Saved | CredentialStorage::Unavailable
            ) && matches!(
                credential_storage,
                CredentialStorage::NotSaved | CredentialStorage::SessionOnly
            ) {
                storage::delete_password()
            } else {
                Ok(())
            }
        });
        if let Err(error) = persist {
            if let Err(rollback_error) = storage::save(&old) {
                self.event(&rollback_error);
            }
            if config.startup != old.startup {
                if let Err(rollback_error) = storage::startup(old.startup) {
                    self.event(&rollback_error);
                }
            }
            return Err(error);
        }
        self.password = new_password;
        if credentials_changed {
            self.blocked = false;
        }
        self.failures = 0;
        self.update(|m| {
            m.config = config;
            m.credential_blocked = self.blocked;
            m.credential_storage = credential_storage;
            m.save_status = SaveStatus::Saved;
        });
        self.event("设置已保存");
        Ok(())
    }
}

pub fn retry_delay(interval: u64, failures: u32) -> Duration {
    Duration::from_secs(if failures == 0 {
        interval
    } else {
        [5, 15, 30, 60, 120, 300][(failures as usize - 1).min(5)]
    })
}
unsafe extern "system" fn interface_change(
    context: *const std::ffi::c_void,
    _: *const MIB_IPINTERFACE_ROW,
    _: MIB_NOTIFICATION_TYPE,
) {
    if !context.is_null() {
        let _ = (&*(context as *const Sender<Command>)).send(Command::Network);
    }
}
unsafe extern "system" fn address_change(
    context: *const std::ffi::c_void,
    _: *const MIB_UNICASTIPADDRESS_ROW,
    _: MIB_NOTIFICATION_TYPE,
) {
    if !context.is_null() {
        let _ = (&*(context as *const Sender<Command>)).send(Command::Network);
    }
}
unsafe extern "system" fn route_change(
    context: *const std::ffi::c_void,
    row: *const MIB_IPFORWARD_ROW2,
    _: MIB_NOTIFICATION_TYPE,
) {
    // Some tunnels replace the default route with two /1 routes.
    if !context.is_null() && !row.is_null() && (*row).DestinationPrefix.PrefixLength <= 1 {
        let _ = (&*(context as *const Sender<Command>)).send(Command::Network);
    }
}
struct Notifications {
    context: *mut Sender<Command>,
    interface: HANDLE,
    address: HANDLE,
    route: HANDLE,
}
impl Notifications {
    fn new(tx: Sender<Command>) -> Self {
        unsafe {
            let context = Box::into_raw(Box::new(tx));
            let (mut interface, mut address, mut route) = (0, 0, 0);
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(interface_change),
                context.cast(),
                0,
                &mut interface,
            );
            NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(address_change),
                context.cast(),
                0,
                &mut address,
            );
            NotifyRouteChange2(AF_UNSPEC, Some(route_change), context.cast(), 0, &mut route);
            Self {
                context,
                interface,
                address,
                route,
            }
        }
    }
}
impl Drop for Notifications {
    fn drop(&mut self) {
        unsafe {
            if self.interface != 0 {
                CancelMibChangeNotify2(self.interface);
            }
            if self.address != 0 {
                CancelMibChangeNotify2(self.address);
            }
            if self.route != 0 {
                CancelMibChangeNotify2(self.route);
            }
            drop(Box::from_raw(self.context));
        }
    }
}
pub fn start(
    shared: Shared,
    wake: impl Fn() + Send + 'static,
) -> (Sender<Command>, thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let notify_tx = tx.clone();
    let join = thread::spawn(move || worker(shared, Box::new(wake), rx, notify_tx));
    (tx, join)
}
fn worker(shared: Shared, wake: Box<dyn Fn() + Send>, rx: Receiver<Command>, tx: Sender<Command>) {
    let config = shared.lock().unwrap().config.clone();
    let saved = if config.remember && !config.username.is_empty() {
        storage::read_password(&config.username)
    } else {
        Ok(Zeroizing::new(String::new()))
    };
    let mut runner = Runner {
        shared,
        wake,
        password: saved.as_ref().cloned().unwrap_or_default(),
        failures: 0,
        blocked: false,
        preferred_probe: 0,
        last_outcome: String::new(),
    };
    runner.update(|m| {
        m.credential_storage = match &saved {
            Err(_) => CredentialStorage::Unavailable,
            Ok(password) if !password.is_empty() => CredentialStorage::Saved,
            Ok(_) => CredentialStorage::NotSaved,
        }
    });
    if let Err(e) = saved {
        runner.event(&e);
    }
    let _notifications = Notifications::new(tx);
    runner.event("后台监测已启动");
    let mut next = Instant::now();
    loop {
        let wait = next.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Command::Stop) => break,
            Ok(Command::Network) => {
                next = Instant::now() + Duration::from_secs(3);
            }
            Ok(Command::Save {
                config,
                password,
                auto_override,
            }) => {
                if let Err(error) = runner.save(config, password, auto_override) {
                    runner.update(|m| m.save_status = SaveStatus::Failed);
                    runner.event(&error);
                }
                next = Instant::now() + Duration::from_secs(1);
            }
            Ok(Command::Auto(enabled)) => {
                let mut config = runner.shared.lock().unwrap().config.clone();
                config.auto = enabled;
                match storage::save(&config) {
                    Ok(()) => runner.update(|m| m.config = config),
                    Err(error) => runner.event(&error),
                }
                next = Instant::now() + Duration::from_secs(1);
            }
            Ok(Command::Check) => {
                runner.run(false, true);
                runner.event("手动检查完成");
                next = Instant::now()
                    + retry_delay(
                        runner.shared.lock().unwrap().config.interval,
                        runner.failures,
                    );
            }
            Ok(Command::Login) => {
                runner.run(true, false);
                next = Instant::now()
                    + retry_delay(
                        runner.shared.lock().unwrap().config.interval,
                        runner.failures,
                    );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                runner.run(false, false);
                next = Instant::now()
                    + retry_delay(
                        runner.shared.lock().unwrap().config.interval,
                        runner.failures,
                    );
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use std::cell::RefCell;
    struct Fake {
        calls: RefCell<Vec<String>>,
        pages: RefCell<VecDeque<Result<Response, String>>>,
    }
    impl Transport for Fake {
        fn get(&self, u: &Url) -> Result<Response, String> {
            self.calls.borrow_mut().push(u.to_string());
            self.pages
                .borrow_mut()
                .pop_front()
                .expect("unexpected request")
        }
    }
    fn r(status: u16, location: Option<&str>, body: &str) -> Result<Response, String> {
        Ok(Response {
            status,
            location: location.map(String::from),
            body: body.into(),
        })
    }
    #[test]
    fn blocks_untrusted_redirect_before_credentials() {
        let t = Fake {
            calls: RefCell::new(vec![]),
            pages: RefCell::new(
                [
                    r(200, None, "not_online"),
                    r(302, Some("https://evil.test/"), ""),
                ]
                .into(),
            ),
        };
        assert!(inspect(&t, "net.zju.edu.cn", "10.1.2.3".parse().unwrap()).is_err());
        assert_eq!(t.calls.borrow().len(), 2);
    }
    #[test]
    fn login_is_never_redirected() {
        let t = Fake {
            calls: RefCell::new(vec![]),
            pages: RefCell::new(
                [
                    r(
                        200,
                        None,
                        r#"cb({"challenge":"0123456789abcdef0123456789abcdef"})"#,
                    ),
                    r(302, Some("https://evil.test/"), ""),
                ]
                .into(),
            ),
        };
        let p = Portal {
            host: "net.zju.edu.cn".into(),
            acid: "80".into(),
            ip: "10.1.2.3".parse().unwrap(),
            online: Online::No,
        };
        assert!(authenticate(&t, &p, "test", "secret").is_err());
        assert_eq!(t.calls.borrow().len(), 2);
        assert!(t
            .calls
            .borrow()
            .iter()
            .all(|s| s.starts_with("https://net.zju.edu.cn/")));
    }
    #[test]
    fn retry_is_bounded() {
        assert_eq!(retry_delay(60, 0).as_secs(), 60);
        assert_eq!(retry_delay(60, 1).as_secs(), 5);
        assert_eq!(retry_delay(60, 100).as_secs(), 300);
    }

    #[test]
    fn save_keeps_credential_pause_and_current_auto_setting() {
        let directory =
            std::env::temp_dir().join(format!("zju-save-regression-{}", std::process::id()));
        let previous_directory = std::env::var_os("ZJU_ASSISTANT_DATA_DIR");
        std::env::set_var("ZJU_ASSISTANT_DATA_DIR", &directory);

        let config = Config {
            username: "synthetic-user".into(),
            remember: false,
            auto: false,
            ..Config::default()
        };
        let shared = Arc::new(Mutex::new(Model::new(config.clone())));
        let mut runner = Runner {
            shared: shared.clone(),
            wake: Box::new(|| {}),
            password: Zeroizing::new("synthetic-password".into()),
            failures: 0,
            blocked: true,
            preferred_probe: 0,
            last_outcome: String::new(),
        };

        // The form was opened before the tray paused auto login.
        let stale_form = Config {
            interval: 90,
            auto: true,
            ..config
        };
        runner.save(stale_form.clone(), None, None).unwrap();
        let model = shared.lock().unwrap().clone();
        assert_eq!(model.config.interval, 90);
        assert!(!model.config.auto);
        assert!(model.credential_blocked);

        // An explicit checkbox change applies, while the same password preserves the block.
        runner
            .save(
                stale_form.clone(),
                Some(runner.password.clone()),
                Some(true),
            )
            .unwrap();
        let model = shared.lock().unwrap().clone();
        assert!(model.config.auto);
        assert!(model.credential_blocked);

        runner
            .save(
                stale_form.clone(),
                Some(Zeroizing::new("new-synthetic-password".into())),
                None,
            )
            .unwrap();
        assert!(!shared.lock().unwrap().credential_blocked);
        runner.blocked = true;
        runner
            .save(
                Config {
                    username: "other-synthetic-user".into(),
                    ..stale_form
                },
                None,
                None,
            )
            .unwrap();
        assert!(!shared.lock().unwrap().credential_blocked);
        assert!(runner.password.is_empty());

        if let Some(path) = previous_directory {
            std::env::set_var("ZJU_ASSISTANT_DATA_DIR", path);
        } else {
            std::env::remove_var("ZJU_ASSISTANT_DATA_DIR");
        }
        std::fs::remove_file(directory.join("config.json")).unwrap();
        std::fs::remove_file(directory.join("events.log")).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn internet_probe_ignores_redirects_and_login_pages() {
        let transport = Fake {
            calls: RefCell::new(vec![]),
            pages: RefCell::new(
                [
                    r(302, Some("https://portal.test/"), ""),
                    r(200, None, "<html>登录</html>"),
                    r(204, None, ""),
                ]
                .into(),
            ),
        };
        assert_eq!(internet(&transport, 0), Some(2));
        assert_eq!(transport.calls.borrow().len(), 3);
    }

    #[test]
    fn internet_probe_prefers_last_working_endpoint() {
        let transport = Fake {
            calls: RefCell::new(vec![]),
            pages: RefCell::new([r(200, None, "h=www.cloudflare.com\ncolo=HKG\n")].into()),
        };
        assert_eq!(internet(&transport, 1), Some(1));
        assert_eq!(&*transport.calls.borrow(), &[INTERNET_PROBES[1].1]);
    }
}

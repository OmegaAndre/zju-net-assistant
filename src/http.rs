//! Small bounded HTTP/1.1 transport. Direct sockets, Schannel TLS, no proxy inheritance.
use crate::network::Adapter;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    cell::RefCell,
    collections::HashMap,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs},
    os::windows::io::AsRawSocket,
    ptr,
    time::{Duration, Instant},
};
use url::Url;
use windows_sys::Win32::{
    NetworkManagement::Dns::*,
    Networking::WinSock::{setsockopt, WSAGetLastError, IPPROTO_IP, IP_UNICAST_IF, SOCKET_ERROR},
};

const LIMIT: usize = 512 * 1024;
pub struct Response {
    pub status: u16,
    pub location: Option<String>,
    pub body: String,
}
pub trait Transport {
    fn get(&self, url: &Url) -> Result<Response, String>;
}

pub struct Direct<'a> {
    adapter: Option<&'a Adapter>,
    campus_dns: RefCell<HashMap<String, Vec<Ipv4Addr>>>,
}

impl<'a> Direct<'a> {
    pub fn campus(adapter: &'a Adapter) -> Self {
        Self {
            adapter: Some(adapter),
            campus_dns: RefCell::new(HashMap::new()),
        }
    }

    pub fn system_route() -> Self {
        Self {
            adapter: None,
            campus_dns: RefCell::new(HashMap::new()),
        }
    }

    fn addresses(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        let Some(adapter) = self.adapter else {
            return (host, port)
                .to_socket_addrs()
                .map(|addresses| addresses.take(2).collect())
                .map_err(|_| "系统 DNS 解析失败".into());
        };

        let mut cache = self.campus_dns.borrow_mut();
        if !cache.contains_key(host) {
            cache.insert(host.to_owned(), resolve_on_interface(host, adapter.index)?);
        }
        Ok(cache[host]
            .iter()
            .map(|ip| SocketAddr::from((*ip, port)))
            .collect())
    }
}

fn resolve_on_interface(host: &str, index: u32) -> Result<Vec<Ipv4Addr>, String> {
    let name = crate::storage::wide(host);
    let request = DNS_QUERY_REQUEST {
        Version: DNS_QUERY_REQUEST_VERSION1,
        QueryName: name.as_ptr(),
        QueryType: DNS_TYPE_A,
        QueryOptions: u64::from(
            DNS_QUERY_BYPASS_CACHE
                | DNS_QUERY_NO_HOSTS_FILE
                | DNS_QUERY_NO_MULTICAST
                | DNS_QUERY_TREAT_AS_FQDN,
        ),
        InterfaceIndex: index,
        pDnsServerList: ptr::null_mut(),
        pQueryCompletionCallback: None,
        pQueryContext: ptr::null_mut(),
    };
    unsafe {
        let mut result = DNS_QUERY_RESULT {
            Version: DNS_QUERY_RESULTS_VERSION1,
            ..std::mem::zeroed()
        };
        let code = DnsQueryEx(&request, &mut result, ptr::null_mut());
        let mut ips = Vec::new();
        if code == 0 && result.QueryStatus == 0 {
            // DnsQueryEx returns Unicode records through DNS_QUERY_RESULT's generic pointer.
            let mut record = result.pQueryRecords.cast::<DNS_RECORDW>();
            while !record.is_null() && ips.len() < 3 {
                if (*record).wType == DNS_TYPE_A {
                    let ip = Ipv4Addr::from((*record).Data.A.IpAddress.to_ne_bytes());
                    let [first, second, ..] = ip.octets();
                    // Reject loopback and the default Fake IP benchmark range on the physical route.
                    if !ip.is_loopback()
                        && !ip.is_unspecified()
                        && !(first == 198 && (second == 18 || second == 19))
                        && !ips.contains(&ip)
                    {
                        ips.push(ip);
                    }
                }
                record = (*record).pNext;
            }
        }
        if !result.pQueryRecords.is_null() {
            DnsFree(result.pQueryRecords.cast(), DnsFreeRecordList);
        }
        if code != 0 || result.QueryStatus != 0 {
            let status = if code != 0 { code } else { result.QueryStatus };
            return Err(format!("物理网卡 DNS 查询失败（{status}）"));
        }
        if ips.is_empty() {
            return Err("物理网卡 DNS 未返回可用门户 IPv4".into());
        }
        Ok(ips)
    }
}

fn bind_adapter(socket: &Socket, adapter: &Adapter) -> Result<(), String> {
    let interface = adapter.index.to_be_bytes();
    unsafe {
        if setsockopt(
            socket.as_raw_socket() as _,
            IPPROTO_IP,
            IP_UNICAST_IF,
            interface.as_ptr(),
            interface.len() as i32,
        ) == SOCKET_ERROR
        {
            return Err(format!("无法指定物理网卡出站接口（{}）", WSAGetLastError()));
        }
    }
    socket
        .bind(&SocketAddr::from((adapter.ip, 0)).into())
        .map_err(|_| "无法绑定物理网卡的源 IP，网卡可能已断开".into())
}

impl Transport for Direct<'_> {
    fn get(&self, url: &Url) -> Result<Response, String> {
        if url.scheme() != "https" && url.scheme() != "http" {
            return Err("不支持的请求协议".into());
        }
        let host = url.host_str().ok_or("请求地址无主机名")?;
        let port = url.port_or_known_default().ok_or("请求端口无效")?;
        let addrs = self.addresses(host, port)?;
        let connect_timeout = Duration::from_secs(if self.adapter.is_some() { 2 } else { 1 });
        let io_timeout = Duration::from_secs(if self.adapter.is_some() { 3 } else { 2 });
        let mut connected = None;
        let start = Instant::now();
        for addr in addrs {
            if start.elapsed() > Duration::from_secs(6) {
                break;
            }
            let domain = if addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let Ok(socket) = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) else {
                continue;
            };
            if let Some(adapter) = self.adapter {
                bind_adapter(&socket, adapter)?;
            }
            if socket
                .connect_timeout(&addr.into(), connect_timeout)
                .is_ok()
            {
                let tcp: TcpStream = socket.into();
                tcp.set_read_timeout(Some(io_timeout))
                    .map_err(|_| "设置读取超时失败")?;
                tcp.set_write_timeout(Some(io_timeout))
                    .map_err(|_| "设置发送超时失败")?;
                connected = Some(tcp);
                break;
            }
        }
        let tcp = connected.ok_or("连接超时或目标不可达")?;
        let mut path = url.path().to_owned();
        if let Some(q) = url.query() {
            path.push('?');
            path.push_str(q);
        }
        // Never log path: authentication query contains secrets.
        let request = zeroize::Zeroizing::new(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ZjuNetAssistant/{}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", env!("CARGO_PKG_VERSION")));
        if url.scheme() == "https" {
            let tls = native_tls::TlsConnector::builder()
                .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
                .build()
                .map_err(|_| "系统 TLS 初始化失败")?;
            let mut stream = tls
                .connect(host, tcp)
                .map_err(|_| "TLS 连接失败（证书或网络异常）")?;
            exchange(&mut stream, request.as_bytes())
        } else {
            let mut tcp = tcp;
            exchange(&mut tcp, request.as_bytes())
        }
    }
}
fn exchange<S: Read + Write>(s: &mut S, req: &[u8]) -> Result<Response, String> {
    s.write_all(req).map_err(|_| "发送请求失败")?;
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut raw = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        if Instant::now() > deadline {
            return Err("服务器响应超时".into());
        }
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if raw.len() + n > LIMIT {
                    return Err("门户响应超过大小限制".into());
                }
                raw.extend_from_slice(&buf[..n]);
                if response_complete(&raw) {
                    break;
                }
            }
            Err(_) => {
                if response_complete(&raw) {
                    break;
                }
                return Err("读取响应失败或超时".into());
            }
        }
    }
    parse(&raw)
}
fn header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|b| b == b"\r\n\r\n").map(|p| p + 4)
}
fn response_complete(raw: &[u8]) -> bool {
    let Some(end) = header_end(raw) else {
        return false;
    };
    let h = String::from_utf8_lossy(&raw[..end]);
    if h.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        == Some("204")
    {
        return true;
    }
    if let Some(n) = h.lines().find_map(|l| {
        l.split_once(':')
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
    }) {
        return raw.len() >= end.saturating_add(n);
    }
    if h.lines().any(|l| {
        l.to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    }) {
        return decode_chunks(&raw[end..]).is_ok();
    }
    false
}
fn decode_chunks(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut p = 0;
    loop {
        let q = raw
            .get(p..)
            .and_then(|b| b.windows(2).position(|w| w == b"\r\n"))
            .map(|i| p + i)
            .ok_or("chunk 长度行不完整")?;
        let n = usize::from_str_radix(
            std::str::from_utf8(&raw[p..q])
                .map_err(|_| "chunk 格式异常")?
                .split(';')
                .next()
                .unwrap_or("")
                .trim(),
            16,
        )
        .map_err(|_| "chunk 长度异常")?;
        p = q + 2;
        if n == 0 {
            if raw.get(p..p + 2) == Some(b"\r\n") {
                return Ok(out);
            }
            return Err("chunk 结尾不完整".into());
        }
        if n > LIMIT || out.len() + n > LIMIT {
            return Err("chunk 超过大小限制".into());
        }
        let end = p.checked_add(n).ok_or("chunk 长度溢出")?;
        if raw.get(end..end + 2) != Some(b"\r\n") {
            return Err("chunk 内容不完整".into());
        }
        out.extend_from_slice(raw.get(p..end).ok_or("chunk 内容缺失")?);
        p = end + 2;
    }
}
pub fn parse(raw: &[u8]) -> Result<Response, String> {
    let end = header_end(raw).ok_or("HTTP 响应头不完整")?;
    let h = std::str::from_utf8(&raw[..end]).map_err(|_| "HTTP 响应头格式异常")?;
    let status = h
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("HTTP 状态码无效")?;
    let mut location = None;
    let mut chunked = false;
    let mut length = None;
    for l in h.lines().skip(1) {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("location") {
                location = Some(v.trim().into());
            }
            if k.eq_ignore_ascii_case("transfer-encoding") {
                if !v.trim().eq_ignore_ascii_case("chunked") {
                    return Err("不支持的 HTTP 传输编码".into());
                }
                chunked = true;
            }
            if k.eq_ignore_ascii_case("content-encoding")
                && !v.trim().eq_ignore_ascii_case("identity")
            {
                return Err("不支持压缩的门户响应".into());
            }
            if k.eq_ignore_ascii_case("content-length") {
                length = Some(v.trim().parse::<usize>().map_err(|_| "HTTP 长度异常")?);
            }
        }
    }
    let bytes = if chunked {
        decode_chunks(&raw[end..])?
    } else {
        let n = length.unwrap_or(raw.len() - end);
        if n > LIMIT {
            return Err("HTTP 内容过大".into());
        }
        raw.get(end..end + n).ok_or("HTTP 内容不完整")?.to_vec()
    };
    Ok(Response {
        status,
        location,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_framing() {
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap()
                .body,
            "ok"
        );
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n")
                .unwrap()
                .body,
            "ok"
        );
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx").is_err());
        assert!(decode_chunks(b"ffffffffffffffff\r\nx").is_err());
    }
}

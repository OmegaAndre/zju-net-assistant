//! Srun wire format. References and original MIT notices: THIRD_PARTY_NOTICES.txt.
use hmac::{Hmac, Mac};
use md5::Md5;
use regex_lite::Regex;
use serde::Serialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::net::Ipv4Addr;
use zeroize::Zeroizing;

const ALPHABET: &[u8; 64] = b"LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
pub const HOSTS: [&str; 3] = ["net.zju.edu.cn", "net2.zju.edu.cn", "net3.zju.edu.cn"];

pub fn trusted_url(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url.host_str().is_some_and(|h| HOSTS.contains(&h))
}

pub fn json_response(text: &str) -> Result<Value, String> {
    let text = text.trim();
    if text.starts_with('{') {
        return serde_json::from_str(text).map_err(|_| "门户 JSON 格式异常".into());
    }
    let start = text.find('(').ok_or("门户返回格式不受支持")?;
    let end = text.rfind(')').ok_or("门户 JSONP 格式异常")?;
    let cb = &text[..start];
    if cb.is_empty() || !cb.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || end <= start {
        return Err("门户 JSONP 格式异常".into());
    }
    serde_json::from_str(&text[start + 1..end]).map_err(|_| "门户 JSONP 数据异常".into())
}

#[derive(Clone, Debug, PartialEq)]
pub enum Online {
    Yes(Option<Ipv4Addr>),
    No,
    Unknown,
}
pub fn online(text: &str) -> Online {
    let text = text.trim();
    if text == "not_online" || text == "not_online_error" {
        return Online::No;
    }
    if let Ok(v) = json_response(text) {
        if v["error"] == "not_online" || v["error"] == "not_online_error" {
            return Online::No;
        }
        if v["error"] == "ok" {
            let ip = v["online_ip"]
                .as_str()
                .or_else(|| v["client_ip"].as_str())
                .and_then(|s| s.parse().ok());
            if v["user_name"]
                .as_str()
                .or_else(|| v["username"].as_str())
                .is_some_and(|s| !s.is_empty())
            {
                return Online::Yes(ip);
            }
        }
    }
    let f: Vec<_> = text.split(',').collect();
    if f.len() >= 9 && !f[0].is_empty() && f[1].parse::<u64>().is_ok() {
        if let Ok(ip) = f[8].parse() {
            return Online::Yes(Some(ip));
        }
    }
    Online::Unknown
}

pub fn portal_fields(
    html: &str,
    page_url: &url::Url,
) -> Result<(String, Option<Ipv4Addr>), String> {
    let acid_query = page_url
        .query_pairs()
        .find(|(k, _)| k == "ac_id")
        .map(|(_, v)| v.into_owned());
    let capture = |patterns: &[&str]| {
        patterns.iter().find_map(|p| {
            Regex::new(p)
                .ok()?
                .captures(html)?
                .get(1)
                .map(|m| m.as_str().to_owned())
        })
    };
    let acid = capture(&[
        r#"(?i)(?:acid|ac_id)\s*:\s*["']?(\d+)"#,
        r#"(?i)id=["']ac_id["'][^>]*value=["'](\d+)"#,
        r#"(?i)value=["'](\d+)["'][^>]*id=["']ac_id["']"#,
    ])
    .or(acid_query)
    .ok_or("无法从门户提取 ac_id，请检查认证入口")?;
    let ip = capture(&[
        r#"(?i)\bip\s*:\s*["']([0-9.]+)["']"#,
        r#"(?i)id=["']user_ip["'][^>]*value=["']([0-9.]+)"#,
    ])
    .and_then(|s| s.parse().ok());
    Ok((acid, ip))
}

pub fn meta_redirect(html: &str) -> Option<String> {
    let re = Regex::new(r#"(?i)<meta\b[^>]*content=["'][^"']*url=([^"'>]+)"#).ok()?;
    re.captures(html)?
        .get(1)
        .map(|m| m.as_str().replace("&amp;", "&"))
}

fn xencode(text: &str, key: &str) -> Zeroizing<Vec<u8>> {
    // Portal JS packs UTF-16 code units, including its non-ASCII behavior.
    fn words(s: &str, length: bool) -> Vec<u32> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut out = Vec::with_capacity(units.len().div_ceil(4) + 1);
        for chunk in units.chunks(4) {
            let mut n = 0u32;
            for (i, u) in chunk.iter().enumerate() {
                n |= (*u as u32).wrapping_shl((i * 8) as u32);
            }
            out.push(n);
        }
        if length {
            out.push(units.len() as u32);
        }
        out
    }
    let mut v = Zeroizing::new(words(text, true));
    let mut k = Zeroizing::new(words(key, false));
    let key_len = k.len().max(4);
    k.resize(key_len, 0);
    let n = v.len() - 1;
    let mut z = v[n];
    let mut sum = 0u32;
    for _ in 0..(6 + 52 / v.len()) {
        sum = sum.wrapping_add(0x9e3779b9);
        let e = (sum >> 2 & 3) as usize;
        for p in 0..=n {
            let y = v[if p == n { 0 } else { p + 1 }];
            let m = ((z >> 5) ^ (y << 2))
                .wrapping_add(((y >> 3) ^ (z << 4)) ^ (sum ^ y))
                .wrapping_add(k[(p & 3) ^ e] ^ z);
            v[p] = v[p].wrapping_add(m);
            z = v[p];
        }
    }
    Zeroizing::new(v.iter().flat_map(|x| x.to_le_bytes()).collect())
}

fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let v = (c[0] as u32) << 16
            | (c.get(1).copied().unwrap_or(0) as u32) << 8
            | c.get(2).copied().unwrap_or(0) as u32;
        out.push(ALPHABET[(v >> 18) as usize] as char);
        out.push(ALPHABET[((v >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 {
            ALPHABET[((v >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            ALPHABET[(v & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn login_query(
    user: &str,
    password: &str,
    ip: Ipv4Addr,
    acid: &str,
    token: &str,
) -> Result<Zeroizing<String>, String> {
    if token.len() < 16 || token.len() > 128 || !token.is_ascii() {
        return Err("门户挑战值无效".into());
    }
    #[derive(Serialize)]
    struct Info<'a> {
        username: &'a str,
        password: &'a str,
        ip: String,
        acid: &'a str,
        enc_ver: &'a str,
    }
    let plain = Zeroizing::new(
        serde_json::to_string(&Info {
            username: user,
            password,
            ip: ip.to_string(),
            acid,
            enc_ver: "srun_bx1",
        })
        .map_err(|_| "认证参数构造失败")?,
    );
    let info = Zeroizing::new(format!("{{SRBX1}}{}", base64(&xencode(&plain, token))));
    let mut mac = Hmac::<Md5>::new_from_slice(token.as_bytes()).map_err(|_| "挑战值格式异常")?;
    mac.update(password.as_bytes());
    let hmd5 = Zeroizing::new(format!("{:x}", mac.finalize().into_bytes()));
    let check = Zeroizing::new(format!(
        "{token}{user}{token}{}{token}{acid}{token}{ip}{token}200{token}1{token}{}",
        hmd5.as_str(),
        info.as_str()
    ));
    let checksum = format!("{:x}", Sha1::digest(check.as_bytes()));
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.extend_pairs([
        ("callback", "zju_cb"),
        ("action", "login"),
        ("username", user),
        ("password", &format!("{{MD5}}{}", hmd5.as_str())),
        ("ac_id", acid),
        ("ip", &ip.to_string()),
        ("chksum", &checksum),
        ("info", &info),
        ("n", "200"),
        ("type", "1"),
        ("os", "Windows"),
        ("name", "Windows"),
        ("double_stack", "0"),
    ]);
    Ok(Zeroizing::new(form.finish()))
}

#[derive(Debug, PartialEq)]
pub enum LoginResult {
    Accepted,
    Credentials,
    Rejected(String),
}
pub fn login_result(v: &Value) -> LoginResult {
    let err = v["error"].as_str().unwrap_or("");
    let suc = v["suc_msg"].as_str().unwrap_or("");
    if err == "ok" || err == "ip_already_online_error" || suc == "ip_already_online_error" {
        return LoginResult::Accepted;
    }
    let code = v["ecode"].as_str().unwrap_or("");
    let msg = v["error_msg"]
        .as_str()
        .or_else(|| v["res"].as_str())
        .unwrap_or("");
    let all = format!("{err} {code} {msg}").to_lowercase();
    if [
        "password_error",
        "username_error",
        "user_not_exist",
        "e2531",
        "e2553",
        "密码错误",
        "密码不正确",
        "用户不存在",
        "账号不存在",
    ]
    .iter()
    .any(|s| all.contains(s))
    {
        return LoginResult::Credentials;
    }
    // Do not surface arbitrary server text, which can echo credentials or URLs.
    let friendly = if all.contains("limit") || all.contains("超限") {
        "在线设备数量超限"
    } else if all.contains("欠费") || all.contains("balance") {
        "账户余额或套餐异常"
    } else {
        "服务器拒绝认证，请查看校园网账户状态或稍后重试"
    };
    LoginResult::Rejected(friendly.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_destinations() {
        for s in [
            "http://net.zju.edu.cn/",
            "https://net.zju.edu.cn.evil.test/",
            "https://evil.test/",
            "https://net.zju.edu.cn:8443/",
            "https://a@net.zju.edu.cn/",
        ] {
            assert!(!trusted_url(&url::Url::parse(s).unwrap()));
        }
        assert!(trusted_url(
            &url::Url::parse("https://net2.zju.edu.cn/srun_portal_pc?ac_id=3").unwrap()
        ));
    }
    #[test]
    fn status_is_not_just_http_success() {
        assert_eq!(online("<html>登录</html>"), Online::Unknown);
        assert_eq!(online("not_online"), Online::No);
        assert_eq!(online("cb({\"error\":\"not_online_error\"})"), Online::No);
        assert_eq!(
            online("u,1700000000,a,b,c,d,e,f,10.1.2.3"),
            Online::Yes(Some("10.1.2.3".parse().unwrap()))
        );
    }
    #[test]
    fn parse_pages() {
        let u = url::Url::parse("https://net.zju.edu.cn/").unwrap();
        assert_eq!(
            portal_fields("acid : \"80\", ip : \"10.2.3.4\"", &u).unwrap(),
            ("80".into(), Some("10.2.3.4".parse().unwrap()))
        );
        assert_eq!(
            portal_fields("<input id='ac_id' value='3'>", &u).unwrap().0,
            "3"
        );
        assert!(portal_fields("arbitrary page", &u).is_err());
        assert_eq!(
            meta_redirect(
                "<meta http-equiv='refresh' content='0;url=/srun?ac_id=80&amp;theme=zju'>"
            )
            .unwrap(),
            "/srun?ac_id=80&theme=zju"
        );
    }
    #[test]
    fn outcome_and_jsonp() {
        assert_eq!(
            login_result(&serde_json::json!({"error":"ip_already_online_error"})),
            LoginResult::Accepted
        );
        assert_eq!(
            login_result(&serde_json::json!({"error":"password_error"})),
            LoginResult::Credentials
        );
        assert_eq!(
            json_response("cb({\"error\":\"ok\"});").unwrap()["error"],
            "ok"
        );
        assert!(json_response("alert(1);cb({})").is_err());
    }
    #[test]
    fn encode_known_vector() {
        // Independently generated using the reference portal JS; see tests/reference.mjs.
        assert_eq!(base64(&[0, 1, 2, 253, 254, 255]), "LLPoAsEA");
        let vectors: Value = serde_json::from_str(include_str!("../tests/vectors.json")).unwrap();
        for v in vectors.as_array().unwrap() {
            let query = login_query(
                v["username"].as_str().unwrap(),
                v["password"].as_str().unwrap(),
                v["ip"].as_str().unwrap().parse().unwrap(),
                v["acid"].as_str().unwrap(),
                v["token"].as_str().unwrap(),
            )
            .unwrap();
            let pairs: std::collections::HashMap<_, _> =
                url::form_urlencoded::parse(query.as_bytes())
                    .into_owned()
                    .collect();
            assert_eq!(pairs["info"], v["info"].as_str().unwrap());
            assert_eq!(
                pairs["password"],
                format!("{{MD5}}{}", v["hmd5"].as_str().unwrap())
            );
            assert_eq!(pairs["chksum"], v["chksum"].as_str().unwrap());
        }
    }
}

use std::{ffi::CStr, net::Ipv4Addr};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::{IpHelper::*, Ndis::*},
    Networking::WinSock::*,
};

#[derive(Clone, Debug, PartialEq)]
pub struct Adapter {
    pub id: String,
    pub name: String,
    pub ip: Ipv4Addr,
    pub index: u32,
    pub metric: u32,
    pub gateway: String,
}
// HardwareInterface is the first bit of MIB_IF_ROW2::InterfaceAndOperStatusFlags.
const HARDWARE_INTERFACE: u8 = 1;

fn is_physical_medium(interface_type: u32, flags: u8) -> bool {
    matches!(interface_type, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
        && flags & HARDWARE_INTERFACE != 0
}

unsafe fn is_physical_adapter(index: u32) -> bool {
    if index == 0 {
        return false;
    }
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..std::mem::zeroed()
    };
    GetIfEntry2Ex(MibIfEntryNormalWithoutStatistics, &mut row) == 0
        && is_physical_medium(row.Type, row.InterfaceAndOperStatusFlags._bitfield)
}
impl Adapter {
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}.{}.{}",
            self.id,
            self.gateway,
            self.ip.octets()[0],
            self.ip.octets()[1],
            self.ip.octets()[2]
        )
    }
}
unsafe fn wstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}
unsafe fn ipv4(a: SOCKET_ADDRESS) -> Option<Ipv4Addr> {
    if a.lpSockaddr.is_null() || (*a.lpSockaddr).sa_family != AF_INET {
        return None;
    }
    let addr = &*(a.lpSockaddr as *const SOCKADDR_IN);
    Some(Ipv4Addr::from(addr.sin_addr.S_un.S_addr.to_ne_bytes()))
}
pub fn adapters() -> Result<Vec<Adapter>, String> {
    unsafe {
        let mut size = 16384u32;
        // Vec<u64> ensures alignment for the Win32 structures in the returned buffer.
        let mut buffer = vec![0u64; size as usize / 8 + 1];
        let flags = GAA_FLAG_INCLUDE_GATEWAYS
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER;
        let mut result = GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            std::ptr::null(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        );
        if result == ERROR_BUFFER_OVERFLOW {
            buffer.resize(size as usize / 8 + 1, 0);
            result = GetAdaptersAddresses(
                AF_INET as u32,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            );
        }
        if result == ERROR_NO_DATA {
            return Ok(Vec::new());
        }
        if result != 0 {
            return Err("无法获取网卡信息".into());
        }
        let mut out = Vec::new();
        let mut p = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !p.is_null() {
            let a = &*p;
            let index = a.Anonymous1.Anonymous.IfIndex;
            if a.OperStatus == IfOperStatusUp
                && matches!(a.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
                && is_physical_adapter(index)
            {
                let id = if a.AdapterName.is_null() {
                    String::new()
                } else {
                    CStr::from_ptr(a.AdapterName.cast())
                        .to_string_lossy()
                        .into_owned()
                };
                let name = wstr(a.FriendlyName);
                let gateway = if a.FirstGatewayAddress.is_null() {
                    String::new()
                } else {
                    ipv4((*a.FirstGatewayAddress).Address)
                        .map(|ip| ip.to_string())
                        .unwrap_or_default()
                };
                let mut unicast = a.FirstUnicastAddress;
                while !unicast.is_null() {
                    if let Some(ip) = ipv4((*unicast).Address) {
                        if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() {
                            out.push(Adapter {
                                id: id.clone(),
                                name: name.clone(),
                                ip,
                                index,
                                metric: a.Ipv4Metric,
                                gateway: gateway.clone(),
                            });
                        }
                    }
                    unicast = (*unicast).Next;
                }
            }
            p = a.Next;
        }
        out.sort_by_key(|a| (a.gateway.is_empty(), a.metric, a.index));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_like_virtual_adapters_are_excluded() {
        assert!(!is_physical_medium(IF_TYPE_ETHERNET_CSMACD, 0));
        assert!(!is_physical_medium(IF_TYPE_IEEE80211, 0));
        assert!(is_physical_medium(
            IF_TYPE_ETHERNET_CSMACD,
            HARDWARE_INTERFACE
        ));
        assert!(is_physical_medium(IF_TYPE_IEEE80211, HARDWARE_INTERFACE));
        assert!(!is_physical_medium(IF_TYPE_TUNNEL, HARDWARE_INTERFACE));
    }
}

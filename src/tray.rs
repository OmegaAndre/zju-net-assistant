use std::ptr::null;
use windows_sys::Win32::{
    Foundation::HWND,
    System::LibraryLoader::GetModuleHandleW,
    UI::{Shell::*, WindowsAndMessaging::*},
};
use zju_net_assistant::storage::wide;

pub const CALLBACK_MESSAGE: u32 = WM_APP + 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Appearance {
    #[default]
    Checking,
    Online,
    NeedsAttention,
    Disconnected,
    Error,
}

impl Appearance {
    fn from_status(status: &str) -> Self {
        match status {
            "等待检查" | "正在认证…" => Self::Checking,
            "已认证" => Self::Online,
            "无可用物理网卡" | "所选网卡未连接" => Self::Disconnected,
            status if status.starts_with("未认证") || status.contains("状态未知") => {
                Self::NeedsAttention
            }
            _ => Self::Error,
        }
    }

    fn color(self) -> [u8; 3] {
        match self {
            Self::Checking => [24, 91, 155],
            Self::Online => [21, 128, 61],
            Self::NeedsAttention => [174, 101, 8],
            Self::Disconnected => [89, 106, 124],
            Self::Error => [181, 41, 61],
        }
    }
}

fn tooltip(status: &str, busy: bool) -> String {
    let suffix = if busy && Appearance::from_status(status) != Appearance::Checking {
        " · 检查中"
    } else {
        ""
    };
    format!("浙大校园网助手 · {status}{suffix}")
}

#[derive(Default)]
pub struct TrayIcon {
    icon: HICON,
    appearance: Appearance,
    tip: String,
}

impl TrayIcon {
    pub unsafe fn sync(
        &mut self,
        owner: HWND,
        brand: HICON,
        status: &str,
        busy: bool,
        recreate: bool,
    ) {
        let appearance = Appearance::from_status(status);
        let tip = tooltip(status, busy);
        let add = recreate || self.icon == 0;
        let change_icon = self.icon == 0 || self.appearance != appearance;
        if !add && !change_icon && tip == self.tip {
            return;
        }

        let icon = if !change_icon {
            self.icon
        } else if appearance == Appearance::Checking {
            brand
        } else {
            create_icon(appearance.color())
        };
        if icon == 0 {
            return;
        }

        let mut data = notification(owner);
        data.uFlags = NIF_TIP;
        if add || change_icon {
            data.uFlags |= NIF_ICON;
            data.hIcon = icon;
        }
        if add {
            data.uFlags |= NIF_MESSAGE;
            data.uCallbackMessage = CALLBACK_MESSAGE;
        }
        let limit = data.szTip.len() - 1;
        for (output, input) in data
            .szTip
            .iter_mut()
            .zip(wide(&tip).into_iter().take(limit))
        {
            *output = input;
        }
        let mut accepted = Shell_NotifyIconW(if add { NIM_ADD } else { NIM_MODIFY }, &data) != 0;
        if !accepted && !add {
            data.uFlags |= NIF_ICON | NIF_MESSAGE;
            data.hIcon = icon;
            data.uCallbackMessage = CALLBACK_MESSAGE;
            accepted = Shell_NotifyIconW(NIM_ADD, &data) != 0;
        }
        if accepted {
            if self.icon != icon {
                release_custom(self.icon, brand);
            }
            self.icon = icon;
            self.appearance = appearance;
            self.tip = tip;
        } else if self.icon != icon {
            release_custom(icon, brand);
        }
    }

    pub unsafe fn remove(&mut self, owner: HWND, brand: HICON) {
        if self.icon != 0 {
            Shell_NotifyIconW(NIM_DELETE, &notification(owner));
            release_custom(self.icon, brand);
            self.icon = 0;
        }
    }
}

unsafe fn notification(owner: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: owner,
        uID: 1,
        ..std::mem::zeroed()
    }
}

unsafe fn release_custom(icon: HICON, brand: HICON) {
    if icon != 0 && icon != brand {
        DestroyIcon(icon);
    }
}

pub unsafe fn create_brand_icon() -> HICON {
    create_icon(Appearance::Checking.color())
}

unsafe fn create_icon([r, g, b]: [u8; 3]) -> HICON {
    let mut pixels = [0u8; 32 * 32 * 4];
    let mask = [0u8; 32 * 4];
    let background = [b, g, r, 255];
    for y in 0..32 {
        for x in 0..32 {
            let mark = ((8..=11).contains(&y) || (20..=23).contains(&y)) && (8..=23).contains(&x)
                || (11..=20).contains(&y) && ((x + y) as i32 - 31).abs() <= 2;
            let index = (y * 32 + x) * 4;
            pixels[index..index + 4].copy_from_slice(if mark {
                &[255, 255, 255, 255]
            } else {
                &background
            });
        }
    }
    CreateIcon(
        GetModuleHandleW(null()),
        32,
        32,
        1,
        32,
        mask.as_ptr(),
        pixels.as_ptr(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigns_tray_colors_from_authentication_status() {
        for (status, expected) in [
            ("等待检查", Appearance::Checking),
            ("正在认证…", Appearance::Checking),
            ("已认证", Appearance::Online),
            ("未认证，请填写账号和密码并保存", Appearance::NeedsAttention),
            ("认证状态未知，暂不提交认证", Appearance::NeedsAttention),
            ("无可用物理网卡", Appearance::Disconnected),
            ("所选网卡未连接", Appearance::Disconnected),
            ("未检测到可用校园网门户", Appearance::Error),
            ("账号或密码错误，自动认证已暂停", Appearance::Error),
        ] {
            assert_eq!(Appearance::from_status(status), expected, "{status}");
        }
        assert!(tooltip("已认证", true).ends_with("已认证 · 检查中"));
        assert!(tooltip("正在认证…", true).ends_with("正在认证…"));
    }
}

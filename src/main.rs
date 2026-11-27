#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod tray;

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    ptr::null,
    sync::{mpsc::Sender, Arc, Mutex},
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::{LibraryLoader::*, SystemServices::*, Threading::*},
    UI::{
        Controls::*,
        HiDpi::*,
        Input::KeyboardAndMouse::{EnableWindow, GetFocus, IsWindowEnabled},
        Shell::*,
        WindowsAndMessaging::*,
    },
};
use zeroize::Zeroizing;
use zju_net_assistant::{
    engine::{self, Command, CredentialStorage, Model, SaveStatus, Shared},
    storage::{self, wide},
};

const UPDATE: u32 = WM_APP + 1;
const OPEN_PANEL: u32 = WM_APP + 3;
const USER: i32 = 101;
const PASS: i32 = 102;
const ADAPTER: i32 = 103;
const PORTAL: i32 = 104;
const INTERVAL: i32 = 105;
const AUTO: i32 = 106;
const REMEMBER: i32 = 107;
const STARTUP: i32 = 108;
const SAVE: i32 = 110;
const LOGIN: i32 = 111;
const CHECK: i32 = 112;
const LOGDIR: i32 = 113;
const SHOW: u32 = 901;
const PAUSE: u32 = 902;
const EXIT: u32 = 903;
const METRIC_LABEL: i32 = 120;
const STATUS_LABEL: i32 = 121;
const CREDENTIAL_LABEL: i32 = 122;
const EVENT_LOG: i32 = 123;

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}
const PANEL_BG: COLORREF = rgb(245, 248, 251);
const INK: COLORREF = rgb(26, 42, 61);
const MUTED: COLORREF = rgb(80, 99, 120);
const BLUE: COLORREF = rgb(21, 77, 153);
const GREEN: COLORREF = rgb(21, 102, 65);
const AMBER: COLORREF = rgb(129, 70, 12);
const RED: COLORREF = rgb(144, 37, 47);

fn state_colors(state: &str, busy: bool) -> (COLORREF, COLORREF) {
    if state == "正在认证…" || busy || state == "等待检查" {
        (rgb(225, 238, 255), BLUE)
    } else if state == "已认证" {
        (rgb(216, 243, 227), GREEN)
    } else if state.starts_with("未认证") || state.contains("未知") {
        (rgb(255, 238, 211), AMBER)
    } else {
        (rgb(254, 228, 231), RED)
    }
}

#[derive(Clone, Copy)]
struct PaintState {
    panel_brush: HBRUSH,
    state_brush: HBRUSH,
    state_bg: COLORREF,
    state_fg: COLORREF,
    credential_color: COLORREF,
}
impl PaintState {
    fn new(panel_brush: HBRUSH) -> Self {
        Self {
            panel_brush,
            state_brush: 0,
            state_bg: PANEL_BG,
            state_fg: BLUE,
            credential_color: MUTED,
        }
    }
}

enum WindowAction {
    Show,
    Close(HWND),
    Minimize(HWND),
    Refresh,
    RefreshCredentials(HWND),
    Save(HWND),
    OpenLogs(HWND),
    TrayMenu,
    RestoreTray(HWND),
    Measure,
    Send(Command),
}

// Win32 can send nested messages while App updates a control. The window
// procedure sees only this shared state; App changes run on the outer loop.
struct WindowEvents {
    pending: RefCell<VecDeque<WindowAction>>,
    paint: Cell<PaintState>,
    taskbar_created: u32,
}
impl WindowEvents {
    fn new(brush: HBRUSH, taskbar_created: u32) -> Self {
        Self {
            pending: RefCell::new(VecDeque::new()),
            paint: Cell::new(PaintState::new(brush)),
            taskbar_created,
        }
    }
    unsafe fn push(&self, window: HWND, action: WindowAction) {
        let needs_wake = {
            let mut queue = self.pending.borrow_mut();
            let was_empty = queue.is_empty();
            queue.push_back(action);
            was_empty
        };
        if needs_wake {
            PostMessageW(window, WM_NULL, 0, 0);
        }
    }
    fn pop(&self) -> Option<WindowAction> {
        self.pending.borrow_mut().pop_front()
    }
}

struct Ui {
    state: HWND,
    internet: HWND,
    adapter: HWND,
    ip: HWND,
    portal_ip: HWND,
    portal: HWND,
    time: HWND,
    credentials: HWND,
    logs: HWND,
    user: HWND,
    password: HWND,
    adapter_ids: Vec<String>,
    log_tail: String,
    font: HFONT,
    state_font: HFONT,
    clear_password_after_save: bool,
    synced_auto: bool,
    scale: i32,
}
impl Default for Ui {
    fn default() -> Self {
        Self {
            state: 0,
            internet: 0,
            adapter: 0,
            ip: 0,
            portal_ip: 0,
            portal: 0,
            time: 0,
            credentials: 0,
            logs: 0,
            user: 0,
            password: 0,
            adapter_ids: Vec::new(),
            log_tail: String::new(),
            font: 0,
            state_font: 0,
            clear_password_after_save: false,
            synced_auto: false,
            scale: 96,
        }
    }
}
struct App<'a> {
    controller: HWND,
    panel: HWND,
    shared: Shared,
    tx: Option<Sender<Command>>,
    ui: Ui,
    icon: HICON,
    tray: tray::TrayIcon,
    windows: &'a WindowEvents,
    exiting: bool,
}
impl App<'_> {
    fn send(&self, c: Command) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(c);
        }
    }
    unsafe fn control(
        &self,
        class: &str,
        text: &str,
        style: u32,
        id: i32,
        bounds: (i32, i32, i32, i32),
    ) -> HWND {
        let (x, y, width, height) = bounds;
        let s = |n: i32| n * self.ui.scale / 96;
        let hwnd = CreateWindowExW(
            if class == "EDIT" { WS_EX_CLIENTEDGE } else { 0 },
            wide(class).as_ptr(),
            wide(text).as_ptr(),
            WS_CHILD | WS_VISIBLE | style,
            s(x),
            s(y),
            s(width),
            s(height),
            self.panel,
            id as isize,
            GetModuleHandleW(null()),
            null(),
        );
        SendMessageW(hwnd, WM_SETFONT, self.ui.font as usize, 1);
        hwnd
    }
    unsafe fn text(&self, value: &str, x: i32, y: i32, w: i32, h: i32) -> HWND {
        self.control("STATIC", value, SS_LEFT | SS_NOPREFIX, 0, (x, y, w, h))
    }
    unsafe fn metric(&self, label: &str, x: i32, y: i32) -> HWND {
        self.control(
            "STATIC",
            label,
            SS_LEFT | SS_CENTERIMAGE,
            METRIC_LABEL,
            (x, y, 83, 23),
        );
        self.control(
            "STATIC",
            "—",
            SS_LEFT | SS_CENTERIMAGE | SS_ENDELLIPSIS | SS_NOPREFIX,
            0,
            (x + 87, y, 187, 23),
        )
    }
    unsafe fn edit(&self, value: &str, id: i32, x: i32, y: i32, w: i32, style: u32) -> HWND {
        let h = self.control(
            "EDIT",
            value,
            WS_TABSTOP | ES_AUTOHSCROLL as u32 | style,
            id,
            (x, y, w, 27),
        );
        SendMessageW(h, EM_SETLIMITTEXT, if id == PASS { 256 } else { 128 }, 0);
        h
    }
    unsafe fn check_box(&self, value: &str, id: i32, x: i32, y: i32, w: i32, checked: bool) {
        let h = self.control(
            "BUTTON",
            value,
            WS_TABSTOP | BS_AUTOCHECKBOX as u32,
            id,
            (x, y, w, 35),
        );
        SendMessageW(h, BM_SETCHECK, checked as usize, 0);
        SetWindowSubclass(h, Some(paintable_checkbox), 1, self.ui.scale as usize);
    }
    unsafe fn show(&mut self) {
        if self.panel != 0 {
            ShowWindow(self.panel, SW_RESTORE);
            SetForegroundWindow(self.panel);
            return;
        }
        self.ui.scale = GetDpiForSystem() as i32;
        let scale = self.ui.scale;
        let family = wide("Microsoft YaHei UI");
        self.ui.font = CreateFontW(
            -14 * scale / 96,
            0,
            0,
            0,
            400,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            0,
            0,
            CLEARTYPE_QUALITY as u32,
            0,
            family.as_ptr(),
        );
        self.ui.state_font = CreateFontW(
            -21 * scale / 96,
            0,
            0,
            0,
            700,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            0,
            0,
            CLEARTYPE_QUALITY as u32,
            0,
            family.as_ptr(),
        );
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 620 * scale / 96,
            bottom: 570 * scale / 96,
        };
        AdjustWindowRectExForDpi(&mut rect, style, 0, WS_EX_CONTROLPARENT, scale as u32);
        self.panel = CreateWindowExW(
            WS_EX_CONTROLPARENT,
            wide("ZjuNetAssistant.Panel").as_ptr(),
            wide("浙大校园网助手").as_ptr(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            rect.right - rect.left,
            rect.bottom - rect.top,
            0,
            0,
            GetModuleHandleW(null()),
            std::ptr::from_ref(self.windows).cast(),
        );
        SendMessageW(self.panel, WM_SETICON, ICON_SMALL as usize, self.icon);
        SendMessageW(self.panel, WM_SETICON, ICON_BIG as usize, self.icon);
        self.ui.state = self.control(
            "STATIC",
            "  ●  等待检查",
            SS_LEFT | SS_CENTERIMAGE | SS_ENDELLIPSIS | SS_NOPREFIX,
            STATUS_LABEL,
            (24, 20, 572, 47),
        );
        SendMessageW(self.ui.state, WM_SETFONT, self.ui.state_font as usize, 1);
        self.ui.adapter = self.metric("连接网卡", 24, 79);
        self.ui.ip = self.metric("本机 IP", 24, 105);
        self.ui.portal_ip = self.metric("门户识别 IP", 24, 131);
        self.ui.internet = self.metric("互联网", 322, 79);
        self.ui.portal = self.metric("认证入口", 322, 105);
        self.ui.time = self.metric("上次检查", 322, 131);
        self.control("STATIC", "", SS_ETCHEDHORZ, 0, (24, 164, 572, 2));
        let config = self.shared.lock().unwrap().config.clone();
        self.text("账号与设置", 24, 177, 160, 24);
        self.ui.credentials = self.control(
            "STATIC",
            "",
            SS_RIGHT | SS_CENTERIMAGE | SS_NOPREFIX,
            CREDENTIAL_LABEL,
            (275, 172, 321, 28),
        );
        self.text("账号", 24, 210, 55, 24);
        self.ui.user = self.edit(&config.username, USER, 80, 205, 204, 0);
        self.text("密码", 306, 210, 50, 24);
        self.ui.password = self.edit("", PASS, 362, 205, 234, ES_PASSWORD as u32);
        SendMessageW(
            self.ui.password,
            EM_SETCUEBANNER,
            0,
            wide("留空沿用当前密码").as_ptr() as isize,
        );
        self.text("网卡", 24, 245, 55, 24);
        self.control(
            "COMBOBOX",
            "",
            WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32,
            ADAPTER,
            (80, 240, 516, 220),
        );
        self.text("入口", 24, 280, 55, 24);
        let portal = self.control(
            "COMBOBOX",
            "",
            WS_TABSTOP | CBS_DROPDOWNLIST as u32,
            PORTAL,
            (80, 275, 300, 180),
        );
        for s in [
            "自动切换（推荐）",
            "net.zju.edu.cn",
            "net2.zju.edu.cn",
            "net3.zju.edu.cn",
        ] {
            SendMessageW(portal, CB_ADDSTRING, 0, wide(s).as_ptr() as isize);
        }
        let selection = zju_net_assistant::protocol::HOSTS
            .iter()
            .position(|h| *h == config.portal)
            .map(|n| n + 1)
            .unwrap_or(0);
        SendMessageW(portal, CB_SETCURSEL, selection, 0);
        self.text("间隔", 398, 280, 44, 24);
        self.edit(
            &config.interval.to_string(),
            INTERVAL,
            447,
            275,
            99,
            ES_NUMBER as u32,
        );
        self.text("秒", 560, 280, 36, 24);
        self.check_box("自动认证", AUTO, 24, 308, 144, config.auto);
        self.ui.synced_auto = config.auto;
        self.check_box("保存账户密码", REMEMBER, 184, 308, 181, config.remember);
        self.check_box("登录系统后启动", STARTUP, 381, 308, 215, config.startup);
        self.control(
            "BUTTON",
            "保存设置",
            WS_TABSTOP | BS_PUSHBUTTON as u32,
            SAVE,
            (24, 354, 132, 35),
        );
        self.control(
            "BUTTON",
            "手动认证",
            WS_TABSTOP | BS_PUSHBUTTON as u32,
            LOGIN,
            (170, 354, 132, 35),
        );
        self.control(
            "BUTTON",
            "立即检查",
            WS_TABSTOP | BS_PUSHBUTTON as u32,
            CHECK,
            (316, 354, 132, 35),
        );
        self.control(
            "BUTTON",
            "打开日志",
            WS_TABSTOP | BS_PUSHBUTTON as u32,
            LOGDIR,
            (462, 354, 134, 35),
        );
        self.text("重要事件", 24, 406, 180, 24);
        self.ui.logs = self.control(
            "EDIT",
            "",
            WS_TABSTOP | WS_VSCROLL | (ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY) as u32,
            EVENT_LOG,
            (24, 433, 572, 113),
        );
        let margin = (8 * scale / 96) as isize;
        SendMessageW(
            self.ui.logs,
            EM_SETMARGINS,
            (EC_LEFTMARGIN | EC_RIGHTMARGIN) as usize,
            margin | margin << 16,
        );
        self.ui.adapter_ids.clear();
        self.ui.log_tail.clear();
        self.refresh();
        ShowWindow(self.panel, SW_SHOW);
        UpdateWindow(self.panel);
        SetForegroundWindow(self.panel);
    }
    unsafe fn refresh(&mut self) {
        self.sync_tray(false);
        if self.panel == 0 {
            return;
        }
        let m = self.shared.lock().unwrap().clone();
        let (background, foreground) = state_colors(&m.state, m.busy);
        let mut paint = self.windows.paint.get();
        if paint.state_brush == 0 || paint.state_bg != background {
            let previous = paint.state_brush;
            paint.state_brush = CreateSolidBrush(background);
            paint.state_bg = background;
            paint.state_fg = foreground;
            self.windows.paint.set(paint);
            if previous != 0 {
                DeleteObject(previous);
            }
            InvalidateRect(self.ui.state, null(), 1);
        }
        let suffix = if m.busy && m.state != "正在认证…" && m.state != "等待检查" {
            "  ·  检查中"
        } else {
            ""
        };
        set(self.ui.state, &format!("  ●  {}{suffix}", m.state));
        set(self.ui.internet, &m.internet);
        set(self.ui.adapter, &m.adapter);
        set(self.ui.ip, &m.ip);
        set(self.ui.portal_ip, &m.portal_ip);
        set(self.ui.portal, &m.portal);
        set(self.ui.time, &m.checked);
        let saving = m.save_status == SaveStatus::Saving;
        if self.ui.clear_password_after_save && !saving {
            self.ui.clear_password_after_save = false;
            if m.save_status == SaveStatus::Saved {
                set(self.ui.password, "");
            }
        }
        for id in [LOGIN, CHECK, SAVE] {
            EnableWindow(GetDlgItem(self.panel, id), (!m.busy && !saving) as i32);
        }
        for id in [USER, PASS, REMEMBER] {
            EnableWindow(GetDlgItem(self.panel, id), !saving as i32);
        }
        self.sync_auto_checkbox(m.config.auto);
        self.refresh_credentials();
        let combo = GetDlgItem(self.panel, ADAPTER);
        let selected = SendMessageW(combo, CB_GETCURSEL, 0, 0);
        let keep_id = if selected > 0 {
            self.ui
                .adapter_ids
                .get(selected as usize - 1)
                .cloned()
                .unwrap_or_default()
        } else {
            m.config.adapter.clone()
        };
        let mut ids = Vec::new();
        let mut names = Vec::new();
        for a in &m.adapters {
            if !ids.contains(&a.id) {
                ids.push(a.id.clone());
                names.push(format!("{} · {}", a.name, a.ip));
            }
        }
        if !m.config.adapter.is_empty() && !ids.contains(&m.config.adapter) {
            ids.push(m.config.adapter.clone());
            names.push("已指定网卡（当前未连接）".into());
        }
        if ids != self.ui.adapter_ids || SendMessageW(combo, CB_GETCOUNT, 0, 0) == 0 {
            SendMessageW(combo, CB_RESETCONTENT, 0, 0);
            SendMessageW(
                combo,
                CB_ADDSTRING,
                0,
                wide("自动选择可用物理网卡").as_ptr() as isize,
            );
            for name in names {
                SendMessageW(combo, CB_ADDSTRING, 0, wide(&name).as_ptr() as isize);
            }
            let n = ids
                .iter()
                .position(|id| *id == keep_id)
                .map(|i| i + 1)
                .unwrap_or(0);
            SendMessageW(combo, CB_SETCURSEL, n, 0);
            self.ui.adapter_ids = ids;
        }
        let log_text = m.events.iter().cloned().collect::<Vec<_>>().join("\r\n");
        if log_text != self.ui.log_tail {
            let mut scroll = SCROLLINFO {
                cbSize: std::mem::size_of::<SCROLLINFO>() as u32,
                fMask: SIF_PAGE | SIF_POS | SIF_RANGE,
                ..std::mem::zeroed()
            };
            let have_scroll = GetScrollInfo(self.ui.logs, SB_VERT, &mut scroll) != 0;
            let was_at_end = !have_scroll || scroll.nPos + scroll.nPage.max(1) as i32 > scroll.nMax;
            SendMessageW(self.ui.logs, WM_SETREDRAW, 0, 0);
            set(self.ui.logs, &log_text);
            if was_at_end {
                SendMessageW(self.ui.logs, WM_VSCROLL, SB_BOTTOM as usize, 0);
            } else {
                SendMessageW(self.ui.logs, EM_LINESCROLL, 0, scroll.nPos as isize);
            }
            SendMessageW(self.ui.logs, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.ui.logs, null(), 1);
            self.ui.log_tail = log_text;
        }
    }
    unsafe fn sync_auto_checkbox(&mut self, auto: bool) {
        if self.ui.synced_auto != auto {
            self.ui.synced_auto = auto;
            SendMessageW(GetDlgItem(self.panel, AUTO), BM_SETCHECK, auto as usize, 0);
        }
    }
    unsafe fn refresh_credentials(&mut self) {
        if self.ui.credentials == 0 || self.ui.password == 0 {
            return;
        }
        let (status, persisted, username, remember) = {
            let model = self.shared.lock().unwrap();
            (
                model.save_status,
                model.credential_storage,
                model.config.username.clone(),
                model.config.remember,
            )
        };
        let edited = get(self.ui.user).trim() != username
            || GetWindowTextLengthW(self.ui.password) > 0
            || checked(self.panel, REMEMBER) != remember;
        let (label, color) = match status {
            SaveStatus::Saving => ("正在保存…", BLUE),
            SaveStatus::Failed => ("保存失败 · 请查看重要事件", RED),
            _ if edited => ("凭据有未保存的修改", AMBER),
            _ => match persisted {
                CredentialStorage::Checking => ("正在检查已保存凭据…", MUTED),
                CredentialStorage::NotSaved => ("账号密码未保存", MUTED),
                CredentialStorage::Saved => ("账号密码已保存", GREEN),
                CredentialStorage::SessionOnly => ("凭据仅本次运行有效", BLUE),
                CredentialStorage::Unavailable => ("无法读取已保存凭据", RED),
            },
        };
        let mut paint = self.windows.paint.get();
        paint.credential_color = color;
        self.windows.paint.set(paint);
        set(self.ui.credentials, label);
    }
    unsafe fn save(&mut self) {
        let mut c = self.shared.lock().unwrap().config.clone();
        c.username = get(GetDlgItem(self.panel, USER)).trim().to_owned();
        let password = Zeroizing::new(get(GetDlgItem(self.panel, PASS)));
        let interval = get(GetDlgItem(self.panel, INTERVAL));
        let Ok(interval) = interval.parse::<u64>() else {
            self.message("检查间隔应为 15～3600 秒的整数。");
            return;
        };
        if !(15..=3600).contains(&interval) {
            self.message("检查间隔应为 15～3600 秒。");
            return;
        }
        c.interval = interval;
        let auto = checked(self.panel, AUTO);
        let auto_override = (auto != self.ui.synced_auto).then_some(auto);
        c.remember = checked(self.panel, REMEMBER);
        c.startup = checked(self.panel, STARTUP);
        let i = SendMessageW(GetDlgItem(self.panel, ADAPTER), CB_GETCURSEL, 0, 0);
        c.adapter = if i > 0 {
            self.ui
                .adapter_ids
                .get(i as usize - 1)
                .cloned()
                .unwrap_or_default()
        } else {
            String::new()
        };
        let i = SendMessageW(GetDlgItem(self.panel, PORTAL), CB_GETCURSEL, 0, 0);
        c.portal = if i > 0 {
            zju_net_assistant::protocol::HOSTS[(i as usize - 1).min(2)].into()
        } else {
            String::new()
        };
        self.shared.lock().unwrap().save_status = SaveStatus::Saving;
        self.ui.clear_password_after_save = true;
        self.refresh();
        self.send(Command::Save {
            config: c,
            password: (!password.is_empty()).then_some(password),
            auto_override,
        });
    }
    unsafe fn message(&self, msg: &str) {
        MessageBoxW(
            self.panel,
            wide(msg).as_ptr(),
            wide("浙大校园网助手").as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
    unsafe fn sync_tray(&mut self, recreate: bool) {
        let (status, busy) = {
            let model = self.shared.lock().unwrap();
            (model.state.clone(), model.busy)
        };
        self.tray
            .sync(self.controller, self.icon, &status, busy, recreate);
    }
    unsafe fn menu(&mut self) {
        let menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, SHOW as usize, wide("显示主界面").as_ptr());
        AppendMenuW(menu, MF_STRING, CHECK as usize, wide("立即检查").as_ptr());
        let auto = self.shared.lock().unwrap().config.auto;
        AppendMenuW(
            menu,
            MF_STRING,
            PAUSE as usize,
            wide(if auto {
                "暂停自动认证"
            } else {
                "开启自动认证"
            })
            .as_ptr(),
        );
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        AppendMenuW(menu, MF_STRING, EXIT as usize, wide("退出").as_ptr());
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(self.controller);
        let selected = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            0,
            self.controller,
            null(),
        );
        DestroyMenu(menu);
        PostMessageW(self.controller, WM_NULL, 0, 0);
        match selected as u32 {
            SHOW => self.show(),
            PAUSE => self.send(Command::Auto(!auto)),
            EXIT => self.exit(),
            x if x == CHECK as u32 => self.send(Command::Check),
            _ => {}
        }
    }
    unsafe fn close_panel(&mut self) {
        if self.panel != 0 {
            let panel = self.panel;
            self.panel = 0;
            DestroyWindow(panel);
        }
        if self.ui.font != 0 {
            DeleteObject(self.ui.font);
            self.ui.font = 0;
        }
        if self.ui.state_font != 0 {
            DeleteObject(self.ui.state_font);
        }
        let paint = self.windows.paint.get();
        self.windows.paint.set(PaintState::new(paint.panel_brush));
        if paint.state_brush != 0 {
            DeleteObject(paint.state_brush);
        }
        self.ui = Ui::default();
    }
    unsafe fn exit(&mut self) {
        self.exiting = true;
        self.send(Command::Stop);
        self.close_panel();
        PostQuitMessage(0);
    }
    unsafe fn handle_action(&mut self, action: WindowAction) {
        match action {
            WindowAction::Show => self.show(),
            WindowAction::Close(h) if h == self.controller => self.exit(),
            WindowAction::Close(h) | WindowAction::Minimize(h) if h == self.panel => {
                self.close_panel()
            }
            WindowAction::Refresh => self.refresh(),
            WindowAction::RefreshCredentials(h) if h == self.panel => self.refresh_credentials(),
            WindowAction::Save(h) if h == self.panel => self.save(),
            WindowAction::OpenLogs(h) if h == self.panel => {
                let path = storage::data_dir();
                let _ = std::fs::create_dir_all(&path);
                ShellExecuteW(
                    h,
                    wide("open").as_ptr(),
                    wide(&path.to_string_lossy()).as_ptr(),
                    null(),
                    null(),
                    SW_SHOWNORMAL,
                );
            }
            WindowAction::TrayMenu => self.menu(),
            WindowAction::RestoreTray(h) if h == self.controller => self.sync_tray(true),
            WindowAction::Measure => {
                let before = memory_sample("window_created");
                self.close_panel();
                let after = memory_sample("window_destroyed");
                let _ = std::fs::write(
                    storage::data_dir().join("memory.json"),
                    format!("[{},{}]", before, after),
                );
                self.exit();
            }
            WindowAction::Send(command) => self.send(command),
            _ => {}
        }
    }
}
unsafe fn set(h: HWND, s: &str) {
    SetWindowTextW(h, wide(s).as_ptr());
}
unsafe fn get(h: HWND) -> String {
    let len = GetWindowTextLengthW(h).max(0) as usize;
    let mut buf = Zeroizing::new(vec![0u16; len + 1]);
    let n = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
    String::from_utf16_lossy(&buf[..n])
}
unsafe fn checked(panel: HWND, id: i32) -> bool {
    SendMessageW(GetDlgItem(panel, id), BM_GETCHECK, 0, 0) == BST_CHECKED as isize
}
unsafe extern "system" fn wndproc(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == WM_NCCREATE {
        let cs = &*(l as *const CREATESTRUCTW);
        SetWindowLongPtrW(h, GWLP_USERDATA, cs.lpCreateParams as isize);
    }
    let p = GetWindowLongPtrW(h, GWLP_USERDATA) as *const WindowEvents;
    if p.is_null() {
        return DefWindowProcW(h, msg, w, l);
    }
    let windows = &*p;
    if msg == windows.taskbar_created && msg != 0 {
        windows.push(h, WindowAction::RestoreTray(h));
        return 0;
    }
    let action = match msg {
        OPEN_PANEL => WindowAction::Show,
        UPDATE => WindowAction::Refresh,
        WM_CLOSE => WindowAction::Close(h),
        WM_SYSCOMMAND if w as u32 & 0xfff0 == SC_MINIMIZE => WindowAction::Minimize(h),
        WM_COMMAND => {
            let id = w as i32 & 0xffff;
            let notification = (w >> 16) as u32 & 0xffff;
            match (id, notification) {
                (SAVE, 0) => WindowAction::Save(h),
                (LOGIN, 0) => WindowAction::Send(Command::Login),
                (CHECK, 0) => WindowAction::Send(Command::Check),
                (REMEMBER, 0) | (USER | PASS, EN_CHANGE) => WindowAction::RefreshCredentials(h),
                (LOGDIR, 0) => WindowAction::OpenLogs(h),
                _ => return 0,
            }
        }
        tray::CALLBACK_MESSAGE => match l as u32 {
            WM_LBUTTONUP => WindowAction::Show,
            WM_RBUTTONUP | WM_CONTEXTMENU => WindowAction::TrayMenu,
            _ => return 0,
        },
        WM_POWERBROADCAST => {
            windows.push(h, WindowAction::Send(Command::Network));
            return 1;
        }
        WM_TIMER if w == 77 => {
            KillTimer(h, 77);
            WindowAction::Measure
        }
        WM_CTLCOLORSTATIC => {
            let paint = windows.paint.get();
            let dc = w as HDC;
            SetBkMode(dc, TRANSPARENT as i32);
            let color = match GetDlgCtrlID(l) {
                EVENT_LOG => {
                    SetTextColor(dc, INK);
                    SetBkColor(dc, GetSysColor(COLOR_WINDOW));
                    return GetSysColorBrush(COLOR_WINDOW);
                }
                STATUS_LABEL if paint.state_brush != 0 => {
                    SetTextColor(dc, paint.state_fg);
                    return paint.state_brush;
                }
                CREDENTIAL_LABEL => paint.credential_color,
                METRIC_LABEL => MUTED,
                _ => INK,
            };
            SetTextColor(dc, color);
            return paint.panel_brush;
        }
        _ => return DefWindowProcW(h, msg, w, l),
    };
    windows.push(h, action);
    0
}

unsafe extern "system" fn paintable_checkbox(
    hwnd: HWND,
    msg: u32,
    w: WPARAM,
    l: LPARAM,
    id: usize,
    dpi: usize,
) -> LRESULT {
    if msg == WM_PAINT {
        let mut paint = std::mem::zeroed::<PAINTSTRUCT>();
        let dc = BeginPaint(hwnd, &mut paint);
        if dc != 0 {
            paint_checkbox(hwnd, dc, dpi as i32);
        }
        EndPaint(hwnd, &paint);
        return 0;
    }
    if msg == WM_PRINTCLIENT {
        paint_checkbox(hwnd, w as HDC, dpi as i32);
        return 0;
    }
    if msg == WM_NCDESTROY {
        RemoveWindowSubclass(hwnd, Some(paintable_checkbox), id);
    }
    let result = DefSubclassProc(hwnd, msg, w, l);
    if matches!(
        msg,
        BM_SETCHECK
            | BM_SETSTATE
            | WM_SETFOCUS
            | WM_KILLFOCUS
            | WM_ENABLE
            | WM_UPDATEUISTATE
            | WM_LBUTTONUP
            | WM_KEYUP
    ) {
        InvalidateRect(hwnd, null(), 0);
    }
    result
}

unsafe fn paint_checkbox(hwnd: HWND, dc: HDC, dpi: i32) {
    let scale = |value: i32| value * dpi / 96;
    let mut rect = std::mem::zeroed::<RECT>();
    GetClientRect(hwnd, &mut rect);
    let background = CreateSolidBrush(PANEL_BG);
    FillRect(dc, &rect, background);
    DeleteObject(background);

    let marked = SendMessageW(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
    let enabled = IsWindowEnabled(hwnd) != 0;
    let edge = scale(20);
    let left = scale(2);
    let top = (rect.bottom - edge) / 2;
    let square = RECT {
        left,
        top,
        right: left + edge,
        bottom: top + edge,
    };
    let outline = if enabled && marked {
        BLUE
    } else {
        rgb(112, 132, 154)
    };
    let fill = if marked { outline } else { rgb(255, 255, 255) };
    let fill_brush = CreateSolidBrush(fill);
    let border_brush = CreateSolidBrush(outline);
    FillRect(dc, &square, fill_brush);
    FrameRect(dc, &square, border_brush);
    DeleteObject(fill_brush);
    DeleteObject(border_brush);
    if marked {
        let pen = CreatePen(PS_SOLID, scale(2).max(1), rgb(255, 255, 255));
        let previous = SelectObject(dc, pen);
        MoveToEx(dc, left + scale(4), top + scale(10), std::ptr::null_mut());
        LineTo(dc, left + scale(8), top + scale(14));
        LineTo(dc, left + scale(16), top + scale(6));
        SelectObject(dc, previous);
        DeleteObject(pen);
    }
    let font = SendMessageW(hwnd, WM_GETFONT, 0, 0);
    let previous_font = if font != 0 { SelectObject(dc, font) } else { 0 };
    SetBkMode(dc, TRANSPARENT as i32);
    SetTextColor(dc, if enabled { INK } else { MUTED });
    let label = wide(&get(hwnd));
    let mut text_rect = RECT {
        left: square.right + scale(9),
        right: rect.right,
        top: 0,
        bottom: rect.bottom,
    };
    DrawTextW(
        dc,
        label.as_ptr(),
        label.len() as i32 - 1,
        &mut text_rect,
        DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
    );
    if previous_font != 0 {
        SelectObject(dc, previous_font);
    }
    if GetFocus() == hwnd
        && SendMessageW(hwnd, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS as isize == 0
    {
        DrawFocusRect(dc, &rect);
    }
}
fn main() {
    if std::env::args().any(|s| s == "--diagnose") {
        diagnose();
        return;
    }
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let testing = std::env::var_os("ZJU_ASSISTANT_DATA_DIR").is_some();
        let mutex = CreateMutexW(
            null(),
            0,
            wide(if testing {
                "Local\\ZjuNetAssistant.Test"
            } else {
                "Local\\ZjuNetAssistant.Desktop"
            })
            .as_ptr(),
        );
        if mutex == 0 {
            return;
        }
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let window = FindWindowW(wide("ZjuNetAssistant.Controller").as_ptr(), null());
            if window != 0 {
                PostMessageW(window, OPEN_PANEL, 0, 0);
            }
            CloseHandle(mutex);
            return;
        }
        let config = storage::load();
        let load_error = config.as_ref().err().cloned();
        let shared = Arc::new(Mutex::new(Model::new(config.unwrap_or_default())));
        let brush = CreateSolidBrush(PANEL_BG);
        let windows = WindowEvents::new(
            brush,
            RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()),
        );
        let mut app = App {
            controller: 0,
            panel: 0,
            shared: shared.clone(),
            tx: None,
            ui: Ui::default(),
            icon: tray::create_brand_icon(),
            tray: tray::TrayIcon::default(),
            windows: &windows,
            exiting: false,
        };
        let instance = GetModuleHandleW(null());
        for name in ["ZjuNetAssistant.Controller", "ZjuNetAssistant.Panel"] {
            let class_name = wide(name);
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                hInstance: instance,
                hIcon: app.icon,
                hCursor: LoadCursorW(0, IDC_ARROW),
                hbrBackground: brush,
                lpszClassName: class_name.as_ptr(),
                ..std::mem::zeroed()
            };
            if RegisterClassW(&wc) == 0 {
                MessageBoxW(
                    0,
                    wide("注册窗口失败").as_ptr(),
                    wide("启动失败").as_ptr(),
                    MB_OK,
                );
                return;
            }
        }
        app.controller = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            wide("ZjuNetAssistant.Controller").as_ptr(),
            wide("ZjuNetAssistant.Controller").as_ptr(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            0,
            0,
            instance,
            std::ptr::from_ref(&windows).cast(),
        );
        if app.controller == 0 {
            return;
        }
        app.sync_tray(true);
        let controller = app.controller;
        let (tx, _worker) = engine::start(shared, move || {
            PostMessageW(controller, UPDATE, 0, 0);
        });
        app.tx = Some(tx);
        if !std::env::args().any(|s| s == "--background") {
            app.show();
        }
        if std::env::args().any(|s| s == "--measure") {
            SetTimer(app.controller, 77, 10000, None);
        }
        if let Some(e) = load_error {
            app.message(&e);
        }
        let mut msg = std::mem::zeroed::<MSG>();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            if app.panel == 0 || IsDialogMessageW(app.panel, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            while !app.exiting {
                let Some(action) = windows.pop() else {
                    break;
                };
                app.handle_action(action);
            }
        }
        app.tray.remove(app.controller, app.icon);
        app.close_panel();
        DestroyWindow(app.controller);
        DestroyIcon(app.icon);
        DeleteObject(brush);
        CloseHandle(mutex);
    }
}
fn memory_sample(phase: &str) -> String {
    #[repr(C)]
    struct Counters {
        cb: u32,
        faults: u32,
        peak_ws: usize,
        ws: usize,
        peak_pool: usize,
        pool: usize,
        peak_nonpool: usize,
        nonpool: usize,
        pagefile: usize,
        peak_pagefile: usize,
        private: usize,
    }
    #[link(name = "psapi")]
    extern "system" {
        fn GetProcessMemoryInfo(process: HANDLE, counters: *mut Counters, size: u32) -> i32;
    }
    unsafe {
        let mut c: Counters = std::mem::zeroed();
        c.cb = std::mem::size_of::<Counters>() as u32;
        if GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut c,
            std::mem::size_of::<Counters>() as u32,
        ) == 0
        {
            return "null".into();
        }
        format!(
            "{{\"phase\":\"{phase}\",\"working_set_bytes\":{},\"private_bytes\":{}}}",
            c.ws, c.private
        )
    }
}
fn diagnose() {
    let path = storage::data_dir();
    let _ = std::fs::create_dir_all(&path);
    let adapters = zju_net_assistant::network::adapters();
    let text = match adapters {
        Ok(a) => format!(
            "ZjuNetAssistant {}\r\n{}\r\nActive physical adapters: {}\r\n{}\r\n",
            env!("CARGO_PKG_VERSION"),
            storage::time(),
            a.len(),
            a.iter()
                .map(|n| format!(
                    "{} | {} | index {} | metric {}",
                    n.name, n.ip, n.index, n.metric
                ))
                .collect::<Vec<_>>()
                .join("\r\n")
        ),
        Err(e) => e,
    };
    let _ = std::fs::write(path.join("diagnostics.txt"), text);
}

#[cfg(test)]
mod window_tests {
    use super::*;

    #[test]
    fn native_edit_notifications_queue_and_auto_sync_preserves_other_edits() {
        unsafe {
            let windows = WindowEvents::new(0, 0);
            let class = wide("ZjuNetAssistant.TestPanel");
            let instance = GetModuleHandleW(null());
            let window_class = WNDCLASSW {
                hInstance: instance,
                lpfnWndProc: Some(wndproc),
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            assert_ne!(RegisterClassW(&window_class), 0);
            let panel = CreateWindowExW(
                0,
                class.as_ptr(),
                null(),
                WS_POPUP,
                0,
                0,
                360,
                120,
                0,
                0,
                instance,
                std::ptr::from_ref(&windows).cast(),
            );
            assert_ne!(panel, 0);
            let mut app = App {
                controller: 0,
                panel,
                shared: Arc::new(Mutex::new(Model::new(Default::default()))),
                tx: None,
                ui: Ui::default(),
                icon: 0,
                tray: tray::TrayIcon::default(),
                windows: &windows,
                exiting: false,
            };
            let password = app.edit("synthetic-password", PASS, 0, 0, 160, ES_PASSWORD as u32);
            let interval = app.edit("90", INTERVAL, 0, 30, 80, ES_NUMBER as u32);
            app.check_box("自动认证", AUTO, 0, 64, 140, true);
            app.ui.synced_auto = true;
            assert_ne!(password, 0);
            assert_ne!(interval, 0);
            while windows.pop().is_some() {}

            set(password, "");
            assert!(
                matches!(windows.pop(), Some(WindowAction::RefreshCredentials(h)) if h == panel)
            );
            assert!(get(password).is_empty());

            app.sync_auto_checkbox(false);
            assert!(!checked(panel, AUTO));
            assert_eq!(get(interval), "90");
            SendMessageW(
                GetDlgItem(panel, AUTO),
                BM_SETCHECK,
                BST_CHECKED as usize,
                0,
            );
            app.sync_auto_checkbox(false);
            assert!(
                checked(panel, AUTO),
                "an unrelated refresh must preserve a draft checkbox change"
            );

            app.close_panel();
            UnregisterClassW(class.as_ptr(), instance);
        }
    }
}

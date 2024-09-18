use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));

    let frame = sciter::WindowBuilder::main_window().resizeable();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[cfg(feature = "qs")]
    let frame = frame
        .with_rect(sciter::window::Rectangle {
            width: 350,
            height: 500,
            x: 0,
            y: 0,
        });

    let mut frame = frame.create();

    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }

    #[cfg(not(feature = "inline"))]
    {
        #[cfg(feature = "qs")]
        let ui_folder = "ui_qs";
        #[cfg(not(feature = "qs"))]
        let ui_folder = "ui";

        frame.load_file(&format!(
            "file://{}/src/{}/{}",
            std::env::current_dir()
                .map(|c| c.display().to_string())
                .unwrap_or("".to_owned()),
            ui_folder,
            page
        ));
    }

    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        // TODO: removed to prevent update, will be used in the future with a update system
        // is_installed_lower_version()
        return false;
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

#[cfg(not(feature = "inline"))]
pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAAAIGNIUk0AAHolAACAgwAA+f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAMAUExURQAAAASCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCuv///zJlvhQAAAD+dFJOUwAACVS06f7Uml0hJKrz+diJPAQ50++jPcGin/CPIzvu2mEI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QGwOlEoiADWawltd5QUgCAoxCa0Amg+RF1bIfQAVIM+cnH+nPy8BwBIUyi5S4ATsKTPBI94xEWAfeuSmvF5oUk0jOF7Bu1reZ8sa8eUJ8ju4F81USIA9y1HgIDadwPc7zs8OII08/JmhAACTQLWW6wsYMF5QEIBJgPkNsPoaC6Bgt5IALAL0NRYz57pPqygAQTC93JLZWbeckXMFyKTwlALoxDwfgDV+f8OMQPytx5QGIOxEPA2iI9ws0JCJnay7C+0AQBxlSmTs2JTsGDnGJTJz6fszLdd+Uiv5hRakhbDO5btfe+zH2MhZouxHagAVozFBSVT6Oz1ITRbYt8QWrlL6Y0ncEe7V8gMERyr/tSbA+Ge8ZyI+s8sHq6Cvm8NtP1+BT3I4CSDPx/f/VQEkQs6oaOtdkOhMO366Dfr2DNa2XnabHb9eJ9rB/06on7ulBz6VK0tmA0La845bB02TpGPPn8PZUcJ/AarUB0x3NOvzAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDI0LTAzLTI2VDEzOjAyOjA4KzAwOjAwYxmZmgAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOC0wOC0yN1QxNDoyNDo1OSswMDowMENKbagAAAAodEVYdGRhdGU6dGltZXN0YW1wADIwMjQtMDQtMDFUMTQ6MTc6MTkrMDA6MDAWo/r2AAAAE3RFWHRkYzpmb3JtYXQAaW1hZ2UvcG5n/7kbPgAAABV0RVh0cGhvdG9zaG9wOkNvbG9yTW9kZQAzVgKzQAAAABR0RVh0eG1wOkNvbG9yU3BhY2UANjU1MzU7VE3yAAAAKHRFWHR4bXA6Q3JlYXRlRGF0ZQAyMDE4LTA4LTI3VDExOjEwOjI3LTAzOjAw6B5UngAAACx0RVh0eG1wOkNyZWF0b3JUb29sAEFkb2JlIFBob3Rvc2hvcCBDQyAoV2luZG93cykoGY/xAAAAKnRFWHR4bXA6TWV0YWRhdGFEYXRlADIwMTgtMDgtMjdUMTE6MjQ6NTktMDM6MDCqt48mAAAAKHRFWHR4bXA6TW9kaWZ5RGF0ZQAyMDE4LTA4LTI3VDExOjI0OjU5LTAzOjAwlhPcmAAAABd0RVh0eG1wOlBpeGVsWERpbWVuc2lvbgA0MTBD7f5KAAAAF3RFWHR4bXA6UGl4ZWxZRGltZW5zaW9uADQxMN7iHzwAAAA9dEVYdHhtcE1NOkRvY3VtZW50SUQAeG1wLmRpZDo5NzE2ODU0Zi1jMWY1LTE5NDgtODY5My1hZWM2NzAxMzc4Y2Z1zZiXAAAAPXRFWHR4bXBNTTpJbnN0YW5jZUlEAHhtcC5paWQ6MTYxNjA1ODQtNWRlMC0wZjQ4LThhZDctZDI3MTA5ZjkwNTYxWrPRKQAAAEV0RVh0eG1wTU06T3JpZ2luYWxEb2N1bWVudElEAHhtcC5kaWQ6OTcxNjg1NGYtYzFmNS0xOTQ4LTg2OTMtYWVjNjcwMTM3OGNmeRD2ZAAAAABJRU5ErkJggg==".into()
    }

    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAAAIGNIUk0AAHolAACAgwAA+f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAMAUExURQAAAASCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCugSCuv///zJlvhQAAAD+dFJOUwAACVS06f7Uml0hJKrz+diJPAQ50++jPcGin/CPIzvu2mEI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QGwOlEoiADWawltd5QUgCAoxCa0Amg+RF1bIfQAVIM+cnH+nPy8BwBIUyi5S4ATsKTPBI94xEWAfeuSmvF5oUk0jOF7Bu1reZ8sa8eUJ8ju4F81USIA9y1HgIDadwPc7zs8OII08/JmhAACTQLWW6wsYMF5QEIBJgPkNsPoaC6Bgt5IALAL0NRYz57pPqygAQTC93JLZWbeckXMFyKTwlALoxDwfgDV+f8OMQPytx5QGIOxEPA2iI9ws0JCJnay7C+0AQBxlSmTs2JTsGDnGJTJz6fszLdd+Uiv5hRakhbDO5btfe+zH2MhZouxHagAVozFBSVT6Oz1ITRbYt8QWrlL6Y0ncEe7V8gMERyr/tSbA+Ge8ZyI+s8sHq6Cvm8NtP1+BT3I4CSDPx/f/VQEkQs6oaOtdkOhMO366Dfr2DNa2XnabHb9eJ9rB/06on7ulBz6VK0tmA0La845bB02TpGPPn8PZUcJ/AarUB0x3NOvzAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDI0LTAzLTI2VDEzOjAyOjA4KzAwOjAwYxmZmgAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOC0wOC0yN1QxNDoyNDo1OSswMDowMENKbagAAAAodEVYdGRhdGU6dGltZXN0YW1wADIwMjQtMDQtMDFUMTQ6MTc6MTkrMDA6MDAWo/r2AAAAE3RFWHRkYzpmb3JtYXQAaW1hZ2UvcG5n/7kbPgAAABV0RVh0cGhvdG9zaG9wOkNvbG9yTW9kZQAzVgKzQAAAABR0RVh0eG1wOkNvbG9yU3BhY2UANjU1MzU7VE3yAAAAKHRFWHR4bXA6Q3JlYXRlRGF0ZQAyMDE4LTA4LTI3VDExOjEwOjI3LTAzOjAw6B5UngAAACx0RVh0eG1wOkNyZWF0b3JUb29sAEFkb2JlIFBob3Rvc2hvcCBDQyAoV2luZG93cykoGY/xAAAAKnRFWHR4bXA6TWV0YWRhdGFEYXRlADIwMTgtMDgtMjdUMTE6MjQ6NTktMDM6MDCqt48mAAAAKHRFWHR4bXA6TW9kaWZ5RGF0ZQAyMDE4LTA4LTI3VDExOjI0OjU5LTAzOjAwlhPcmAAAABd0RVh0eG1wOlBpeGVsWERpbWVuc2lvbgA0MTBD7f5KAAAAF3RFWHR4bXA6UGl4ZWxZRGltZW5zaW9uADQxMN7iHzwAAAA9dEVYdHhtcE1NOkRvY3VtZW50SUQAeG1wLmRpZDo5NzE2ODU0Zi1jMWY1LTE5NDgtODY5My1hZWM2NzAxMzc4Y2Z1zZiXAAAAPXRFWHR4bXBNTTpJbnN0YW5jZUlEAHhtcC5paWQ6MTYxNjA1ODQtNWRlMC0wZjQ4LThhZDctZDI3MTA5ZjkwNTYxWrPRKQAAAEV0RVh0eG1wTU06T3JpZ2luYWxEb2N1bWVudElEAHhtcC5kaWQ6OTcxNjg1NGYtYzFmNS0xOTQ4LTg2OTMtYWVjNjcwMTM3OGNmeRD2ZAAAAABJRU5ErkJggg==".into()
    }
}

#[cfg(feature = "inline")]
pub fn get_icon() -> String {
    return inline::get_icon();
}

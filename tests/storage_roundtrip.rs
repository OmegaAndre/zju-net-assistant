use zju_net_assistant::storage::{self, Config};
#[test]
fn isolated_windows_storage_roundtrip() {
    let dir = std::env::temp_dir().join(format!("zju-assistant-test-{}", std::process::id()));
    std::env::set_var("ZJU_ASSISTANT_DATA_DIR", &dir);
    let c = Config {
        username: "synthetic-test-account".into(),
        ..Config::default()
    };
    storage::save(&c).unwrap();
    assert_eq!(storage::load().unwrap().username, c.username);
    let text = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(!text.contains("synthetic-test-password"));
    storage::log("synthetic event").unwrap();
    assert!(std::fs::read_to_string(dir.join("events.log"))
        .unwrap()
        .contains("synthetic event"));
    // Delete only the uniquely created test directory, never the normal user data directory.
    std::fs::remove_dir_all(&dir).unwrap();
    std::env::remove_var("ZJU_ASSISTANT_DATA_DIR");
}

#[test]
#[ignore = "Requires Windows Credential Manager access in a desktop logon session"]
fn credential_vault_roundtrip() {
    let dir = std::env::temp_dir().join(format!("zju-vault-test-{}", std::process::id()));
    std::env::set_var("ZJU_ASSISTANT_DATA_DIR", &dir);
    storage::write_password("synthetic-test-account", "synthetic-test-password").unwrap();
    assert_eq!(
        &*storage::read_password("synthetic-test-account").unwrap(),
        "synthetic-test-password"
    );
    assert!(storage::read_password("different-user").unwrap().is_empty());
    storage::delete_password().unwrap();
    assert!(storage::read_password("synthetic-test-account")
        .unwrap()
        .is_empty());
}

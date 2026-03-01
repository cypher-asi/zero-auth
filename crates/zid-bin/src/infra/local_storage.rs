use std::fs;
use std::path::PathBuf;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::AppError;

const DEFAULT_PROFILE: &str = "default";
const MAX_PROFILE_NAME_LEN: usize = 32;

#[derive(Serialize, Deserialize)]
struct ProfileConfig {
    active_profile: String,
}

pub struct LocalStorage {
    base_dir: PathBuf,
    root_dir: PathBuf,
    active_profile: String,
}

impl LocalStorage {
    pub fn new() -> Result<Self, AppError> {
        let root_dir = root_data_dir();
        fs::create_dir_all(&root_dir)
            .map_err(|e| AppError::StorageError(format!("Cannot create data directory: {e}")))?;

        migrate_flat_layout(&root_dir)?;
        migrate_old_project_dirs(&root_dir)?;

        let config = read_profile_config(&root_dir);
        let active = config.active_profile;

        let base_dir = root_dir.join("profiles").join(&active);
        fs::create_dir_all(&base_dir)
            .map_err(|e| AppError::StorageError(format!("Cannot create profile directory: {e}")))?;

        Ok(Self {
            base_dir,
            root_dir,
            active_profile: active,
        })
    }

    pub fn with_profile(name: &str) -> Result<Self, AppError> {
        validate_profile_name(name)?;
        let root_dir = root_data_dir();
        let base_dir = root_dir.join("profiles").join(name);
        if !base_dir.exists() {
            return Err(AppError::StorageError(format!(
                "Profile '{name}' does not exist"
            )));
        }
        let config = read_profile_config(&root_dir);
        Ok(Self {
            base_dir,
            root_dir,
            active_profile: config.active_profile,
        })
    }

    pub fn with_dir(base_dir: PathBuf) -> Result<Self, AppError> {
        fs::create_dir_all(&base_dir)
            .map_err(|e| AppError::StorageError(format!("Cannot create data directory: {e}")))?;
        let root_dir = root_data_dir();
        let config = read_profile_config(&root_dir);
        Ok(Self {
            base_dir,
            root_dir,
            active_profile: config.active_profile,
        })
    }

    pub fn active_profile_name(&self) -> &str {
        &self.active_profile
    }

    pub fn list_profiles(&self) -> Result<Vec<String>, AppError> {
        let profiles_dir = self.root_dir.join("profiles");
        if !profiles_dir.exists() {
            return Ok(vec![self.active_profile.clone()]);
        }
        let mut names = Vec::new();
        let entries = fs::read_dir(&profiles_dir)
            .map_err(|e| AppError::StorageError(format!("Cannot read profiles dir: {e}")))?;
        for entry in entries {
            let entry = entry
                .map_err(|e| AppError::StorageError(format!("Cannot read entry: {e}")))?;
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    names.push(name.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn create_profile(&self, name: &str) -> Result<(), AppError> {
        validate_profile_name(name)?;
        let profile_dir = self.root_dir.join("profiles").join(name);
        if profile_dir.exists() {
            return Err(AppError::StorageError(format!(
                "Profile '{name}' already exists"
            )));
        }
        fs::create_dir_all(&profile_dir)
            .map_err(|e| AppError::StorageError(format!("Cannot create profile: {e}")))?;
        Ok(())
    }

    pub fn delete_profile(&self, name: &str) -> Result<(), AppError> {
        if name == self.active_profile {
            return Err(AppError::StorageError(
                "Cannot delete the active profile".into(),
            ));
        }
        if name == DEFAULT_PROFILE {
            return Err(AppError::StorageError(
                "Cannot delete the default profile".into(),
            ));
        }
        let profile_dir = self.root_dir.join("profiles").join(name);
        if !profile_dir.exists() {
            return Err(AppError::StorageError(format!(
                "Profile '{name}' does not exist"
            )));
        }
        fs::remove_dir_all(&profile_dir)
            .map_err(|e| AppError::StorageError(format!("Cannot delete profile: {e}")))?;
        Ok(())
    }

    pub fn switch_profile(&mut self, name: &str) -> Result<(), AppError> {
        let profile_dir = self.root_dir.join("profiles").join(name);
        if !profile_dir.exists() {
            return Err(AppError::StorageError(format!(
                "Profile '{name}' does not exist"
            )));
        }
        let config = ProfileConfig {
            active_profile: name.to_string(),
        };
        write_profile_config(&self.root_dir, &config)?;
        self.active_profile = name.to_string();
        self.base_dir = profile_dir;
        Ok(())
    }

    pub fn server_data_dir(&self) -> PathBuf {
        self.root_dir.join("server")
    }

    pub fn config_path(&self) -> PathBuf {
        self.root_dir.join("config.json")
    }

    pub fn credentials_path(&self) -> PathBuf {
        self.base_dir.join("credentials.json")
    }

    pub fn session_path(&self) -> PathBuf {
        self.base_dir.join("session.json")
    }

    pub fn settings_path(&self) -> PathBuf {
        self.base_dir.join("settings.json")
    }

    pub fn has_credentials(&self) -> bool {
        self.credentials_path().exists()
    }

    pub fn read_json<T: DeserializeOwned>(&self, path: &PathBuf) -> Result<T, AppError> {
        let content = fs::read_to_string(path).map_err(|e| {
            AppError::StorageError(format!("Failed to read {}: {e}", path.display()))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            AppError::StorageError(format!("Failed to parse {}: {e}", path.display()))
        })
    }

    pub fn write_json<T: Serialize>(&self, path: &PathBuf, data: &T) -> Result<(), AppError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| AppError::StorageError(format!("Cannot create directory: {e}")))?;
        }

        let content = serde_json::to_string_pretty(data)
            .map_err(|e| AppError::StorageError(format!("Failed to serialize: {e}")))?;

        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, &content)
            .map_err(|e| AppError::StorageError(format!("Failed to write: {e}")))?;

        fs::rename(&tmp_path, path)
            .map_err(|e| AppError::StorageError(format!("Failed to commit write: {e}")))?;

        set_restrictive_permissions(path)?;
        Ok(())
    }

    pub fn delete_file(&self, path: &PathBuf) -> Result<(), AppError> {
        if path.exists() {
            fs::remove_file(path)
                .map_err(|e| AppError::StorageError(format!("Failed to delete: {e}")))?;
        }
        Ok(())
    }
}

fn root_data_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".zid")
}

fn read_profile_config(root_dir: &PathBuf) -> ProfileConfig {
    let config_path = root_dir.join("config.json");
    if config_path.exists() {
        if let Ok(content) = fs::read_to_string(&config_path) {
            if let Ok(config) = serde_json::from_str::<ProfileConfig>(&content) {
                return config;
            }
        }
    }
    ProfileConfig {
        active_profile: DEFAULT_PROFILE.to_string(),
    }
}

fn write_profile_config(root_dir: &PathBuf, config: &ProfileConfig) -> Result<(), AppError> {
    let config_path = root_dir.join("config.json");
    let content = serde_json::to_string_pretty(config)
        .map_err(|e| AppError::StorageError(format!("Failed to serialize config: {e}")))?;
    fs::write(&config_path, &content)
        .map_err(|e| AppError::StorageError(format!("Failed to write config: {e}")))?;
    Ok(())
}

fn validate_profile_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::StorageError(
            "Profile name cannot be empty".into(),
        ));
    }
    if name.len() > MAX_PROFILE_NAME_LEN {
        return Err(AppError::StorageError(format!(
            "Profile name cannot exceed {MAX_PROFILE_NAME_LEN} characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::StorageError(
            "Profile name may only contain alphanumeric characters, hyphens, and underscores"
                .into(),
        ));
    }
    Ok(())
}

/// If `~/.zid/` contains flat credential/session/settings files but no `profiles/` dir,
/// migrate them into `profiles/default/`.
fn migrate_flat_layout(root_dir: &PathBuf) -> Result<(), AppError> {
    let profiles_dir = root_dir.join("profiles");
    if profiles_dir.exists() {
        return Ok(());
    }

    let files_to_migrate = ["credentials.json", "session.json", "settings.json"];
    let has_any = files_to_migrate
        .iter()
        .any(|f| root_dir.join(f).exists());

    if !has_any {
        return Ok(());
    }

    let default_dir = profiles_dir.join(DEFAULT_PROFILE);
    fs::create_dir_all(&default_dir)
        .map_err(|e| AppError::StorageError(format!("Cannot create default profile dir: {e}")))?;

    for filename in &files_to_migrate {
        let src = root_dir.join(filename);
        if src.exists() {
            let dst = default_dir.join(filename);
            fs::rename(&src, &dst).map_err(|e| {
                AppError::StorageError(format!("Failed to migrate {filename}: {e}"))
            })?;
        }
    }

    let config = ProfileConfig {
        active_profile: DEFAULT_PROFILE.to_string(),
    };
    write_profile_config(root_dir, &config)?;

    tracing::info!("Migrated flat layout to profile-based layout");
    Ok(())
}

/// If the old `ProjectDirs` path has data but `~/.zid/profiles/` doesn't,
/// copy it over and migrate.
fn migrate_old_project_dirs(root_dir: &PathBuf) -> Result<(), AppError> {
    let profiles_dir = root_dir.join("profiles");
    let has_profiles = profiles_dir.exists()
        && fs::read_dir(&profiles_dir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);

    if has_profiles {
        return Ok(());
    }

    let old_dir = match directories::ProjectDirs::from("com", "cypher", "zid") {
        Some(p) => p.data_dir().to_path_buf(),
        None => return Ok(()),
    };

    if old_dir == *root_dir || !old_dir.exists() {
        return Ok(());
    }

    let files_to_migrate = ["credentials.json", "session.json", "settings.json"];
    let has_any = files_to_migrate
        .iter()
        .any(|f| old_dir.join(f).exists());

    if !has_any {
        return Ok(());
    }

    let default_dir = profiles_dir.join(DEFAULT_PROFILE);
    fs::create_dir_all(&default_dir)
        .map_err(|e| AppError::StorageError(format!("Cannot create default profile dir: {e}")))?;

    for filename in &files_to_migrate {
        let src = old_dir.join(filename);
        if src.exists() {
            let dst = default_dir.join(filename);
            if !dst.exists() {
                fs::copy(&src, &dst).map_err(|e| {
                    AppError::StorageError(format!(
                        "Failed to copy {filename} from old location: {e}"
                    ))
                })?;
            }
        }
    }

    // Migrate server data too if present
    let old_server = old_dir.join("server");
    let new_server = root_dir.join("server");
    if old_server.exists() && !new_server.exists() {
        copy_dir_recursive(&old_server, &new_server)?;
    }

    let config = ProfileConfig {
        active_profile: DEFAULT_PROFILE.to_string(),
    };
    write_profile_config(root_dir, &config)?;

    tracing::info!(
        "Migrated data from old location ({}) to ~/.zid/",
        old_dir.display()
    );
    Ok(())
}

fn copy_dir_recursive(src: &PathBuf, dst: &PathBuf) -> Result<(), AppError> {
    fs::create_dir_all(dst)
        .map_err(|e| AppError::StorageError(format!("Cannot create directory: {e}")))?;
    let entries = fs::read_dir(src)
        .map_err(|e| AppError::StorageError(format!("Cannot read directory: {e}")))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| AppError::StorageError(format!("Cannot read entry: {e}")))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).map_err(|e| {
                AppError::StorageError(format!("Cannot copy file: {e}"))
            })?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_restrictive_permissions(path: &PathBuf) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)
        .map_err(|e| AppError::StorageError(format!("Failed to set file permissions: {e}")))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_restrictive_permissions(_path: &PathBuf) -> Result<(), AppError> {
    Ok(())
}

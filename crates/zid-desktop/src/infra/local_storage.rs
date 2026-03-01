use std::fs;
use std::path::PathBuf;

use serde::{de::DeserializeOwned, Serialize};

use crate::error::AppError;

pub struct LocalStorage {
    base_dir: PathBuf,
}

impl LocalStorage {
    pub fn new() -> Result<Self, AppError> {
        let base_dir = default_data_dir();
        fs::create_dir_all(&base_dir)
            .map_err(|e| AppError::StorageError(format!("Cannot create data directory: {e}")))?;
        Ok(Self { base_dir })
    }

    pub fn with_dir(base_dir: PathBuf) -> Result<Self, AppError> {
        fs::create_dir_all(&base_dir)
            .map_err(|e| AppError::StorageError(format!("Cannot create data directory: {e}")))?;
        Ok(Self { base_dir })
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
        let content = fs::read_to_string(path)
            .map_err(|e| AppError::StorageError(format!("Failed to read {}: {e}", path.display())))?;
        serde_json::from_str(&content)
            .map_err(|e| AppError::StorageError(format!("Failed to parse {}: {e}", path.display())))
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

fn default_data_dir() -> PathBuf {
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "cypher", "zid") {
        proj_dirs.data_dir().to_path_buf()
    } else {
        dirs_fallback()
    }
}

fn dirs_fallback() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".zid")
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

use crate::error::AppError;

pub fn copy_to_clipboard(text: &str) -> Result<(), AppError> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| AppError::StorageError(format!("Clipboard unavailable: {e}")))?;
    clipboard
        .set_text(text.to_string())
        .map_err(|e| AppError::StorageError(format!("Failed to copy to clipboard: {e}")))?;
    Ok(())
}

pub fn open_browser(url: &str) -> Result<(), AppError> {
    open::that(url)
        .map_err(|e| AppError::StorageError(format!("Failed to open browser: {e}")))?;
    Ok(())
}

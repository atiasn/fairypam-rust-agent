use crate::WindowsError;

pub fn validate_dpi(dpi: u32) -> Result<u32, WindowsError> {
    if (72..=960).contains(&dpi) {
        Ok(dpi)
    } else {
        Err(WindowsError::new(
            "target.dpi_invalid",
            "window DPI is outside the validated range",
        ))
    }
}

pub fn physical_to_logical(value: i32, dpi: u32) -> Result<i32, WindowsError> {
    let dpi = i64::from(validate_dpi(dpi)?);
    let scaled = i64::from(value)
        .checked_mul(96)
        .ok_or_else(|| WindowsError::new("target.dpi_overflow", "DPI conversion overflow"))?;
    i32::try_from(scaled / dpi)
        .map_err(|_| WindowsError::new("target.dpi_overflow", "DPI conversion overflow"))
}

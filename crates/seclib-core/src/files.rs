use std::collections::HashSet;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FileValidationError {
    #[error("Error de validación de archivo: {0}")]
    Generic(String),
}

#[derive(Debug, Error)]
pub enum VirusFoundError {
    #[error("Malware detectado: {0}")]
    MalwareDetected(String),
    #[error("Error de ClamAV: {0}")]
    Generic(String),
}

pub fn sanitize_filename(filename: &str) -> String {
    let path = std::path::Path::new(filename);
    let base = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(filename);

    let mut sanitized = String::new();
    for c in base.chars() {
        if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
            sanitized.push(c);
        } else {
            sanitized.push('_');
        }
    }
    let mut cleaned = sanitized.replace("..", ".");
    while cleaned.contains("..") {
        cleaned = cleaned.replace("..", ".");
    }
    if cleaned.starts_with('.') {
        cleaned = format!("safe_{cleaned}");
    }
    if cleaned.is_empty() {
        cleaned = "unnamed_file".to_string();
    }
    cleaned
}

pub fn save_to_quarantine(
    file_data: &[u8],
    filename: &str,
    quarantine_dir: &str,
) -> Result<String, std::io::Error> {
    std::fs::create_dir_all(quarantine_dir)?;
    let unique_name = format!("{}_{}", uuid::Uuid::new_v4(), sanitize_filename(filename));
    let path = std::path::Path::new(quarantine_dir).join(&unique_name);
    std::fs::write(&path, file_data)?;
    Ok(path.to_string_lossy().to_string())
}

pub fn validate_identity(
    filepath: &str,
    allowed_extensions: &HashSet<String>,
) -> Result<String, FileValidationError> {
    let path = std::path::Path::new(filepath);
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| FileValidationError::Generic("Nombre de archivo inválido".to_string()))?;

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{}", s.to_lowercase()))
        .ok_or_else(|| FileValidationError::Generic("Archivo sin extensión".to_string()))?;

    if !allowed_extensions.contains(&ext) {
        return Err(FileValidationError::Generic(format!(
            "Extensión no permitida: {ext}"
        )));
    }

    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() > 2 {
        for part in &parts[1..parts.len() - 1] {
            let p_lower = part.to_lowercase();
            match p_lower.as_str() {
                "exe" | "bat" | "cmd" | "sh" | "js" | "vbs" | "scr" | "pif" | "msi" => {
                    return Err(FileValidationError::Generic(
                        "Doble extensión con sufijo ejecutable detectada".to_string(),
                    ));
                }
                _ => {}
            }
        }
    }

    let mime_type = match infer::get_from_path(filepath) {
        Ok(Some(kind)) => kind.mime_type().to_string(),
        _ => {
            let mut file = std::fs::File::open(filepath)
                .map_err(|e| FileValidationError::Generic(e.to_string()))?;
            use std::io::Read;
            let mut head = [0u8; 1024];
            let bytes_read = file
                .read(&mut head)
                .map_err(|e| FileValidationError::Generic(format!("Error de lectura: {e}")))?;
            let head_bytes = &head[..bytes_read];

            if head_bytes.starts_with(b"%PDF-") {
                "application/pdf".to_string()
            } else if head_bytes.starts_with(b"PK\x03\x04") {
                "application/zip".to_string()
            } else if head_bytes.starts_with(b"\xef\xbb\xbf")
                || head_bytes.iter().all(|&b| {
                    b.is_ascii_alphanumeric() || b.is_ascii_punctuation() || b.is_ascii_whitespace()
                })
            {
                let decoded = String::from_utf8_lossy(head_bytes);
                if decoded.contains(',') || decoded.contains(';') || decoded.contains('\t') {
                    "text/csv".to_string()
                } else {
                    "text/plain".to_string()
                }
            } else {
                "application/octet-stream".to_string()
            }
        }
    };

    if ext == ".pdf" && mime_type != "application/pdf" {
        return Err(FileValidationError::Generic(format!(
            "Extensión .pdf pero contenido detectado es {mime_type}"
        )));
    }
    if ext == ".xlsx"
        && mime_type != "application/zip"
        && mime_type != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    {
        return Err(FileValidationError::Generic(format!(
            "Extensión .xlsx pero contenido detectado es {mime_type}"
        )));
    }
    if ext == ".csv" {
        if !mime_type.contains("csv") && !mime_type.contains("text") {
            return Err(FileValidationError::Generic(format!(
                "Extensión .csv pero contenido detectado es {mime_type}"
            )));
        }
        let mut file = std::fs::File::open(filepath)
            .map_err(|e| FileValidationError::Generic(e.to_string()))?;
        use std::io::Read;
        let mut head = [0u8; 1024];
        let bytes_read = file
            .read(&mut head)
            .map_err(|e| FileValidationError::Generic(format!("Error de lectura: {e}")))?;
        let decoded = String::from_utf8_lossy(&head[..bytes_read]);
        if !decoded.contains(',') && !decoded.contains(';') && !decoded.contains('\t') {
            return Err(FileValidationError::Generic(
                "Extensión .csv pero sin estructura de CSV".to_string(),
            ));
        }
    }

    Ok(mime_type)
}

pub fn check_zip_bomb(filepath: &str) -> Result<(), FileValidationError> {
    let file = std::fs::File::open(filepath)
        .map_err(|e| FileValidationError::Generic(format!("Fallo al abrir ZIP: {e}")))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| FileValidationError::Generic(format!("ZIP inválido: {e}")))?;

    let mut total_uncompressed_size: u64 = 0;
    let mut total_entries = 0;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| FileValidationError::Generic(format!("Error en entrada ZIP: {e}")))?;

        total_entries += 1;
        if total_entries > 1000 {
            return Err(FileValidationError::Generic(
                "El archivo ZIP contiene demasiadas entradas (>1000)".to_string(),
            ));
        }

        let name = entry.name();
        if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
            return Err(FileValidationError::Generic(format!(
                "Path traversal detectado en entrada ZIP: {name}"
            )));
        }

        if entry.is_file() {
            use std::io::Read;
            let remaining_limit =
                (200 * 1024 * 1024 + 1_u64).saturating_sub(total_uncompressed_size);
            let mut limited_reader = (&mut entry).take(remaining_limit);
            let written =
                std::io::copy(&mut limited_reader, &mut std::io::sink()).map_err(|e| {
                    FileValidationError::Generic(format!("Error al leer entrada ZIP: {e}"))
                })?;
            total_uncompressed_size += written;

            if total_uncompressed_size > 200 * 1024 * 1024 {
                return Err(FileValidationError::Generic(
                    "El tamaño descomprimido supera el límite de 200MB".to_string(),
                ));
            }
        }
    }

    let compressed_size = std::fs::metadata(filepath).map(|m| m.len()).unwrap_or(0);

    if compressed_size > 0 {
        let ratio = total_uncompressed_size as f64 / compressed_size as f64;
        if ratio > 100.0 {
            return Err(FileValidationError::Generic(format!(
                "Alta tasa de compresión detectada: {ratio:.1}:1 (potencial bomba ZIP)"
            )));
        }
    }

    Ok(())
}

pub fn scan_antivirus(filepath: &str, host: &str, port: u16) -> Result<bool, VirusFoundError> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(format!("{host}:{port}"))
        .map_err(|e| VirusFoundError::Generic(format!("Fallo de conexión a ClamAV: {e}")))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| VirusFoundError::Generic(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| VirusFoundError::Generic(e.to_string()))?;

    stream
        .write_all(b"zINSTREAM\0")
        .map_err(|e| VirusFoundError::Generic(e.to_string()))?;

    let mut file =
        std::fs::File::open(filepath).map_err(|e| VirusFoundError::Generic(e.to_string()))?;
    let mut chunk = [0u8; 4096];

    loop {
        let n = file
            .read(&mut chunk)
            .map_err(|e| VirusFoundError::Generic(e.to_string()))?;
        if n == 0 {
            break;
        }
        stream
            .write_all(&(n as u32).to_be_bytes())
            .map_err(|e| VirusFoundError::Generic(e.to_string()))?;
        stream
            .write_all(&chunk[..n])
            .map_err(|e| VirusFoundError::Generic(e.to_string()))?;
    }

    stream
        .write_all(&0u32.to_be_bytes())
        .map_err(|e| VirusFoundError::Generic(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| VirusFoundError::Generic(e.to_string()))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| VirusFoundError::Generic(e.to_string()))?;

    let response_str = String::from_utf8_lossy(&response);

    if response_str.contains("FOUND") {
        Err(VirusFoundError::MalwareDetected(format!(
            "MALWARE DETECTADO: Respuesta de ClamAV: {response_str}"
        )))
    } else if response_str.contains("OK") {
        Ok(true)
    } else {
        Err(VirusFoundError::Generic(format!(
            "ClamAV retornó salida inesperada: {response_str}"
        )))
    }
}

pub fn sanitize_csv_cell(value: &str) -> String {
    match value.chars().next() {
        Some('=') | Some('+') | Some('-') | Some('@') | Some('\t') | Some('\r') | Some('\n') => {
            format!("'{value}")
        }
        _ => value.to_string(),
    }
}

pub fn process_xlsx(
    filepath: &str,
    max_cells: usize,
) -> Result<Vec<Vec<String>>, FileValidationError> {
    let path = std::path::Path::new(filepath);
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{}", s.to_lowercase()))
        .ok_or_else(|| FileValidationError::Generic("Archivo sin extensión".to_string()))?;

    if ext == ".xlsm" || ext == ".xlsb" || ext == ".xls" {
        return Err(FileValidationError::Generic(
            "Formatos con macros o antiguos están prohibidos".to_string(),
        ));
    }

    check_zip_bomb(filepath)?;

    use calamine::{open_workbook, Reader, Xlsx};
    let mut workbook: Xlsx<_> = open_workbook(filepath)
        .map_err(|e| FileValidationError::Generic(format!("Error al abrir XLSX: {e}")))?;

    let sheet_names = workbook.sheet_names().to_vec();
    if sheet_names.is_empty() {
        return Err(FileValidationError::Generic(
            "El libro no tiene hojas".to_string(),
        ));
    }

    let mut total_cells = 0;
    for name in &sheet_names {
        if let Ok(range) = workbook.worksheet_range(name) {
            total_cells += range.width() * range.height();
            if total_cells > max_cells {
                return Err(FileValidationError::Generic(format!(
                    "El libro supera el límite total de celdas {max_cells}"
                )));
            }
        }
    }

    let sheet_name = sheet_names
        .first()
        .ok_or_else(|| FileValidationError::Generic("El libro no tiene hojas".to_string()))?
        .clone();
    let range = workbook.worksheet_range(&sheet_name).map_err(|e| {
        FileValidationError::Generic(format!(
            "No se pudo obtener el rango de la primera hoja: {e}"
        ))
    })?;

    let mut rows = Vec::new();
    let mut cell_count = 0;

    for row in range.rows() {
        let mut row_data = Vec::new();
        for cell in row {
            cell_count += 1;
            if cell_count > max_cells {
                return Err(FileValidationError::Generic(format!(
                    "La hoja supera el límite de celdas {max_cells}"
                )));
            }
            row_data.push(cell.to_string());
        }
        rows.push(row_data);
    }

    Ok(rows)
}

pub fn process_pdf(filepath: &str, max_pages: u32) -> Result<String, FileValidationError> {
    use lopdf::Document;

    let doc = Document::load(filepath)
        .map_err(|e| FileValidationError::Generic(format!("PDF inválido: {e}")))?;

    let pages_count = doc.get_pages().len() as u32;
    if pages_count > max_pages {
        return Err(FileValidationError::Generic(format!(
            "El PDF supera el límite de páginas de {max_pages}"
        )));
    }

    if doc.is_encrypted() {
        return Err(FileValidationError::Generic(
            "PDFs cifrados no están soportados".to_string(),
        ));
    }

    if let Ok(catalog) = doc.catalog() {
        if let Ok(names) = catalog.get(b"Names") {
            let names_obj = match names {
                lopdf::Object::Reference(id) => doc.get_object(*id).unwrap_or(names),
                _ => names,
            };
            if let Ok(names_dict) = names_obj.as_dict() {
                if names_dict.has(b"JavaScript") {
                    return Err(FileValidationError::Generic(
                        "El PDF contiene un árbol de Names.JavaScript prohibido".to_string(),
                    ));
                }
                if names_dict.has(b"EmbeddedFiles") {
                    return Err(FileValidationError::Generic(
                        "El PDF contiene un árbol de Names.EmbeddedFiles prohibido".to_string(),
                    ));
                }
            }
        }

        if catalog.has(b"JS") || catalog.has(b"JavaScript") {
            return Err(FileValidationError::Generic(
                "El PDF contiene JavaScript embebido prohibido en el Catalog".to_string(),
            ));
        }

        if catalog.has(b"AA") {
            return Err(FileValidationError::Generic(
                "El PDF contiene Additional Actions (AA) prohibidas en el Catalog".to_string(),
            ));
        }

        if let Ok(open_action) = catalog.get(b"OpenAction") {
            let open_action_obj = match open_action {
                lopdf::Object::Reference(id) => doc.get_object(*id).unwrap_or(open_action),
                _ => open_action,
            };
            if let Ok(action_dict) = open_action_obj.as_dict() {
                if let Ok(s) = action_dict.get(b"S") {
                    if let Ok(s_name) = s.as_name() {
                        let s_str = String::from_utf8_lossy(s_name);
                        if s_str == "JavaScript" || s_str == "Launch" {
                            return Err(FileValidationError::Generic(format!(
                                "El PDF contiene OpenAction prohibida: {s_str}"
                            )));
                        }
                    }
                }
            }
        }
    }

    for (page_num, &page_id) in doc.get_pages().iter() {
        if let Ok(page_dict) = doc.get_object(page_id).and_then(|o| o.as_dict()) {
            if page_dict.has(b"AA") {
                return Err(FileValidationError::Generic(format!(
                    "El PDF contiene Additional Actions (AA) en la página {page_num}"
                )));
            }

            if let Ok(annots) = page_dict.get(b"Annots") {
                if let Ok(annots_arr) = annots.as_array() {
                    for annot_ref in annots_arr {
                        let annot_obj = match annot_ref.as_reference() {
                            Ok(id) => doc.get_object(id).and_then(|o| o.as_dict()),
                            _ => annot_ref.as_dict(),
                        };
                        if let Ok(annot_dict) = annot_obj {
                            if annot_dict.has(b"AA") {
                                return Err(FileValidationError::Generic(format!(
                                    "El PDF contiene Additional Actions (AA) de anotación en la página {page_num}"
                                )));
                            }
                            if let Ok(action) = annot_dict.get(b"A") {
                                if let Ok(action_dict) = action.as_dict() {
                                    if let Ok(s) = action_dict.get(b"S") {
                                        if let Ok(s_name) = s.as_name() {
                                            let s_str = String::from_utf8_lossy(s_name);
                                            if s_str == "JavaScript" || s_str == "Launch" {
                                                return Err(FileValidationError::Generic(format!(
                                                    "El PDF contiene acción JavaScript/Launch en anotación de la página {page_num}"
                                                )));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut text_content = String::new();
    for &page_num in doc.get_pages().keys() {
        if let Ok(text) = doc.extract_text(&[page_num]) {
            text_content.push_str(&text);
            text_content.push('\n');
        }
    }

    Ok(text_content)
}

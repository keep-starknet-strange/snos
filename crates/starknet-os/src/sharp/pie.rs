use std::fs::File;
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose;
use base64::Engine as _;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use zip::write::FileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::error::SnOsError;

pub const PIE_FILES: [&str; 5] = ["metadata", "memory", "additional_data", "execution_resources", "version"];

/// Writes [CairoPie] to zip file and returns the encoded base64 of the pie.
pub fn encode_pie(pie: CairoPie, dst: &Path) -> Result<String, SnOsError> {
    let output = File::create(dst).map_err(|e| SnOsError::PieZipping(format!("{e}")))?;
    let zip = zip::ZipWriter::new(output);

    write_to_zip(pie, zip)?;

    let mut pie_zip = File::open(dst).map_err(|e| SnOsError::PieEncoding(format!("{e}")))?;
    let mut buffer = Vec::new();

    // Read file into vector.
    pie_zip.read_to_end(&mut buffer).map_err(|e| SnOsError::PieEncoding(format!("{e}")))?;

    Ok(general_purpose::STANDARD.encode(buffer))
}

pub fn encode_pie_mem(pie: CairoPie) -> Result<String, SnOsError> {
    let mut data = Vec::new();

    {
        let buf = Cursor::new(&mut data);
        let zip = zip::ZipWriter::new(buf);

        write_to_zip(pie, zip)?;
    }

    Ok(general_purpose::STANDARD.encode(data))
}

/// Write [CairoPie] to a zip Writer (either a file or a rust object).
fn write_to_zip<W: Write + Seek>(pie: CairoPie, mut zip: ZipWriter<W>) -> Result<(), SnOsError> {
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated).unix_permissions(0o755);

    let pie_s = serde_json::to_value(pie).map_err(|e| SnOsError::PieZipping(format!("{e}")))?;

    for file in PIE_FILES {
        if file == "memory" {
            let pie_mem_bytes = hex::decode(pie_s[file].to_string().trim_matches('"'))
                .map_err(|e| SnOsError::PieZipping(format!("{e}")))?;

            zip.start_file(&format!("{file}.bin"), options).map_err(|e| SnOsError::PieZipping(format!("{e}")))?;
            zip.write_all(&pie_mem_bytes).map_err(|e| SnOsError::PieZipping(format!("{e}")))?;
        } else {
            zip.start_file(&format!("{file}.json"), options).map_err(|e| SnOsError::PieZipping(format!("{e}")))?;
            zip.write_all(pie_s[file].to_string().as_bytes()).map_err(|e| SnOsError::PieZipping(format!("{e}")))?;
        };
    }

    zip.finish().map_err(|e| SnOsError::PieZipping(format!("{e}")))?;

    Ok(())
}

/// Convert the base64 encoding of the pie to an unzipped folder.
pub fn decode_base64_to_unzipped(pie_str: &str, dst: &str) -> Result<(), SnOsError> {
    let buffer =
        general_purpose::STANDARD.decode(pie_str.as_bytes()).map_err(|e| SnOsError::PieZipping(format!("{e}")))?;
    ZipArchive::new(Cursor::new(&buffer))
        .unwrap()
        .extract(&PathBuf::from(dst))
        .map_err(|e| SnOsError::PieZipping(format!("{e}")))?;
    Ok(())
}

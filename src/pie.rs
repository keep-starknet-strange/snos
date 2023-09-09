use cairo_vm::types::relocatable::MaybeRelocatable;
use num_bigint::BigUint;
use num_traits::Num;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use zip::write::FileOptions;

use cairo_vm::vm::runners::cairo_pie::CairoPieMemory;

const _CAIRO_PIE_VERSION: &str = "1.1";

const ADDR_BYTE_LEN: usize = 8;
const FIELD_BYTE_LEN: usize = 32;
const _SEGMENT_BIT_LEN: usize = 16;
const _OFFSET_BIT_LEN: usize = 47;
const ADDR_BASE: usize = 0x8000000000000000; // 2 ** (8 * ADDR_BYTE_LEN - 1)
const OFFSET_BASE: usize = 0x800000000000; // 2 ** OFFSET_BIT_LEN
const RELOCATE_BASE: &str = "8000000000000000000000000000000000000000000000000000000000000000"; // 2 ** (8 * FIELD_BYTE_LEN - 1)

const PIE_FILES: [&'static str; 5] = [
    "metadata.json",
    "memory.bin",
    "additional_data.json",
    "execution_resources.json",
    "version.json",
];

// Memory address in Cairo is represented like this: <segment>:<offset>
// <segment> is the segment number deterimined by runner
// <offset> is the position of the address relative to the segment
// "relocatable": on program run these memory cells will be relocated so that the memory ends up continuous.
// field bytes = 32

// Serializes RelocatableValue as:
// 1bit |   SEGMENT_BITS |   OFFSET_BITS
// 1    |     segment    |   offset
// Serializes int as
// 1bit | num
// 0    | num

pub fn serialize_memory(memory: CairoPieMemory, relocated_mem: crate::RelocatedMemory) -> Vec<u8> {
    let mem_cap = memory.len() * ADDR_BYTE_LEN + memory.len() * FIELD_BYTE_LEN;
    let mut res = Vec::with_capacity(mem_cap);

    // TODO: safety checks
    for (i, ((segment, offset), value)) in memory.iter().enumerate() {
        match value {
            MaybeRelocatable::RelocatableValue(rel_val) => {
                let mem_addr = ADDR_BASE + *segment * OFFSET_BASE + *offset;

                let reloc_base = BigUint::from_str_radix(RELOCATE_BASE, 16).unwrap();
                let reloc_value = reloc_base
                    + BigUint::from(rel_val.segment_index as usize) * BigUint::from(OFFSET_BASE)
                    + BigUint::from(rel_val.offset);
                res.extend_from_slice(mem_addr.to_le_bytes().as_ref());
                res.extend_from_slice(reloc_value.to_bytes_le().as_ref());
                println!(
                    "{}: {:?}:{:?} {:?}:{:?} {:?} {:?}",
                    i + 1,
                    segment,
                    offset,
                    rel_val.segment_index,
                    rel_val.offset,
                    relocated_mem[i + 1],
                    reloc_value.to_bytes_le()
                );
            }
            MaybeRelocatable::Int(data_val) => {
                let mem_addr = ADDR_BASE + *segment * OFFSET_BASE + *offset;
                res.extend_from_slice(mem_addr.to_le_bytes().as_ref());
                res.extend_from_slice(data_val.to_le_bytes().as_ref());
                println!(
                    "{}: {:?}:{:?} {} {:?}",
                    i + 1,
                    segment,
                    offset,
                    data_val,
                    data_val.to_le_bytes()
                );
            }
        };
    }
    println!("Mem Len: {}/{}", res.len(), res.capacity());

    res
}

pub fn zip_pie(path: &str) {
    let mut pie_dir = PathBuf::from(path.clone());
    let pie_zip = PathBuf::from(path).join("testy.zip");

    let file = File::create(pie_zip).unwrap();

    let mut zip = zip::ZipWriter::new(file);

    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    let mut buffer = Vec::new();
    for file in PIE_FILES {
        pie_dir.push(file);
        if !pie_dir.exists() {
            println!("PATH DOES NOT EXIST: ");
        }
        let _ = zip.start_file(file, options);
        let mut f = File::open(pie_dir.clone()).unwrap();
        f.read_to_end(&mut buffer).unwrap();
        zip.write_all(&buffer).unwrap();
        buffer.clear();
        pie_dir.pop();
    }

    zip.finish().unwrap();
}

// "add_job", {"cairo_pie": base64.b64encode(cairo_pie.serialize()).decode("ascii")}
pub fn encode_pie() {}

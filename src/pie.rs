use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use zip::write::FileOptions;

use cairo_vm::vm::runners::cairo_pie::CairoPieMemory;

const CAIRO_PIE_VERSION: &str = "1.1";
const FIELD_BYTES: u8 = 32;

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

pub fn serialize_memory(memory: CairoPieMemory) -> Vec<u8> {
    let res = Vec::new();
    for ((addr, val), rel) in memory.iter() {
        println!("Addr: {:?}:{:?}", addr, val);
        println!("Rel: {:?}", rel);
    }

    res
}

// def to_file(self, file, merge_extra_segments: bool = False):
// extra_segments, segment_offsets = (
//     self.merge_extra_segments()
//     if merge_extra_segments and len(self.metadata.extra_segments) > 0
//     else (None, None)
// )
// metadata = self.metadata
// if extra_segments is not None:
//     metadata = dataclasses.replace(metadata, extra_segments=extra_segments)
// with zipfile.ZipFile(file, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
//     with zf.open(self.METADATA_FILENAME, "w") as fp:
//         fp.write(json.dumps(CairoPieMetadata.Schema().dump(metadata)).encode("ascii"))
//     with zf.open(self.MEMORY_FILENAME, "w") as fp:
//         fp.write(
//             self.memory.serialize(
//                 field_bytes=self.metadata.field_bytes,
//                 relocate_value=self.get_relocate_value_func(
//                     segment_offsets=segment_offsets
//                 ),
//             )
//         )
//     with zf.open(self.ADDITIONAL_DATA_FILENAME, "w") as fp:
//         fp.write(json.dumps(self.additional_data).encode("ascii"))
//     with zf.open(self.EXECUTION_RESOURCES_FILENAME, "w") as fp:
//         fp.write(
//             json.dumps(ExecutionResources.Schema().dump(self.execution_resources)).encode(
//                 "ascii"
//             )
//         )
//     with zf.open(self.VERSION_FILENAME, "w") as fp:
//         fp.write(json.dumps(self.version).encode("ascii"))
pub fn zip_pie(path: &str) {
    let mut pie_dir = PathBuf::from(path.clone());
    let pie_zip = PathBuf::from(path).join("testy.zip");
    print!("OUT: {:?}", pie_dir);

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

// MISC
// """
// Submits a job to the SHARP, and returns a job identifier.
// Asserts that the number of execution steps does not exceed the allowed limit.
// """
// n_steps = cairo_pie.execution_resources.n_steps
// assert n_steps < self.steps_limit, (
//     f"Execution trace length exceeds limit. The execution length is {n_steps} "
//     f"and the limit is {self.steps_limit}."
// )

// memory serialize
// def serialize(self, field_bytes, relocate_value: Optional[RelocateValueFunc] = None):
// assert (
//     len(self.relocation_rules) == 0
// ), "Cannot serialize a MemoryDict with active segment relocation rules."

// if relocate_value is None:
//     relocate_value = lambda val: val

// return b"".join(
//     RelocatableValue.to_bytes(relocate_value(addr), ADDR_SIZE_IN_BYTES, "little")
//     + RelocatableValue.to_bytes(relocate_value(value), field_bytes, "little")
//     for addr, value in self.items()
// )

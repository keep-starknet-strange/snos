use anyhow::{Context, Error, Result};
use starknet_api::core::ClassHash;
use from_pathfinder::{HashChain, PoseidonHasher};
use sha3::Digest;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use super::pathfinder_felts::{Felt, MontFelt};

#[derive(Debug, PartialEq)]
pub enum ComputedClassHash {
    Cairo(ClassHash),
    Sierra(ClassHash),
}

impl ComputedClassHash {
    pub fn hash(&self) -> ClassHash {
        match self {
            ComputedClassHash::Cairo(h) => *h,
            ComputedClassHash::Sierra(h) => *h,
        }
    }
}

mod from_pathfinder {

    use super::*;

    type EntryPoint = Felt;
    type ByteCodeOffset = Felt;

    /// Computes the starknet class hash for given class definition JSON blob.
    ///
    /// This function first parses the JSON blob to decide if it's a Cairo or Sierra
    /// class definition and then calls the appropriate function to compute the
    /// class hash with the parsed definition.
    pub fn compute_class_hash(contract_definition_dump: &[u8]) -> Result<ComputedClassHash> {
        let contract_definition = parse_contract_definition(contract_definition_dump)
            .context("Failed to parse contract definition")?;

        match contract_definition {
            json::ContractDefinition::Sierra(definition) => compute_sierra_class_hash(definition)
                .map(ComputedClassHash::Sierra)
                .context("Compute class hash"),
            json::ContractDefinition::Cairo(definition) => compute_cairo_class_hash(definition)
                .map(ComputedClassHash::Cairo)
                .context("Compute class hash"),
        }
    }

    /// Parse either a Sierra or a Cairo contract definition.
    ///
    /// Due to an issue in serde_json we can't use an untagged enum and simply
    /// derive a Deserialize implementation: <https://github.com/serde-rs/json/issues/559>
    fn parse_contract_definition(
        contract_definition_dump: &[u8],
    ) -> serde_json::Result<json::ContractDefinition<'_>> {
        serde_json::from_slice::<json::SierraContractDefinition<'_>>(contract_definition_dump)
            .map(json::ContractDefinition::Sierra)
            .or_else(|_| {
                serde_json::from_slice::<json::CairoContractDefinition<'_>>(contract_definition_dump)
                    .map(json::ContractDefinition::Cairo)
            })
    }

    /// Sibling functionality to only [`compute_class_hash`], returning also the
    /// ABI, and bytecode parts as json bytes.
    ///
    /// NOTE: This function is deprecated. We no longer store ABI and bytecode in
    /// the database, and this function is only used by _old_ database migration
    /// steps.
    pub fn extract_abi_code_hash(
        contract_definition_dump: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, ClassHash)> {
        let contract_definition = parse_contract_definition(contract_definition_dump)
            .context("Failed to parse contract definition")?;

        match contract_definition {
            json::ContractDefinition::Sierra(contract_definition) => {
                let abi = serde_json::to_vec(&contract_definition.abi)
                    .context("Serialize contract_definition.abi")?;
                let code = serde_json::to_vec(&contract_definition.sierra_program)
                    .context("Serialize contract_definition.sierra_program")?;

                let hash =
                    compute_sierra_class_hash(contract_definition).context("Compute class hash")?;

                Ok((abi, code, hash))
            }
            json::ContractDefinition::Cairo(contract_definition) => {
                // just in case we'd accidentally modify these in the compute_class_hash0
                let abi = serde_json::to_vec(&contract_definition.abi)
                    .context("Serialize contract_definition.abi")?;
                let code = serde_json::to_vec(&contract_definition.program.data)
                    .context("Serialize contract_definition.program.data")?;

                let hash =
                    compute_cairo_class_hash(contract_definition).context("Compute class hash")?;

                Ok((abi, code, hash))
            }
        }
    }

    pub mod from_parts {
        use std::collections::HashMap;

        use anyhow::Result;
        use super::*;

        use super::json;

        pub fn compute_cairo_class_hash(
            abi: &[u8],
            program: &[u8],
            external_entry_points: Vec<SelectorAndOffset>,
            l1_handler_entry_points: Vec<SelectorAndOffset>,
            constructor_entry_points: Vec<SelectorAndOffset>,
        ) -> Result<ClassHash> {
            let mut entry_points_by_type = HashMap::new();
            entry_points_by_type.insert(EntryPointType::External, external_entry_points);
            entry_points_by_type.insert(EntryPointType::L1Handler, l1_handler_entry_points);
            entry_points_by_type.insert(EntryPointType::Constructor, constructor_entry_points);

            let contract_definition = json::CairoContractDefinition {
                abi: serde_json::from_slice(abi)?,
                program: serde_json::from_slice(program)?,
                entry_points_by_type,
            };

            super::compute_cairo_class_hash(contract_definition)
        }

        pub fn compute_sierra_class_hash(
            abi: &str,
            sierra_program: Vec<Felt>,
            contract_class_version: &str,
            entry_points: SierraEntryPoints,
        ) -> Result<ClassHash> {
            let mut entry_points_by_type = HashMap::new();
            entry_points_by_type.insert(EntryPointType::External, entry_points.external);
            entry_points_by_type.insert(EntryPointType::L1Handler, entry_points.l1_handler);
            entry_points_by_type.insert(EntryPointType::Constructor, entry_points.constructor);

            let contract_definition = json::SierraContractDefinition {
                abi: abi.into(),
                sierra_program,
                contract_class_version: contract_class_version.into(),
                entry_points_by_type,
            };

            super::compute_sierra_class_hash(contract_definition)
        }
    }

    /// Computes the class hash for given Cairo class definition.
    ///
    /// The structure of the blob is not strictly defined, so it lives in privacy
    /// under `json` module of this module. The class hash has [official
    /// documentation][starknet-doc] and [cairo-lang
    /// has an implementation][cairo-compute] which is half-python and
    /// half-[cairo][cairo-contract].
    ///
    /// Outline of the hashing is:
    ///
    /// 1. class definition is serialized with python's [`sort_keys=True`
    ///    option][py-sortkeys], then a truncated Keccak256 hash is calculated of
    ///    the serialized json
    /// 2. a [hash chain][`HashChain`] construction is used to process in order the
    ///    contract entry points, builtins, the truncated keccak hash and bytecodes
    /// 3. each of the hashchains is hash chained together to produce a final class
    ///    hash
    ///
    /// Hash chain construction is explained at the [official
    /// documentation][starknet-doc], but it's text explanations are much more
    /// complex than the actual implementation in `HashChain`.
    ///
    /// [starknet-doc]: https://docs.starknet.io/documentation/architecture_and_concepts/Contracts/class-hash/
    /// [cairo-compute]: https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/core/os/contract_hash.py
    /// [cairo-contract]: https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/core/os/contracts.cairo#L76-L118
    /// [py-sortkeys]: https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/core/os/contract_hash.py#L58-L71
    fn compute_cairo_class_hash(
        mut contract_definition: json::CairoContractDefinition<'_>,
    ) -> Result<ClassHash> {
        use EntryPointType::*;

        // the other modification is handled by skipping if the attributes vec is empty
        contract_definition.program.debug_info = None;

        // Cairo 0.8 added "accessible_scopes" and "flow_tracking_data" attribute
        // fields, which were not present in older contracts. They present as null /
        // empty for older contracts and should not be included in the hash
        // calculation in these cases.
        //
        // We therefore check and remove them from the definition before calculating the
        // hash.
        contract_definition
            .program
            .attributes
            .iter_mut()
            .try_for_each(|attr| -> anyhow::Result<()> {
                let vals = attr
                    .as_object_mut()
                    .context("Program attribute was not an object")?;

                match vals.get_mut("accessible_scopes") {
                    Some(serde_json::Value::Array(array)) => {
                        if array.is_empty() {
                            vals.remove("accessible_scopes");
                        }
                    }
                    Some(_other) => {
                        anyhow::bail!(
                            r#"A program's attribute["accessible_scopes"] was not an array type."#
                        );
                    }
                    None => {}
                }
                // We don't know what this type is supposed to be, but if its missing it is
                // null.
                if let Some(serde_json::Value::Null) = vals.get_mut("flow_tracking_data") {
                    vals.remove("flow_tracking_data");
                }

                Ok(())
            })?;

        fn add_extra_space_to_cairo_named_tuples(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Array(v) => walk_array(v),
                serde_json::Value::Object(m) => walk_map(m),
                _ => {}
            }
        }

        fn walk_array(array: &mut [serde_json::Value]) {
            for v in array.iter_mut() {
                add_extra_space_to_cairo_named_tuples(v);
            }
        }

        fn walk_map(object: &mut serde_json::Map<String, serde_json::Value>) {
            for (k, v) in object.iter_mut() {
                match v {
                    serde_json::Value::String(s) => {
                        let new_value = add_extra_space_to_named_tuple_type_definition(k, s);
                        if new_value.as_ref() != s {
                            *v = serde_json::Value::String(new_value.into());
                        }
                    }
                    _ => add_extra_space_to_cairo_named_tuples(v),
                }
            }
        }

        fn add_extra_space_to_named_tuple_type_definition<'a>(
            key: &str,
            value: &'a str,
        ) -> std::borrow::Cow<'a, str> {
            use std::borrow::Cow::*;
            match key {
                "cairo_type" | "value" => Owned(add_extra_space_before_colon(value)),
                _ => Borrowed(value),
            }
        }

        fn add_extra_space_before_colon(v: &str) -> String {
            // This is required because if we receive an already correct ` : `, we will
            // still "repair" it to `  : ` which we then fix at the end.
            v.replace(": ", " : ").replace("  :", " :")
        }

        // Handle a backwards compatibility hack which is required if compiler_version
        // is not present. See `insert_space` for more details.
        if contract_definition.program.compiler_version.is_none() {
            add_extra_space_to_cairo_named_tuples(&mut contract_definition.program.identifiers);
            add_extra_space_to_cairo_named_tuples(&mut contract_definition.program.reference_manager);
        }

        let truncated_keccak = {
            use std::io::Write;

            // It's less efficient than tweaking the formatter to emit the encoding but I
            // don't know how and this is an emergency issue (mainnt nodes stuck).
            let mut string_buffer = vec![];

            let mut ser =
                serde_json::Serializer::with_formatter(&mut string_buffer, PythonDefaultFormatter);
            contract_definition
                .serialize(&mut ser)
                .context("Serializing contract_definition for Keccak256")?;

            let raw_json_output = unsafe {
                // We never emit invalid UTF-8.
                String::from_utf8_unchecked(string_buffer)
            };

            let mut keccak_writer = KeccakWriter::default();
            keccak_writer
                .write_all(raw_json_output.as_bytes())
                .expect("writing to KeccakWriter never fails");

            let KeccakWriter(hash) = keccak_writer;
            truncated_keccak(<[u8; 32]>::from(hash.finalize()))
        };

        // what follows is defined over at the contract.cairo

        const API_VERSION: Felt = Felt::ZERO;

        let mut outer = HashChain::default();

        // This wasn't in the docs, but similarly to contract_state hash, we start with
        // this 0, so this will yield outer == H(0, 0); However, dissimilarly to
        // contract_state hash, we do include the number of items in this
        // class_hash.
        outer.update(API_VERSION);

        // It is important to process the different entrypoint hashchains in correct
        // order. Each of the entrypoint lists gets updated into the `outer`
        // hashchain.
        //
        // This implementation doesn't preparse the strings, which makes it a bit more
        // noisy. Late parsing is made in an attempt to lean on the one big string
        // allocation we've already got, but these three hash chains could be
        // constructed at deserialization time.
        [External, L1Handler, Constructor]
            .iter()
            .map(|key| {
                contract_definition
                    .entry_points_by_type
                    .get(key)
                    .unwrap_or(&Vec::new())
                    .iter()
                    // flatten each entry point to get a list of (selector, offset, selector, offset,
                    // ...)
                    .flat_map(|x| [x.selector.0, x.offset.0].into_iter())
                    .fold(HashChain::default(), |mut hc, next| {
                        hc.update(next);
                        hc
                    })
            })
            .for_each(|x| outer.update(x.finalize()));

        fn update_hash_chain(mut hc: HashChain, next: Result<Felt, Error>) -> Result<HashChain, Error> {
            hc.update(next?);
            Result::<_, Error>::Ok(hc)
        }

        let builtins = contract_definition
            .program
            .builtins
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.as_bytes()))
            .map(|(i, s)| {
                Felt::from_be_slice(s).with_context(|| format!("Invalid builtin at index {i}"))
            })
            .try_fold(HashChain::default(), update_hash_chain)
            .context("Failed to process contract_definition.program.builtins")?;

        outer.update(builtins.finalize());

        outer.update(truncated_keccak);

        let bytecodes = contract_definition
            .program
            .data
            .iter()
            .enumerate()
            .map(|(i, s)| {
                Felt::from_hex_str(s).with_context(|| format!("Invalid bytecode at index {i}"))
            })
            .try_fold(HashChain::default(), update_hash_chain)
            .context("Failed to process contract_definition.program.data")?;

        outer.update(bytecodes.finalize());

        Ok(ClassHash(outer.finalize()))
    }

    /// Computes the class hash for a Sierra class definition.
    ///
    /// This matches the (not very precise) [official documentation][starknet-doc]
    /// and the [cairo-lang implementation][cairo-compute] written in Cairo.
    ///
    /// Calculation is somewhat simpler than for Cairo classes, since it does _not_
    /// involve serializing JSON and calculating hashes for the JSON output.
    /// Instead, ABI is handled as a string and all other relevant parts of the
    /// class definition are transformed into Felts and hashed using Poseidon.
    ///
    /// [starknet-doc]: https://docs.starknet.io/documentation/architecture_and_concepts/Contracts/class-hash/
    /// [cairo-compute]: https://github.com/starkware-libs/cairo-lang/blob/12ca9e91bbdc8a423c63280949c7e34382792067/src/starkware/starknet/core/os/contract_class/contract_class.cairo#L42
    fn compute_sierra_class_hash(
        contract_definition: json::SierraContractDefinition<'_>,
    ) -> Result<ClassHash> {
        use EntryPointType::*;

        if contract_definition.contract_class_version != "0.1.0" {
            anyhow::bail!("Unsupported Sierra class version");
        }

        let mut hash = PoseidonHasher::default();

        const SIERRA_VERSION: Felt = crate::felt_bytes!(b"CONTRACT_CLASS_V0.1.0");
        hash.write(SIERRA_VERSION.into());

        // It is important to process the different entrypoint hashchains in correct
        // order. Each of the entrypoint lists gets updated into the `outer`
        // hashchain.
        //
        // This implementation doesn't preparse the strings, which makes it a bit more
        // noisy. Late parsing is made in an attempt to lean on the one big string
        // allocation we've already got, but these three hash chains could be
        // constructed at deserialization time.
        [External, L1Handler, Constructor]
            .iter()
            .map(|key| {
                contract_definition
                    .entry_points_by_type
                    .get(key)
                    .unwrap_or(&Vec::new())
                    .iter()
                    // flatten each entry point to get a list of (selector, function_idx, selector,
                    // function_idx, ...)
                    .flat_map(|x| [x.selector.0, x.function_idx.into()].into_iter())
                    .fold(PoseidonHasher::default(), |mut hc, next| {
                        hc.write(next.into());
                        hc
                    })
            })
            .for_each(|x| hash.write(x.finish()));

        let abi_truncated_keccak = {
            let mut keccak = sha3::Keccak256::default();
            keccak.update(contract_definition.abi.as_bytes());
            truncated_keccak(<[u8; 32]>::from(keccak.finalize()))
        };
        hash.write(abi_truncated_keccak.into());

        let program_hash = {
            let program_hash = contract_definition.sierra_program.iter().fold(
                PoseidonHasher::default(),
                |mut hc, next| {
                    hc.write((*next).into());
                    hc
                },
            );
            program_hash.finish()
        };
        hash.write(program_hash);

        Ok(ClassHash(hash.finish().into()))
    }

    /// See:
    /// <https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/public/abi.py#L21-L26>
    pub(crate) fn truncated_keccak(mut plain: [u8; 32]) -> Felt {
        // python code masks with (2**250 - 1) which starts 0x03 and is followed by 31
        // 0xff in be truncation is needed not to overflow the field element.
        plain[0] &= 0x03;
        Felt::from_be_bytes(plain).expect("cannot overflow: smaller than modulus")
    }

    /// `std::io::Write` adapter for Keccak256; we don't need the serialized version
    /// in compute_class_hash, but we need the truncated_keccak hash.
    ///
    /// When debugging mismatching hashes, it might be useful to check the length of
    /// each before trying to find the wrongly serialized spot. Example length >
    /// 500kB.
    #[derive(Default)]
    struct KeccakWriter(sha3::Keccak256);

    impl std::io::Write for KeccakWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            // noop is fine, we'll finalize after the write phase
            Ok(())
        }
    }

    /// Starkware doesn't use compact formatting for JSON but default python
    /// formatting. This is required to hash to the same value after sorted
    /// serialization.
    struct PythonDefaultFormatter;

    impl serde_json::ser::Formatter for PythonDefaultFormatter {
        fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
        where
            W: ?Sized + std::io::Write,
        {
            if first {
                Ok(())
            } else {
                writer.write_all(b", ")
            }
        }

        fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
        where
            W: ?Sized + std::io::Write,
        {
            if first {
                Ok(())
            } else {
                writer.write_all(b", ")
            }
        }

        fn begin_object_value<W>(&mut self, writer: &mut W) -> std::io::Result<()>
        where
            W: ?Sized + std::io::Write,
        {
            writer.write_all(b": ")
        }

        // Credit: Jonathan Lei from starknet-rs (https://github.com/xJonathanLEI/starknet-rs)`
        #[inline]
        fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> std::io::Result<()>
        where
            W: ?Sized + std::io::Write,
        {
            let mut buf = [0, 0];

            for c in fragment.chars() {
                if c.is_ascii() {
                    writer.write_all(&[c as u8])?;
                } else {
                    let buf = c.encode_utf16(&mut buf);
                    for i in buf {
                        write!(writer, r"\u{:4x}", i)?;
                    }
                }
            }

            Ok(())
        }
    }


    mod json {
        use super::*;
        use std::borrow::Cow;
        use std::collections::{BTreeMap, HashMap};

        pub enum ContractDefinition<'a> {
            Cairo(CairoContractDefinition<'a>),
            Sierra(SierraContractDefinition<'a>),
        }

        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct SierraContractDefinition<'a> {
            /// Contract ABI.
            #[serde(borrow)]
            pub abi: Cow<'a, str>,

            /// Main program definition.
            pub sierra_program: Vec<Felt>,

            // Version
            #[serde(borrow)]
            pub contract_class_version: Cow<'a, str>,

            /// The contract entry points
            pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndFunctionIndex>>,
        }

        /// Our version of the cairo contract definition used to deserialize and
        /// re-serialize a modified version for a hash of the contract
        /// definition.
        ///
        /// The implementation uses `serde_json::Value` extensively for the
        /// unknown/undefined structure, and the correctness of this
        /// implementation depends on the following features of serde_json:
        ///
        /// - feature `raw_value` has to be enabled for the thrown away
        ///   `program.debug_info`
        /// - feature `preserve_order` has to be disabled, as we want everything
        ///   sorted
        /// - feature `arbitrary_precision` has to be enabled, as there are big
        ///   integers in the input
        ///
        /// It would be much more efficient to have a serde_json::Value which would
        /// only hold borrowed types.
        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(deny_unknown_fields)]
        pub struct CairoContractDefinition<'a> {
            /// Contract ABI, which has no schema definition.
            pub abi: serde_json::Value,

            /// Main program definition.
            #[serde(borrow)]
            pub program: CairoProgram<'a>,

            /// The contract entry points.
            ///
            /// These are left out of the re-serialized version with the ordering
            /// requirement to a Keccak256 hash.
            #[serde(skip_serializing)]
            pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndOffset>>,
        }

        // It's important that this is ordered alphabetically because the fields need to
        // be in sorted order for the keccak hashed representation.
        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(deny_unknown_fields)]
        pub struct CairoProgram<'a> {
            #[serde(skip_serializing_if = "Vec::is_empty", default)]
            pub attributes: Vec<serde_json::Value>,

            #[serde(borrow)]
            pub builtins: Vec<Cow<'a, str>>,

            // Added in Starknet 0.10, so we have to handle this not being present.
            #[serde(borrow, skip_serializing_if = "Option::is_none")]
            pub compiler_version: Option<Cow<'a, str>>,

            #[serde(borrow)]
            pub data: Vec<Cow<'a, str>>,

            #[serde(borrow)]
            pub debug_info: Option<&'a serde_json::value::RawValue>,

            // Important that this is ordered by the numeric keys, not lexicographically
            pub hints: BTreeMap<u64, Vec<serde_json::Value>>,

            pub identifiers: serde_json::Value,

            #[serde(borrow)]
            pub main_scope: Cow<'a, str>,

            // Unlike most other integers, this one is hex string. We don't need to interpret it,
            // it just needs to be part of the hashed output.
            #[serde(borrow)]
            pub prime: Cow<'a, str>,

            pub reference_manager: serde_json::Value,
        }

    }

    /// HashChain is the structure used over at cairo side to represent the hash
    /// construction needed for computing the class hash.
    ///
    /// Empty hash chained value equals `H(0, 0)` where `H` is the
    /// [`pedersen_hash()`] function, and the second value is the number of values
    /// hashed together in this chain. For other values, the accumulator is on each
    /// update replaced with the `H(hash, value)` and the number of count
    /// incremented by one.
    #[derive(Default)]
    pub struct HashChain {
        hash: Felt,
        count: usize,
    }

    impl HashChain {
        pub fn update(&mut self, value: Felt) {
            self.hash = pedersen_hash(self.hash, value);
            self.count = self
                .count
                .checked_add(1)
                .expect("could not have deserialized larger than usize Vecs");
        }

        pub fn chain_update(mut self, value: Felt) -> Self {
            self.update(value);
            self
        }

        pub fn finalize(self) -> Felt {
            let count =
                Felt::from_be_slice(&self.count.to_be_bytes()).expect("usize is smaller than 251-bits");
            pedersen_hash(self.hash, count)
        }

        pub fn single(value: Felt) -> Felt {
            Self::default().chain_update(value).finalize()
        }
    }

    /// The PoseidonHasher can build up a hash by appending to state
    ///
    /// Its output is equivalent to calling [poseidon_hash_many] with the field
    /// elements.
    pub struct PoseidonHasher {
        state: PoseidonState,
        buffer: Option<MontFelt>,
    }

    impl PoseidonHasher {
        /// Creates a new PoseidonHasher
        pub fn new() -> PoseidonHasher {
            PoseidonHasher {
                state: [MontFelt::ZERO, MontFelt::ZERO, MontFelt::ZERO],
                buffer: None,
            }
        }

        /// Absorbs message into the hash
        pub fn write(&mut self, msg: MontFelt) {
            match self.buffer.take() {
                Some(previous_message) => {
                    self.state[0] += previous_message;
                    self.state[1] += msg;
                    permute(&mut self.state);
                }
                None => {
                    self.buffer = Some(msg);
                }
            }
        }

        /// Same as [Self::write] but returns self to enable chaining writes.
        pub fn chain(mut self, msg: MontFelt) -> Self {
            self.write(msg);
            self
        }

        /// Finish and return hash
        pub fn finish(mut self) -> MontFelt {
            // Apply padding
            match self.buffer.take() {
                Some(last_message) => {
                    self.state[0] += last_message;
                    self.state[1] += MontFelt::ONE;
                }
                None => {
                    self.state[0] += MontFelt::ONE;
                }
            }
            permute(&mut self.state);

            self.state[0]
        }
    }

    // --------------------------------------------------------------------
    // MontFelt impl
    // TODO: this got out of hand, it needs its own module...
    // --------------------------------------------------------------------

    /// State for the Poseidon hash function
    pub type PoseidonState = [MontFelt; 3];

    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 83;

    #[rustfmt::skip]
    pub const POSEIDON_COMP_CONSTS: [MontFelt; 107] = [
        MontFelt::from_raw([ 9243643933561577962u64,18087611126302680282u64, 7098098609281275249u64,  289757450055368158u64,]),
        MontFelt::from_raw([ 7853535095351734343u64,10850711010770646915u64,12570458558381957509u64,  325478872510666341u64,]),
        MontFelt::from_raw([14487852855283887204u64, 5186719240138179095u64, 8414109922749085282u64,  400708606768273790u64,]),
        MontFelt::from_raw([ 3280395077118373336u64,17795901222489795490u64, 2641423859640672268u64,   77297546474262716u64,]),
        MontFelt::from_raw([ 8106789448329946608u64, 5622576456418619364u64,  917099606739132255u64,  531983052745549445u64,]),
        MontFelt::from_raw([  595196979161159364u64,13104152156623721627u64,11543764507410437138u64,  296030771607252997u64,]),
        MontFelt::from_raw([ 7816701695378368721u64, 3357934764826603292u64,15403608342128707689u64,  450788015873872442u64,]),
        MontFelt::from_raw([  636799349004279181u64, 6138586124645004146u64, 9427309254075631876u64,  241320328808721095u64,]),
        MontFelt::from_raw([17291774529514094747u64, 5039440405858006990u64, 9298428421172181112u64,  506951390701988816u64,]),
        MontFelt::from_raw([11806696651894481589u64, 1092083221520939347u64,14414850501582138681u64,  221101813663738384u64,]),
        MontFelt::from_raw([13829429898061010046u64, 2611422711440939737u64,15408727842397286736u64,  507284792967663799u64,]),
        MontFelt::from_raw([13083162048600272883u64, 8232965923506882345u64,10342036084285918913u64,    4246917344608281u64,]),
        MontFelt::from_raw([14120941658239655251u64, 2642188447246846335u64, 6420128711794491484u64,  387738584202674747u64,]),
        MontFelt::from_raw([ 4557515129132896247u64,12925333772434149495u64, 8021291067466006291u64,  359812401200365725u64,]),
        MontFelt::from_raw([ 1890170602709420465u64,10101417316275735447u64,14228475625622468342u64,  213055788422889429u64,]),
        MontFelt::from_raw([17718807227125703766u64, 3165015027285286767u64,17001522267729424593u64,  193938768174500364u64,]),
        MontFelt::from_raw([   11967566541251349u64, 8042878571206807946u64,12035959970295095627u64,  392852226019534694u64,]),
        MontFelt::from_raw([14702858513363496537u64, 1891459712461864795u64,11108523323717023107u64,  156261542945214132u64,]),
        MontFelt::from_raw([ 1945929902309569324u64,12703913861703223537u64,18026399617460967320u64,  552659386849285670u64,]),
        MontFelt::from_raw([15676691957102339301u64, 7305794071419508305u64,15605369973884503830u64,  279124040567655554u64,]),
        MontFelt::from_raw([ 6878414542634060631u64, 6806916028752188971u64, 6743346892345011852u64,  209421398668690776u64,]),
        MontFelt::from_raw([14451878242532315248u64,  280667558436689575u64, 7481193996043836595u64,  102898977772584225u64,]),
        MontFelt::from_raw([10099174071678455934u64,10050300413654558496u64,15460796480957384300u64,  326260635675691414u64,]),
        MontFelt::from_raw([12189485177509053284u64,18189503908521730582u64, 2742965211333049654u64,  246759231813836949u64,]),
        MontFelt::from_raw([17131884891365868725u64, 4126475231607707865u64, 4142744258917121527u64,  517354668301661021u64,]),
        MontFelt::from_raw([ 9321360184240157338u64, 8642907823639066926u64, 4815888288973513717u64,  387266619660887473u64,]),
        MontFelt::from_raw([ 9877712865958333042u64,  172887203519774060u64,14912001171503456000u64,  379922462175671594u64,]),
        MontFelt::from_raw([ 5253862319821606646u64, 3112421893979476452u64,12476994431456066104u64,  503867426189678810u64,]),
        MontFelt::from_raw([ 6459833828500045091u64, 8544893956421165385u64, 4198699220078046017u64,  361247795501724706u64,]),
        MontFelt::from_raw([15367072576308287971u64,11136955306523718350u64, 1150777808545574589u64,  569094971639990703u64,]),
        MontFelt::from_raw([  938972551523044539u64,14766818754575560648u64,14214531273441880096u64,  519370339044767210u64,]),
        MontFelt::from_raw([ 8541051058482254568u64,15415072429245325504u64,14957220415534017748u64,   76536527755312734u64,]),
        MontFelt::from_raw([ 2465712523883598144u64, 6511341599113654315u64, 6309081263114838229u64,  393450888402641516u64,]),
        MontFelt::from_raw([  940821186092154852u64, 8192839842351846874u64, 5396406749139750234u64,  288112524550260818u64,]),
        MontFelt::from_raw([18013945796863515455u64,14414340112335121757u64, 8020715533944075007u64,  378547930620493071u64,]),
        MontFelt::from_raw([10882040312752948163u64,13534318422278561025u64,16239338703176780807u64,  315921785019971079u64,]),
        MontFelt::from_raw([11804152077864610443u64,10711845104699761001u64, 2579945555704418307u64,  407428959149964045u64,]),
        MontFelt::from_raw([ 3599124979175311464u64,12397382694363857548u64, 2441162789755772647u64,  519829512759629210u64,]),
        MontFelt::from_raw([ 1122008851702936351u64, 2255313605192201584u64, 9526529507379911735u64,  297026039684882166u64,]),
        MontFelt::from_raw([ 1993625032903604531u64,  596810388162793045u64,15598201710380655007u64,  131529263108506346u64,]),
        MontFelt::from_raw([ 4674850965951748614u64, 4226133210265092969u64,16131311957670865406u64,  224060573845038011u64,]),
        MontFelt::from_raw([11214981260617649902u64, 2473985365883836987u64, 5936657039588618128u64,   75239021508281120u64,]),
        MontFelt::from_raw([ 1656325451144825481u64, 9292758618068460829u64,10708624397900073633u64,  194216947938400317u64,]),
        MontFelt::from_raw([ 8903410050073285790u64, 8661236053987118957u64, 1615364812064241551u64,   67542072505613059u64,]),
        MontFelt::from_raw([15404542557975125459u64, 2998788108140034653u64, 2552297003970802502u64,  469030315210549517u64,]),
        MontFelt::from_raw([12823358311737123095u64, 7648424977752018148u64, 6761349120637124061u64,  453636870534881918u64,]),
        MontFelt::from_raw([ 9487732293618798109u64,10740489098835571894u64,11738903622058165831u64,  161717009046994634u64,]),
        MontFelt::from_raw([13651502097878895227u64,10047101549636218127u64,10044469647704241764u64,  277982644699321060u64,]),
        MontFelt::from_raw([ 8555164891384310121u64, 8824267949549756926u64, 7305199522290707083u64,  263260756366809017u64,]),
        MontFelt::from_raw([ 8140624856704023682u64, 8045915014876264352u64,17217076042215213576u64,   72504083815642834u64,]),
        MontFelt::from_raw([ 2393283877389675021u64,  184042354645416614u64, 5319475030094698416u64,  521277606880990981u64,]),
        MontFelt::from_raw([  434646374717545122u64,16968292764294941446u64,  397903500864519791u64,  189962858545866132u64,]),
        MontFelt::from_raw([15192322066947113426u64, 7230072155523803250u64, 1912611278135465035u64,  484438043712101051u64,]),
        MontFelt::from_raw([ 3404050675041230416u64, 5349474969561382272u64,10312121908398277288u64,  131659008494808833u64,]),
        MontFelt::from_raw([16161573332686472539u64,11482954176039056988u64,10321079257176384834u64,  285431294163195780u64,]),
        MontFelt::from_raw([ 7769460563456887047u64,15933903404722266197u64, 4417375624575928495u64,  509185859951343125u64,]),
        MontFelt::from_raw([ 4757536062552078975u64,14345591597495868207u64, 5136403899854077412u64,  155548508933381698u64,]),
        MontFelt::from_raw([16954136253536679036u64,15495192077804287724u64, 3602538967473509698u64,  424756635805120473u64,]),
        MontFelt::from_raw([  782587731399981975u64, 8752948468066486506u64,11249513498993831494u64,  297791197798108890u64,]),
        MontFelt::from_raw([ 8920685932186110294u64,  607857242333979734u64, 9067276084563478270u64,  257755501610648687u64,]),
        MontFelt::from_raw([12797826492922709079u64,  598864940726990753u64,10808632893013728360u64,  255507877414539372u64,]),
        MontFelt::from_raw([18357585898410668675u64,14427109677195052515u64,11616133167538022764u64,  337499443474645791u64,]),
        MontFelt::from_raw([11006876850199954451u64, 4471887087529055003u64,13709407269306624594u64,  461544350634460860u64,]),
        MontFelt::from_raw([ 3935449925401609487u64, 7247938434158659126u64,16055252784997531913u64,  241572537953357206u64,]),
        MontFelt::from_raw([12185916472608269828u64, 8599903496731799844u64, 7473372200107268523u64,   20826784995699326u64,]),
        MontFelt::from_raw([ 9114145677234606895u64,11335924134290767337u64,12339440635155145939u64,  325284558926946894u64,]),
        MontFelt::from_raw([ 7913511813685739207u64,13510010034121256720u64, 5786681712809070321u64,  524297675686992468u64,]),
        MontFelt::from_raw([11489572640693348549u64,  653791830907185044u64, 1343259707956093156u64,   91862724283776664u64,]), 
        MontFelt::from_raw([ 8475224572437702585u64, 6117048525531009669u64, 2612824879774856987u64,  152655841869983584u64,]),
        MontFelt::from_raw([10275284836695919781u64, 1229936912426117714u64,  852953717024661566u64,  494626294612738458u64,]),
        MontFelt::from_raw([  458652097155681902u64,14888651917691804798u64,16255075206832288784u64,   24654605265517243u64,]),
        MontFelt::from_raw([12078376201244291123u64,15650814510286239758u64, 7824274777759107853u64,  548147943423761875u64,]),
        MontFelt::from_raw([ 7150607360351293312u64,15869512646666935948u64,17547962929740675348u64,  544265221469581427u64,]),
        MontFelt::from_raw([ 8825399362075630882u64, 8320101570235006675u64,  831216380162620582u64,  110482907032568200u64,]),
        MontFelt::from_raw([16250629230069546482u64, 2730194971623754710u64, 2257455797750592448u64,  492309260778657687u64,]),
        MontFelt::from_raw([14147969271427023624u64,  828879174920615316u64,  774481952233097841u64,  358764916624727771u64,]),
        MontFelt::from_raw([ 2327560102298050020u64,16326474056896465620u64,11569722182073805281u64,  505092152210714943u64,]),
        MontFelt::from_raw([ 9785912164301152354u64, 8106490610561126785u64, 1630249814069958098u64,   58834859029597485u64,]),
        MontFelt::from_raw([ 3289890810144882514u64, 3215734868963276321u64, 8055317084564590682u64,  119086600262724981u64,]),
        MontFelt::from_raw([ 5483225686717068229u64,16371685975512595166u64,15450955014197186841u64,  247943736268488503u64,]),
        MontFelt::from_raw([ 4381919769144899813u64,13933618086851303637u64, 5230009595729784912u64,   20792489568442719u64,]),
        MontFelt::from_raw([ 8789178883266410059u64,16721801817937206035u64,13400733992682978294u64,  442589726189451790u64,]),
        MontFelt::from_raw([14046586735054130921u64,  292037712493469239u64, 5356712645210626551u64,  293939309306751922u64,]),
        MontFelt::from_raw([  380205073025197349u64, 5755966045834097308u64, 5866406040614980707u64,  348659944710609305u64,]),
        MontFelt::from_raw([ 9134565645309956025u64, 5970118022284662551u64, 7792904134063363468u64,  113718338186485349u64,]),
        MontFelt::from_raw([ 2923116954730895285u64, 4758998626841090083u64,11310098556304705439u64,   48545222501354940u64,]),
        MontFelt::from_raw([10356409984278808132u64, 8626434746901408014u64,14741910479101271233u64,  288126037191662696u64,]),
        MontFelt::from_raw([15089483185994803607u64,15995340104776500525u64, 8804335419305831150u64,  396859084962881839u64,]),
        MontFelt::from_raw([ 1806552960857676317u64, 5044268144265983057u64,10937421026512331976u64,  388825756002312816u64,]),
        MontFelt::from_raw([  195394918711621979u64,11495023801469827766u64,10387650783476140513u64,   36031442409401774u64,]),
        MontFelt::from_raw([ 6252690410849898787u64,15336030451772296178u64, 9931420975657904643u64,  342401574327501171u64,]),
        MontFelt::from_raw([ 8845585704258239691u64, 6335878880627979647u64,11428826230512157512u64,  125599780553714479u64,]),
        MontFelt::from_raw([15678553522198702946u64, 5956556265401411549u64,15531514790645111620u64,  321829728761679778u64,]),
        MontFelt::from_raw([12747317311074323278u64,18276738862377911125u64,16869705933132331722u64,  429960475805585734u64,]),
        MontFelt::from_raw([ 8818520944555213172u64,12659942709060110110u64, 3152386375917271891u64,  538072118411786464u64,]),
        MontFelt::from_raw([ 7051814885573177194u64, 6963721086450009179u64,17624329337577352587u64,  478549527730244073u64,]),
        MontFelt::from_raw([12782217873770289538u64,15295458184819533181u64, 4074200589034403638u64,  173095944718984339u64,]),
        MontFelt::from_raw([ 1759489451407771803u64, 2198678818123145500u64, 8614653954149136745u64,  522963184775328415u64,]),
        MontFelt::from_raw([15754679985287562033u64,17144367048005459911u64, 8637536145542499282u64,  178770311623751184u64,]),
        MontFelt::from_raw([  298970159691700591u64,12014891315505021636u64, 5642896886612387367u64,  320523276021081874u64,]),
        MontFelt::from_raw([ 2161827243834369197u64, 6529000939326479156u64, 3360240309062894342u64,  423278556197684001u64,]),
        MontFelt::from_raw([17922407737483631270u64,10846304006776507478u64, 4814020835957029095u64,  558105788237772190u64,]),
        MontFelt::from_raw([14309821559636775821u64, 5191281667707819629u64, 7991629750293746597u64,   55044774064780458u64,]),
        MontFelt::from_raw([ 4475858853850722769u64, 4126326734531744171u64,14548036495158561611u64,  569399000276545969u64,]),
        MontFelt::from_raw([17137171742635080032u64,13734979251366108230u64,  733658667004231380u64,  393850665517739074u64,]),
        MontFelt::from_raw([18207273213375707676u64, 9125832381882861274u64,13182372482997690796u64,  374441752858986998u64,]),
        MontFelt::from_raw([11725146126629035967u64, 2224508228469132237u64, 1606247714594998930u64,  162358740541808928u64,]),
    ];

    /// Poseidon mix function.
    ///
    /// The MixLayer operation using MDS matrix M = ((3,1,1), (1,-1,1), (1,1,-2)).
    /// Given state vector x=(a,b,c), it returns Mx, optimized by precomputing
    /// t=a+b+c.
    #[inline(always)]
    fn mix(state: &mut PoseidonState) {
        let t = state[0] + state[1] + state[2];
        state[0] = t + state[0].double();
        state[1] = t - state[1].double();
        state[2] = t - (state[2].double() + state[2]);
    }

    /// Poseidon full round function.
    ///
    /// Each round consists of three steps:
    ///   - AddRoundConstants adds precomputed constants
    ///   - SubWords is the cube function
    ///   - MixLayer multiplies the state with fixed matrix
    #[inline]
    fn full_round(state: &mut PoseidonState, idx: usize) {
        state[0] += POSEIDON_COMP_CONSTS[idx];
        state[1] += POSEIDON_COMP_CONSTS[idx + 1];
        state[2] += POSEIDON_COMP_CONSTS[idx + 2];
        state[0] = state[0].square() * state[0];
        state[1] = state[1].square() * state[1];
        state[2] = state[2].square() * state[2];
        mix(state);
    }

    /// Poseidon partial round function.
    ///
    /// This only applies the non-linear part to a partial state.
    #[inline]
    fn partial_round(state: &mut PoseidonState, idx: usize) {
        state[2] += POSEIDON_COMP_CONSTS[idx];
        state[2] = state[2].square() * state[2];
        mix(state);
    }

    /// Poseidon permutation function
    ///
    /// The permutation consists of 8 full rounds, 83 partial rounds followed by 8
    /// full rounds.
    pub fn permute(state: &mut PoseidonState) {
        let mut idx = 0;

        // Full rounds
        for _ in 0..(FULL_ROUNDS / 2) {
            full_round(state, idx);
            idx += 3;
        }

        // Partial rounds
        for _ in 0..PARTIAL_ROUNDS {
            partial_round(state, idx);
            idx += 1;
        }

        // Full rounds
        for _ in 0..(FULL_ROUNDS / 2) {
            full_round(state, idx);
            idx += 3;
        }
    }

    /// Creates a [`pathfinder_crypto::Felt`] from a byte slice, resulting in
    /// compile-time error when invalid.
    #[macro_export]
    macro_rules! felt_bytes {
        ($bytes:expr) => {{
            match Felt::from_be_slice($bytes) {
                Ok(sh) => sh,
                Err(OverflowError) => panic!("Invalid constant: OverflowError"),
            }
        }};
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct SierraEntryPoints {
        #[serde(rename = "EXTERNAL")]
        pub external: Vec<SelectorAndFunctionIndex>,
        #[serde(rename = "L1_HANDLER")]
        pub l1_handler: Vec<SelectorAndFunctionIndex>,
        #[serde(rename = "CONSTRUCTOR")]
        pub constructor: Vec<SelectorAndFunctionIndex>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct CairoEntryPoints {
        #[serde(rename = "EXTERNAL")]
        pub external: Vec<SelectorAndOffset>,
        #[serde(rename = "L1_HANDLER")]
        pub l1_handler: Vec<SelectorAndOffset>,
        #[serde(rename = "CONSTRUCTOR")]
        pub constructor: Vec<SelectorAndOffset>,
    }

    #[derive(Copy, Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Hash, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
        #[serde(rename = "CONSTRUCTOR")]
        Constructor,
    }

    impl std::fmt::Display for EntryPointType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            use EntryPointType::*;
            f.pad(match self {
                External => "EXTERNAL",
                L1Handler => "L1_HANDLER",
                Constructor => "CONSTRUCTOR",
            })
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct SelectorAndOffset {
        pub selector: EntryPoint,
        #[serde_as(as = "OffsetSerde")]
        pub offset: ByteCodeOffset,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(untagged)]
    pub enum OffsetSerde {
        HexStr(Felt),
        Decimal(u64),
    }
        impl serde_with::SerializeAs<ByteCodeOffset> for OffsetSerde {
        fn serialize_as<S>(source: &ByteCodeOffset, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::Serialize;

            Felt::serialize(&source.0, serializer)
        }
    }

    impl<'de> serde_with::DeserializeAs<'de, ByteCodeOffset> for OffsetSerde {
        fn deserialize_as<D>(deserializer: D) -> Result<ByteCodeOffset, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::Deserialize;

            let offset = OffsetSerde::deserialize(deserializer)?;
            let offset = match offset {
                OffsetSerde::HexStr(felt) => felt,
                OffsetSerde::Decimal(decimal) => Felt::from_u64(decimal),
            };
            Ok(ByteCodeOffset(offset))
        }
    }

    /// Descriptor of an entry point in a Sierra class.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct SelectorAndFunctionIndex {
        pub selector: EntryPoint,
        pub function_idx: u64,
    }
}

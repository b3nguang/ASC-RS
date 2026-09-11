use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{Arc, OnceLock},
};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context, Result, anyhow, ensure};

use crate::dex_format::{
    DexHeader as Header, FieldId, MethodId, ProtoId, bytes_at as get_bytes,
    instruction_width_bytes, read_field_ids, read_method_ids, read_proto_ids, read_string,
    read_strings, read_type_list, read_types, read_uleb, u32_at,
};

#[cfg(test)]
use crate::dex_format::decode_mutf8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceKind {
    String,
    Type,
    Method,
    Field,
}

#[derive(Debug, Clone)]
pub struct MemberQuery {
    pub class: Option<String>,
    pub fuzzy_class: bool,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Query {
    String(String),
    Type(String),
    Method(MemberQuery),
    Field(MemberQuery),
}

/// Reusable multi-pattern matcher for one batch of string queries.
///
/// Duplicate and empty queries are kept as distinct result groups even though
/// only unique, non-empty patterns are added to the automaton.
pub(crate) struct StringBatchMatcher {
    automaton: Option<AhoCorasick>,
    unique_to_queries: Vec<Vec<usize>>,
    empty_queries: Vec<usize>,
    query_count: usize,
}

impl StringBatchMatcher {
    pub(crate) fn new(patterns: &[String]) -> Result<Self> {
        let mut unique_patterns = Vec::<&str>::new();
        let mut unique_to_queries = Vec::<Vec<usize>>::new();
        let mut unique_ids = HashMap::<&str, usize>::new();
        let mut empty_queries = Vec::new();

        for (query_index, pattern) in patterns.iter().enumerate() {
            if pattern.is_empty() {
                empty_queries.push(query_index);
                continue;
            }
            if let Some(&unique_index) = unique_ids.get(pattern.as_str()) {
                unique_to_queries[unique_index].push(query_index);
            } else {
                let unique_index = unique_patterns.len();
                unique_patterns.push(pattern);
                unique_to_queries.push(vec![query_index]);
                unique_ids.insert(pattern, unique_index);
            }
        }

        let automaton = if unique_patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::Standard)
                    .build(&unique_patterns)?,
            )
        };
        Ok(Self {
            automaton,
            unique_to_queries,
            empty_queries,
            query_count: patterns.len(),
        })
    }

    pub(crate) fn matching_indices(&self, strings: &[String]) -> Vec<Vec<u32>> {
        let mut results = vec![Vec::new(); self.query_count];
        let mut last_seen = vec![usize::MAX; self.unique_to_queries.len()];

        for (string_index, value) in strings.iter().enumerate() {
            let string_index_u32 = string_index as u32;
            for &query_index in &self.empty_queries {
                results[query_index].push(string_index_u32);
            }
            let Some(automaton) = &self.automaton else {
                continue;
            };
            for matched in automaton.find_overlapping_iter(value) {
                let unique_index = matched.pattern().as_usize();
                if last_seen[unique_index] == string_index {
                    continue;
                }
                last_seen[unique_index] = string_index;
                for &query_index in &self.unique_to_queries[unique_index] {
                    results[query_index].push(string_index_u32);
                }
            }
        }
        results
    }
}

impl Query {
    pub fn kind(&self) -> ReferenceKind {
        match self {
            Self::String(_) => ReferenceKind::String,
            Self::Type(_) => ReferenceKind::Type,
            Self::Method(_) => ReferenceKind::Method,
            Self::Field(_) => ReferenceKind::Field,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CodeItem {
    method_idx: u32,
    insns_offset: usize,
    insns_size: usize,
}

#[derive(Debug)]
struct ReferenceIndex {
    /// Sites sorted by target index, then caller and code-unit offset.
    sites: Box<[ReferenceSite]>,
}

#[derive(Debug)]
pub struct Dex {
    data: Arc<[u8]>,
    header: Header,
    strings: Vec<String>,
    types: Vec<u32>,
    protos: Vec<ProtoId>,
    fields: Vec<FieldId>,
    methods: Vec<MethodId>,
    class_type_indices: Vec<u32>,
    code_items: Vec<CodeItem>,
    method_scan_order: Vec<u32>,
    reference_indexes: [OnceLock<Result<ReferenceIndex, String>>; 4],
    method_descriptors: Vec<OnceLock<Result<String, String>>>,
}

impl Dex {
    /// Parse borrowed bytes into a self-contained DEX. Prefer `parse_shared`
    /// when the caller already owns the data in an `Arc` to avoid a copy.
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::parse_shared(Arc::from(data))
    }

    pub fn parse_shared(data: Arc<[u8]>) -> Result<Self> {
        Self::parse_shared_at(data, 0)
    }

    pub(crate) fn parse_shared_at(data: Arc<[u8]>, header_offset: usize) -> Result<Self> {
        let header = Header::parse_at(&data, header_offset)?;
        let strings = read_strings(&data, &header)?;
        let types = read_types(&data, &header)?;
        let protos = read_proto_ids(&data, &header)?;
        let fields = read_field_ids(&data, &header)?;
        let methods = read_method_ids(&data, &header)?;

        let mut class_type_indices = Vec::with_capacity(header.class_defs_size as usize);
        let mut class_data_offsets = Vec::with_capacity(header.class_defs_size as usize);
        for index in 0..header.class_defs_size as usize {
            let offset = header.class_defs_off as usize + index * 32;
            let class_idx = u32_at(&data, offset)?;
            ensure!(
                class_idx < header.type_ids_size,
                "class #{index} has invalid type index"
            );
            class_type_indices.push(class_idx);
            class_data_offsets.push(u32_at(&data, offset + 24)?);
        }

        let method_descriptor_count = methods.len();
        let mut dex = Self {
            data,
            header,
            strings,
            types,
            protos,
            fields,
            methods,
            class_type_indices,
            code_items: Vec::new(),
            method_scan_order: vec![u32::MAX; method_descriptor_count],
            reference_indexes: std::array::from_fn(|_| OnceLock::new()),
            method_descriptors: (0..method_descriptor_count)
                .map(|_| OnceLock::new())
                .collect(),
        };
        for offset in class_data_offsets {
            if offset != 0 {
                dex.parse_class_data(offset as usize)?;
            }
        }
        Ok(dex)
    }

    fn parse_class_data(&mut self, offset: usize) -> Result<()> {
        let mut cursor = offset;
        let static_fields = read_uleb(&self.data, &mut cursor)?;
        let instance_fields = read_uleb(&self.data, &mut cursor)?;
        let direct_methods = read_uleb(&self.data, &mut cursor)?;
        let virtual_methods = read_uleb(&self.data, &mut cursor)?;

        let field_count = static_fields
            .checked_add(instance_fields)
            .context("encoded field count overflow")?;
        for _ in 0..field_count {
            let _field_idx_diff = read_uleb(&self.data, &mut cursor)?;
            let _access_flags = read_uleb(&self.data, &mut cursor)?;
        }

        for count in [direct_methods, virtual_methods] {
            let mut method_idx = 0u32;
            for _ in 0..count {
                method_idx = method_idx
                    .checked_add(read_uleb(&self.data, &mut cursor)?)
                    .context("method index overflow in class_data_item")?;
                let _access_flags = read_uleb(&self.data, &mut cursor)?;
                let code_offset = read_uleb(&self.data, &mut cursor)? as usize;
                ensure!(
                    method_idx < self.header.method_ids_size,
                    "invalid encoded method index"
                );
                if code_offset == 0 {
                    continue;
                }
                let insns_size = u32_at(&self.data, code_offset + 12)? as usize;
                let insns_offset = code_offset + 16;
                let insns_bytes = insns_size
                    .checked_mul(2)
                    .context("code item size overflow")?;
                get_bytes(&self.data, insns_offset, insns_bytes)?;
                let scan_order =
                    u32::try_from(self.code_items.len()).context("too many code items to index")?;
                self.method_scan_order[method_idx as usize] = scan_order;
                self.code_items.push(CodeItem {
                    method_idx,
                    insns_offset,
                    insns_size,
                });
            }
        }
        Ok(())
    }

    fn type_descriptor(&self, type_idx: u32) -> &str {
        let string_idx = self.types[type_idx as usize];
        &self.strings[string_idx as usize]
    }

    pub fn defines_class(&self, descriptor: &str) -> bool {
        self.class_type_indices
            .iter()
            .any(|&index| self.type_descriptor(index) == descriptor)
    }

    pub fn class_count(&self) -> usize {
        self.class_type_indices.len()
    }

    pub fn method_count(&self) -> usize {
        self.methods.len()
    }

    pub fn matching_indices(&self, query: &Query) -> HashSet<u32> {
        match query {
            Query::String(pattern) => self
                .strings
                .iter()
                .enumerate()
                .filter(|(_, value)| value.contains(pattern))
                .map(|(index, _)| index as u32)
                .collect(),
            Query::Type(pattern) => self
                .types
                .iter()
                .enumerate()
                .filter(|(_, string_idx)| self.strings[**string_idx as usize].contains(pattern))
                .map(|(index, _)| index as u32)
                .collect(),
            Query::Method(member) => self
                .methods
                .iter()
                .enumerate()
                .filter(|(_, method)| {
                    self.member_matches(method.class_idx, method.name_idx, member)
                })
                .map(|(index, _)| index as u32)
                .collect(),
            Query::Field(member) => self
                .fields
                .iter()
                .enumerate()
                .filter(|(_, field)| self.member_matches(field.class_idx, field.name_idx, member))
                .map(|(index, _)| index as u32)
                .collect(),
        }
    }

    pub(crate) fn matching_string_indices_batch(
        &self,
        matcher: &StringBatchMatcher,
    ) -> Vec<Vec<u32>> {
        matcher.matching_indices(&self.strings)
    }

    fn member_matches(&self, class_idx: u16, name_idx: u32, query: &MemberQuery) -> bool {
        let name_matches = query
            .name
            .as_ref()
            .is_none_or(|pattern| self.strings[name_idx as usize].contains(pattern));
        let class_matches = query.class.as_ref().is_none_or(|pattern| {
            let descriptor = self.type_descriptor(u32::from(class_idx));
            if query.fuzzy_class {
                descriptor.contains(pattern)
            } else {
                descriptor == pattern
            }
        });
        name_matches && class_matches
    }

    pub fn scan_reference_sites(
        &self,
        kind: ReferenceKind,
        targets: &HashSet<u32>,
    ) -> Result<Vec<ReferenceSite>> {
        let mut targets = targets.iter().copied().collect::<Vec<_>>();
        targets.sort_unstable();
        self.scan_reference_sites_sorted(kind, &targets)
    }

    pub(crate) fn scan_reference_sites_sorted(
        &self,
        kind: ReferenceKind,
        targets: &[u32],
    ) -> Result<Vec<ReferenceSite>> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }
        debug_assert!(targets.windows(2).all(|pair| pair[0] < pair[1]));
        let index = self.reference_index(kind)?;
        let mut results = Vec::new();
        for &target in targets {
            let start = index
                .sites
                .partition_point(|site| site.target_index < target);
            let end = index
                .sites
                .partition_point(|site| site.target_index <= target);
            results.extend_from_slice(&index.sites[start..end]);
        }
        results.sort_unstable_by_key(|site| {
            (
                self.method_scan_order
                    .get(site.caller_index as usize)
                    .copied()
                    .unwrap_or(u32::MAX),
                site.code_unit_offset,
                site.target_index,
            )
        });
        Ok(results)
    }

    fn reference_index(&self, kind: ReferenceKind) -> Result<&ReferenceIndex> {
        let cached = self.reference_indexes[kind.slot()].get_or_init(|| {
            self.build_reference_index(kind)
                .map_err(|error| format!("{error:#}"))
        });
        cached
            .as_ref()
            .map_err(|message| anyhow!(message.to_owned()))
    }

    fn build_reference_index(&self, kind: ReferenceKind) -> Result<ReferenceIndex> {
        let mut sites = Vec::new();
        for code in &self.code_items {
            let insns_bytes = code
                .insns_size
                .checked_mul(2)
                .context("code item size overflow")?;
            let bytes = get_bytes(&self.data, code.insns_offset, insns_bytes)?;
            let mut pc = 0usize;
            while pc < code.insns_size {
                let opcode = (code_unit(bytes, pc)? & 0xff) as u8;
                if let Some(index) = reference_index(kind, opcode, bytes, pc) {
                    sites.push(ReferenceSite {
                        caller_index: code.method_idx,
                        target_index: index,
                        code_unit_offset: pc as u32,
                    });
                }
                let width = instruction_width_bytes(bytes, pc)?;
                let next = pc
                    .checked_add(width)
                    .context("instruction offset overflow")?;
                ensure!(
                    width > 0 && next <= code.insns_size,
                    "invalid instruction width at code unit {pc}"
                );
                pc = next;
            }
        }
        sites.sort_unstable_by_key(|site| {
            (site.target_index, site.caller_index, site.code_unit_offset)
        });
        Ok(ReferenceIndex {
            sites: sites.into_boxed_slice(),
        })
    }

    pub fn scan_references(
        &self,
        kind: ReferenceKind,
        targets: &HashSet<u32>,
    ) -> Result<BTreeMap<u32, BTreeSet<u32>>> {
        let mut grouped = BTreeMap::<u32, BTreeSet<u32>>::new();
        for site in self.scan_reference_sites(kind, targets)? {
            grouped
                .entry(site.caller_index)
                .or_default()
                .insert(site.target_index);
        }
        Ok(grouped)
    }

    pub fn format_method(&self, index: u32) -> String {
        self.try_format_method(index)
            .unwrap_or_else(|_| format!("method@{index}"))
    }

    pub fn try_format_method(&self, index: u32) -> Result<String> {
        let descriptor = self
            .method_descriptors
            .get(index as usize)
            .with_context(|| format!("invalid method index {index}"))?
            .get_or_init(|| {
                self.build_method_descriptor(index)
                    .map_err(|error| format!("{error:#}"))
            });
        descriptor
            .as_ref()
            .cloned()
            .map_err(|message| anyhow!(message.to_owned()))
    }

    fn build_method_descriptor(&self, index: u32) -> Result<String> {
        let method = &self.methods[index as usize];
        let proto = self
            .protos
            .get(method.proto_idx as usize)
            .with_context(|| format!("invalid proto index {}", method.proto_idx))?;
        let parameters =
            read_type_list(&self.data, proto.parameters_off, self.header.type_ids_size)?
                .into_iter()
                .map(|type_idx| self.type_descriptor(u32::from(type_idx)))
                .collect::<String>();
        Ok(format!(
            "{}->{}({}){}",
            self.type_descriptor(u32::from(method.class_idx)),
            self.strings[method.name_idx as usize],
            parameters,
            self.type_descriptor(proto.return_type_idx)
        ))
    }

    pub fn format_match(&self, kind: ReferenceKind, index: u32) -> String {
        self.try_format_match(kind, index)
            .unwrap_or_else(|_| format!("{}@{index}", kind.label()))
    }

    pub fn try_format_match(&self, kind: ReferenceKind, index: u32) -> Result<String> {
        match kind {
            ReferenceKind::String => self
                .strings
                .get(index as usize)
                .cloned()
                .with_context(|| format!("invalid string index {index}")),
            ReferenceKind::Type => Ok(self.type_descriptor(index).to_owned()),
            ReferenceKind::Method => self.try_format_method(index),
            ReferenceKind::Field => {
                let field = self
                    .fields
                    .get(index as usize)
                    .with_context(|| format!("invalid field index {index}"))?;
                Ok(format!(
                    "{}->{}:{}",
                    self.type_descriptor(u32::from(field.class_idx)),
                    self.strings[field.name_idx as usize],
                    self.type_descriptor(u32::from(field.type_idx))
                ))
            }
        }
    }
}

impl ReferenceKind {
    fn slot(self) -> usize {
        match self {
            Self::String => 0,
            Self::Type => 1,
            Self::Method => 2,
            Self::Field => 3,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Type => "type",
            Self::Method => "method",
            Self::Field => "field",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceSite {
    pub caller_index: u32,
    pub target_index: u32,
    /// Offset from the beginning of the caller's instruction stream, measured
    /// in 16-bit DEX code units.
    pub code_unit_offset: u32,
}

/// Read only the tables required to index class definitions. This avoids
/// walking every method and code item when locating one class in a multidex APK.
pub fn class_descriptors(data: &[u8]) -> Result<Vec<String>> {
    class_descriptors_at(data, 0)
}

pub(crate) fn class_descriptors_at(data: &[u8], header_offset: usize) -> Result<Vec<String>> {
    let header = Header::parse_at(data, header_offset)?;
    let types = read_types(data, &header)?;
    let mut result = Vec::with_capacity(header.class_defs_size as usize);
    for index in 0..header.class_defs_size as usize {
        let class_idx = u32_at(data, header.class_defs_off as usize + index * 32)?;
        let string_idx = *types
            .get(class_idx as usize)
            .with_context(|| format!("class #{index} has invalid type index"))?;
        result.push(read_string(data, &header, string_idx as usize)?);
    }
    Ok(result)
}

/// Probe the sorted type table and then the class-def table without building a
/// full class index. This is the same on-demand path used by original ASC.
pub(crate) fn dex_defines_class_at(
    data: &[u8],
    header_offset: usize,
    target: &str,
) -> Result<bool> {
    let header = Header::parse_at(data, header_offset)?;
    if header.string_ids_size == 0 || header.type_ids_size == 0 {
        return Ok(false);
    }

    let target = target.as_bytes();
    let mut left = 0usize;
    let mut right = header.type_ids_size as usize;
    let mut target_type = None;
    while left < right {
        let middle = left + (right - left) / 2;
        let string_idx = u32_at(data, header.type_ids_off as usize + middle * 4)?;
        ensure!(
            string_idx < header.string_ids_size,
            "type #{middle} has invalid string index"
        );
        let mut string_offset = u32_at(
            data,
            header.string_ids_off as usize + string_idx as usize * 4,
        )? as usize;
        let _utf16_size = read_uleb(data, &mut string_offset)?;
        let tail = data
            .get(string_offset..)
            .with_context(|| format!("string #{string_idx} data offset is out of bounds"))?;
        let end = tail
            .iter()
            .position(|&byte| byte == 0)
            .map(|length| string_offset + length)
            .with_context(|| format!("unterminated DEX string #{string_idx}"))?;
        match data[string_offset..end].cmp(target) {
            std::cmp::Ordering::Less => left = middle + 1,
            std::cmp::Ordering::Greater => right = middle,
            std::cmp::Ordering::Equal => {
                target_type = Some(middle as u32);
                break;
            }
        }
    }
    let Some(target_type) = target_type else {
        return Ok(false);
    };

    for index in 0..header.class_defs_size as usize {
        if u32_at(data, header.class_defs_off as usize + index * 32)? == target_type {
            return Ok(true);
        }
    }
    Ok(false)
}

fn code_unit(bytes: &[u8], pc: usize) -> Result<u16> {
    let offset = pc.checked_mul(2).context("code unit offset overflow")?;
    let pair = get_bytes(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([pair[0], pair[1]]))
}

fn reference_index(kind: ReferenceKind, opcode: u8, bytes: &[u8], pc: usize) -> Option<u32> {
    let short = || code_unit(bytes, pc + 1).ok().map(u32::from);
    match kind {
        ReferenceKind::String if opcode == 0x1a => short(),
        ReferenceKind::String if opcode == 0x1b => Some(
            u32::from(code_unit(bytes, pc + 1).ok()?)
                | (u32::from(code_unit(bytes, pc + 2).ok()?) << 16),
        ),
        ReferenceKind::Type if matches!(opcode, 0x1c | 0x1f | 0x20 | 0x22..=0x25) => short(),
        ReferenceKind::Field if (0x52..=0x6d).contains(&opcode) => short(),
        ReferenceKind::Method if matches!(opcode, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb) => {
            short()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dex_format::instruction_width;

    #[test]
    fn decodes_modified_utf8() {
        assert_eq!(decode_mutf8(b"hello"), "hello");
        assert_eq!(decode_mutf8(&[0xc0, 0x80]), "\0");
        assert_eq!(decode_mutf8(&[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]), "😀");
    }

    #[test]
    fn understands_payload_widths() {
        for (units, expected) in [
            (vec![0x0100, 2, 0, 0, 0, 0, 0, 0], 8),
            (vec![0x0300, 1, 3, 0, 0, 0], 6),
        ] {
            let bytes = units
                .iter()
                .flat_map(|unit| u16::to_le_bytes(*unit))
                .collect::<Vec<_>>();
            assert_eq!(instruction_width(&units, 0).unwrap(), expected);
            assert_eq!(instruction_width_bytes(&bytes, 0).unwrap(), expected);
        }
    }

    #[test]
    fn reads_reference_operands_directly_from_dex_bytes() {
        let jumbo = [0x001b_u16, 0x5678, 0x1234]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            reference_index(ReferenceKind::String, 0x1b, &jumbo, 0),
            Some(0x1234_5678)
        );

        let invoke = [0x006e_u16, 0xabcd, 0]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            reference_index(ReferenceKind::Method, 0x6e, &invoke, 0),
            Some(0xabcd)
        );
    }

    #[test]
    fn batch_string_matcher_preserves_overlaps_duplicates_and_empty_queries() {
        let strings = ["abc", "zabcab", "other"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let patterns = ["ab", "abc", "ab", "", "no"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let matcher = StringBatchMatcher::new(&patterns).unwrap();

        assert_eq!(
            matcher.matching_indices(&strings),
            vec![vec![0, 1], vec![0, 1], vec![0, 1], vec![0, 1, 2], vec![]]
        );
    }
}

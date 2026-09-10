use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{Context, Result, ensure};

use crate::dex_format::{
    DexHeader as Header, FieldId, MethodId, ProtoId, bytes_at as get_bytes, instruction_width,
    read_field_ids, read_method_ids, read_proto_ids, read_string, read_strings, read_type_list,
    read_types, read_uleb, u32_at,
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
pub struct Dex<'a> {
    data: &'a [u8],
    header: Header,
    strings: Vec<String>,
    types: Vec<u32>,
    protos: Vec<ProtoId>,
    fields: Vec<FieldId>,
    methods: Vec<MethodId>,
    class_type_indices: Vec<u32>,
    code_items: Vec<CodeItem>,
}

impl<'a> Dex<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let header = Header::parse(data)?;
        let strings = read_strings(data, &header)?;
        let types = read_types(data, &header)?;
        let protos = read_proto_ids(data, &header)?;
        let fields = read_field_ids(data, &header)?;
        let methods = read_method_ids(data, &header)?;

        let mut class_type_indices = Vec::with_capacity(header.class_defs_size as usize);
        let mut class_data_offsets = Vec::with_capacity(header.class_defs_size as usize);
        for index in 0..header.class_defs_size as usize {
            let offset = header.class_defs_off as usize + index * 32;
            let class_idx = u32_at(data, offset)?;
            ensure!(
                class_idx < header.type_ids_size,
                "class #{index} has invalid type index"
            );
            class_type_indices.push(class_idx);
            class_data_offsets.push(u32_at(data, offset + 24)?);
        }

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
        let static_fields = read_uleb(self.data, &mut cursor)?;
        let instance_fields = read_uleb(self.data, &mut cursor)?;
        let direct_methods = read_uleb(self.data, &mut cursor)?;
        let virtual_methods = read_uleb(self.data, &mut cursor)?;

        for _ in 0..static_fields + instance_fields {
            let _field_idx_diff = read_uleb(self.data, &mut cursor)?;
            let _access_flags = read_uleb(self.data, &mut cursor)?;
        }

        for count in [direct_methods, virtual_methods] {
            let mut method_idx = 0u32;
            for _ in 0..count {
                method_idx = method_idx
                    .checked_add(read_uleb(self.data, &mut cursor)?)
                    .context("method index overflow in class_data_item")?;
                let _access_flags = read_uleb(self.data, &mut cursor)?;
                let code_offset = read_uleb(self.data, &mut cursor)? as usize;
                ensure!(
                    method_idx < self.header.method_ids_size,
                    "invalid encoded method index"
                );
                if code_offset == 0 {
                    continue;
                }
                let insns_size = u32_at(self.data, code_offset + 12)? as usize;
                let insns_offset = code_offset + 16;
                get_bytes(self.data, insns_offset, insns_size.saturating_mul(2))?;
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
        let mut results = Vec::new();
        if targets.is_empty() {
            return Ok(results);
        }
        for code in &self.code_items {
            let bytes = get_bytes(self.data, code.insns_offset, code.insns_size * 2)?;
            let mut units = Vec::with_capacity(code.insns_size);
            for pair in bytes.chunks_exact(2) {
                units.push(u16::from_le_bytes([pair[0], pair[1]]));
            }
            let mut pc = 0usize;
            while pc < units.len() {
                let opcode = (units[pc] & 0xff) as u8;
                if let Some(index) = reference_index(kind, opcode, &units, pc)
                    && targets.contains(&index)
                {
                    results.push(ReferenceSite {
                        caller_index: code.method_idx,
                        target_index: index,
                        code_unit_offset: pc as u32,
                    });
                }
                let width = instruction_width(&units, pc)?;
                ensure!(
                    width > 0 && pc + width <= units.len(),
                    "invalid instruction width at code unit {pc}"
                );
                pc += width;
            }
        }
        Ok(results)
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
        let method = self
            .methods
            .get(index as usize)
            .with_context(|| format!("invalid method index {index}"))?;
        let proto = self
            .protos
            .get(method.proto_idx as usize)
            .with_context(|| format!("invalid proto index {}", method.proto_idx))?;
        let parameters =
            read_type_list(self.data, proto.parameters_off, self.header.type_ids_size)?
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
    let header = Header::parse(data)?;
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

fn reference_index(kind: ReferenceKind, opcode: u8, units: &[u16], pc: usize) -> Option<u32> {
    let short = || units.get(pc + 1).copied().map(u32::from);
    match kind {
        ReferenceKind::String if opcode == 0x1a => short(),
        ReferenceKind::String if opcode == 0x1b => {
            Some(u32::from(*units.get(pc + 1)?) | (u32::from(*units.get(pc + 2)?) << 16))
        }
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

    #[test]
    fn decodes_modified_utf8() {
        assert_eq!(decode_mutf8(b"hello"), "hello");
        assert_eq!(decode_mutf8(&[0xc0, 0x80]), "\0");
        assert_eq!(decode_mutf8(&[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]), "😀");
    }

    #[test]
    fn understands_payload_widths() {
        assert_eq!(
            instruction_width(&[0x0100, 2, 0, 0, 0, 0, 0, 0], 0).unwrap(),
            8
        );
        assert_eq!(instruction_width(&[0x0300, 1, 3, 0, 0, 0], 0).unwrap(), 6);
    }
}

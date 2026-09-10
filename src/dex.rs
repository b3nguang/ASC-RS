use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{Context, Result, bail, ensure};

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
struct Table {
    size: u32,
    offset: u32,
    item_size: usize,
}

#[derive(Debug)]
struct Header {
    strings: Table,
    types: Table,
    fields: Table,
    methods: Table,
    classes: Table,
}

#[derive(Debug, Clone)]
struct FieldId {
    class_idx: u16,
    name_idx: u32,
}

#[derive(Debug, Clone)]
struct MethodId {
    class_idx: u16,
    name_idx: u32,
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
    fields: Vec<FieldId>,
    methods: Vec<MethodId>,
    class_type_indices: Vec<u32>,
    code_items: Vec<CodeItem>,
}

fn get_bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    data.get(offset..offset.saturating_add(size))
        .with_context(|| {
            format!(
                "DEX range 0x{offset:x}..0x{:x} is out of bounds",
                offset + size
            )
        })
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = get_bytes(data, offset, 2)?.try_into().unwrap();
    Ok(u16::from_le_bytes(bytes))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = get_bytes(data, offset, 4)?.try_into().unwrap();
    Ok(u32::from_le_bytes(bytes))
}

fn read_uleb128(data: &[u8], cursor: &mut usize) -> Result<u32> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = *data
            .get(*cursor)
            .with_context(|| format!("truncated ULEB128 at 0x{:x}", *cursor))?;
        *cursor += 1;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("invalid ULEB128 value")
}

fn decode_mutf8(data: &[u8]) -> String {
    let mut units = Vec::with_capacity(data.len());
    let mut cursor = 0;
    while cursor < data.len() {
        let b0 = data[cursor];
        if b0 & 0x80 == 0 {
            units.push(u16::from(b0));
            cursor += 1;
        } else if b0 & 0xe0 == 0xc0 && cursor + 1 < data.len() {
            let b1 = data[cursor + 1];
            units.push((u16::from(b0 & 0x1f) << 6) | u16::from(b1 & 0x3f));
            cursor += 2;
        } else if b0 & 0xf0 == 0xe0 && cursor + 2 < data.len() {
            let b1 = data[cursor + 1];
            let b2 = data[cursor + 2];
            units.push(
                (u16::from(b0 & 0x0f) << 12) | (u16::from(b1 & 0x3f) << 6) | u16::from(b2 & 0x3f),
            );
            cursor += 3;
        } else {
            units.push(0xfffd);
            cursor += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

impl Header {
    fn parse(data: &[u8]) -> Result<Self> {
        ensure!(data.len() >= 0x70, "DEX is shorter than its header");
        ensure!(&data[..4] == b"dex\n", "invalid DEX magic");
        ensure!(data[7] == 0, "invalid DEX version terminator");

        let table = |size_offset, offset_offset, item_size| -> Result<Table> {
            let result = Table {
                size: u32_at(data, size_offset)?,
                offset: u32_at(data, offset_offset)?,
                item_size,
            };
            let start = result.offset as usize;
            let bytes = result.size as usize * result.item_size;
            get_bytes(data, start, bytes)?;
            Ok(result)
        };
        Ok(Self {
            strings: table(0x38, 0x3c, 4)?,
            types: table(0x40, 0x44, 4)?,
            fields: table(0x50, 0x54, 8)?,
            methods: table(0x58, 0x5c, 8)?,
            classes: table(0x60, 0x64, 32)?,
        })
    }
}

impl<'a> Dex<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let header = Header::parse(data)?;

        let mut strings = Vec::with_capacity(header.strings.size as usize);
        for index in 0..header.strings.size as usize {
            let id_offset = header.strings.offset as usize + index * 4;
            let mut cursor = u32_at(data, id_offset)? as usize;
            let _utf16_size = read_uleb128(data, &mut cursor)?;
            let end = data[cursor..]
                .iter()
                .position(|&byte| byte == 0)
                .map(|length| cursor + length)
                .with_context(|| format!("unterminated DEX string #{index}"))?;
            strings.push(decode_mutf8(&data[cursor..end]));
        }

        let mut types = Vec::with_capacity(header.types.size as usize);
        for index in 0..header.types.size as usize {
            let string_idx = u32_at(data, header.types.offset as usize + index * 4)?;
            ensure!(
                string_idx < header.strings.size,
                "type #{index} has invalid string index"
            );
            types.push(string_idx);
        }

        let mut fields = Vec::with_capacity(header.fields.size as usize);
        for index in 0..header.fields.size as usize {
            let offset = header.fields.offset as usize + index * 8;
            let class_idx = u16_at(data, offset)?;
            let name_idx = u32_at(data, offset + 4)?;
            ensure!(
                u32::from(class_idx) < header.types.size,
                "field #{index} has invalid class index"
            );
            ensure!(
                name_idx < header.strings.size,
                "field #{index} has invalid name index"
            );
            fields.push(FieldId {
                class_idx,
                name_idx,
            });
        }

        let mut methods = Vec::with_capacity(header.methods.size as usize);
        for index in 0..header.methods.size as usize {
            let offset = header.methods.offset as usize + index * 8;
            let class_idx = u16_at(data, offset)?;
            let name_idx = u32_at(data, offset + 4)?;
            ensure!(
                u32::from(class_idx) < header.types.size,
                "method #{index} has invalid class index"
            );
            ensure!(
                name_idx < header.strings.size,
                "method #{index} has invalid name index"
            );
            methods.push(MethodId {
                class_idx,
                name_idx,
            });
        }

        let mut class_type_indices = Vec::with_capacity(header.classes.size as usize);
        let mut class_data_offsets = Vec::with_capacity(header.classes.size as usize);
        for index in 0..header.classes.size as usize {
            let offset = header.classes.offset as usize + index * 32;
            let class_idx = u32_at(data, offset)?;
            ensure!(
                class_idx < header.types.size,
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
        let static_fields = read_uleb128(self.data, &mut cursor)?;
        let instance_fields = read_uleb128(self.data, &mut cursor)?;
        let direct_methods = read_uleb128(self.data, &mut cursor)?;
        let virtual_methods = read_uleb128(self.data, &mut cursor)?;

        for _ in 0..static_fields + instance_fields {
            let _field_idx_diff = read_uleb128(self.data, &mut cursor)?;
            let _access_flags = read_uleb128(self.data, &mut cursor)?;
        }

        for count in [direct_methods, virtual_methods] {
            let mut method_idx = 0u32;
            for _ in 0..count {
                method_idx = method_idx
                    .checked_add(read_uleb128(self.data, &mut cursor)?)
                    .context("method index overflow in class_data_item")?;
                let _access_flags = read_uleb128(self.data, &mut cursor)?;
                let code_offset = read_uleb128(self.data, &mut cursor)? as usize;
                ensure!(
                    method_idx < self.header.methods.size,
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

    pub fn scan_references(
        &self,
        kind: ReferenceKind,
        targets: &HashSet<u32>,
    ) -> Result<BTreeMap<u32, BTreeSet<u32>>> {
        let mut results: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
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
                    results.entry(code.method_idx).or_default().insert(index);
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

    pub fn format_method(&self, index: u32) -> String {
        let method = &self.methods[index as usize];
        format!(
            "{}->{}",
            self.type_descriptor(u32::from(method.class_idx)),
            self.strings[method.name_idx as usize]
        )
    }

    pub fn format_match(&self, kind: ReferenceKind, index: u32) -> String {
        match kind {
            ReferenceKind::String => self.strings[index as usize].clone(),
            ReferenceKind::Type => self.type_descriptor(index).to_owned(),
            ReferenceKind::Method => self.format_method(index),
            ReferenceKind::Field => {
                let field = &self.fields[index as usize];
                format!(
                    "{}->{}",
                    self.type_descriptor(u32::from(field.class_idx)),
                    self.strings[field.name_idx as usize]
                )
            }
        }
    }
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

fn instruction_width(units: &[u16], pc: usize) -> Result<usize> {
    let unit = *units.get(pc).context("instruction starts past code item")?;
    let opcode = (unit & 0xff) as u8;
    if opcode == 0 {
        return match unit >> 8 {
            0 => Ok(1),
            1 => {
                let size = usize::from(
                    *units
                        .get(pc + 1)
                        .context("truncated packed-switch payload")?,
                );
                Ok(4 + size * 2)
            }
            2 => {
                let size = usize::from(
                    *units
                        .get(pc + 1)
                        .context("truncated sparse-switch payload")?,
                );
                Ok(2 + size * 4)
            }
            3 => {
                let element_width =
                    usize::from(*units.get(pc + 1).context("truncated fill-array payload")?);
                let low = u32::from(*units.get(pc + 2).context("truncated fill-array payload")?);
                let high = u32::from(*units.get(pc + 3).context("truncated fill-array payload")?);
                let size =
                    usize::try_from(low | (high << 16)).context("fill-array size overflow")?;
                Ok(4 + element_width.saturating_mul(size).div_ceil(2))
            }
            ident => bail!("unknown DEX payload identifier 0x{ident:02x}"),
        };
    }

    let width = match opcode {
        0x01
        | 0x04
        | 0x07
        | 0x0a..=0x12
        | 0x1d..=0x1e
        | 0x21
        | 0x27..=0x28
        | 0x3e..=0x43
        | 0x73
        | 0x79..=0x8f
        | 0xb0..=0xcf
        | 0xe3..=0xf9 => 1,
        0x02
        | 0x05
        | 0x08
        | 0x13
        | 0x15..=0x16
        | 0x19..=0x1a
        | 0x1c
        | 0x1f..=0x20
        | 0x22..=0x23
        | 0x29
        | 0x2d..=0x3d
        | 0x44..=0x6d
        | 0x90..=0xaf
        | 0xd0..=0xe2
        | 0xfe..=0xff => 2,
        0x03
        | 0x06
        | 0x09
        | 0x14
        | 0x17
        | 0x1b
        | 0x24..=0x26
        | 0x2a..=0x2c
        | 0x6e..=0x72
        | 0x74..=0x78
        | 0xfc..=0xfd => 3,
        0xfa..=0xfb => 4,
        0x18 => 5,
        // opcode 0 is handled above, including payload pseudo-instructions.
        0x00 => unreachable!(),
    };
    Ok(width)
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

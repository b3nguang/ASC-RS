//! Build the same one-class, dependency-closed DEX used by ASC before
//! decompilation. The output is intentionally self-contained: bytecode
//! references, metadata references, try/catch types, and all ID tables are
//! remapped to dense indices.

use adler2::adler32_slice;
use anyhow::{Context, Result, bail, ensure};
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const NO_INDEX: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
struct Header {
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    proto_ids_size: u32,
    proto_ids_off: u32,
    field_ids_size: u32,
    field_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
    class_defs_off: u32,
}

#[derive(Debug, Clone, Copy)]
struct ProtoId {
    shorty_idx: u32,
    return_type_idx: u32,
    parameters_off: u32,
}

#[derive(Debug, Clone, Copy)]
struct FieldId {
    class_idx: u16,
    type_idx: u16,
    name_idx: u32,
}

#[derive(Debug, Clone, Copy)]
struct MethodId {
    class_idx: u16,
    proto_idx: u16,
    name_idx: u32,
}

#[derive(Debug, Clone, Copy)]
struct ClassDef {
    class_idx: u32,
    access_flags: u32,
    superclass_idx: u32,
    interfaces_off: u32,
    source_file_idx: u32,
    annotations_off: u32,
    class_data_off: u32,
    static_values_off: u32,
}

#[derive(Debug, Clone, Copy)]
struct EncodedField {
    field_idx: u32,
    access_flags: u32,
}

#[derive(Debug, Clone, Copy)]
struct EncodedMethod {
    method_idx: u32,
    access_flags: u32,
    code_off: u32,
}

#[derive(Debug, Default)]
struct ClassData {
    static_fields: Vec<EncodedField>,
    instance_fields: Vec<EncodedField>,
    direct_methods: Vec<EncodedMethod>,
    virtual_methods: Vec<EncodedMethod>,
}

impl ClassData {
    fn fields(&self) -> impl Iterator<Item = &EncodedField> {
        self.static_fields.iter().chain(&self.instance_fields)
    }

    fn methods(&self) -> impl Iterator<Item = &EncodedMethod> {
        self.direct_methods.iter().chain(&self.virtual_methods)
    }
}

#[derive(Debug, Clone)]
struct TryItem {
    start_addr: u32,
    insn_count: u16,
    handler_off: u16,
}

#[derive(Debug, Clone)]
struct CatchHandler {
    old_offset: u16,
    size: i32,
    pairs: Vec<(u32, u32)>,
    catch_all_addr: Option<u32>,
}

#[derive(Debug, Clone)]
struct CodeItem {
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    tries_size: u16,
    debug_info_off: u32,
    insns: Vec<u8>,
    tries: Vec<TryItem>,
    handlers: Vec<CatchHandler>,
}

#[derive(Debug, Clone)]
enum EncodedValue {
    Indexed(IndexKind, u32),
    Array(Vec<EncodedValue>),
    Annotation(EncodedAnnotation),
    Null,
    Boolean(u8),
    Primitive(u8, Vec<u8>),
}

#[derive(Debug, Clone)]
struct EncodedAnnotation {
    type_idx: u32,
    elements: Vec<(u32, EncodedValue)>,
}

#[derive(Debug, Clone)]
struct AnnotationItem {
    visibility: u8,
    annotation: EncodedAnnotation,
}

#[derive(Debug, Clone, Copy)]
enum DebugOp {
    End,
    AdvancePc(u32),
    AdvanceLine(i32),
    StartLocal(u32, u32, u32),
    StartLocalExtended(u32, u32, u32, u32),
    EndOrRestartLocal(u8, u32),
    SetFile(u32),
    Plain(u8),
}

#[derive(Debug, Clone)]
struct DebugInfo {
    line_start: u32,
    parameter_names: Vec<u32>,
    ops: Vec<DebugOp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexKind {
    String,
    Type,
    Field,
    Method,
}

#[derive(Debug, Default)]
struct OrderedIds {
    values: Vec<u32>,
    reverse: HashMap<u32, u32>,
}

impl OrderedIds {
    fn insert(&mut self, old: u32) -> u32 {
        if let Some(&new) = self.reverse.get(&old) {
            return new;
        }
        let new = self.values.len() as u32;
        self.values.push(old);
        self.reverse.insert(old, new);
        new
    }
}

#[derive(Debug, Default)]
struct BytecodeRefs {
    strings: OrderedIds,
    types: OrderedIds,
    protos: OrderedIds,
    fields: OrderedIds,
    methods: OrderedIds,
}

#[derive(Debug, Clone)]
struct NewProto {
    shorty_idx: u32,
    return_type_idx: u32,
    params: Vec<u16>,
}

#[derive(Debug, Clone, Copy)]
struct NewField {
    class_idx: u16,
    type_idx: u16,
    name_idx: u32,
}

#[derive(Debug, Clone, Copy)]
struct NewMethod {
    class_idx: u16,
    proto_idx: u16,
    name_idx: u32,
}

#[derive(Debug)]
struct DexView<'a> {
    data: &'a [u8],
    header: Header,
    strings: Vec<String>,
    type_descriptor_indices: Vec<u32>,
    protos: Vec<ProtoId>,
    fields: Vec<FieldId>,
    methods: Vec<MethodId>,
}

fn bytes_at(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    data.get(offset..offset.saturating_add(size))
        .with_context(|| {
            format!(
                "DEX range 0x{offset:x}..0x{:x} is out of bounds",
                offset + size
            )
        })
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes_at(data, offset, 2)?.try_into().unwrap(),
    ))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes_at(data, offset, 4)?.try_into().unwrap(),
    ))
}

fn read_uleb(data: &[u8], cursor: &mut usize) -> Result<u32> {
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
    bail!("invalid ULEB128")
}

fn read_sleb(data: &[u8], cursor: &mut usize) -> Result<i32> {
    let mut value = 0i32;
    let mut shift = 0;
    loop {
        ensure!(shift < 35, "invalid SLEB128");
        let byte = *data
            .get(*cursor)
            .with_context(|| format!("truncated SLEB128 at 0x{:x}", *cursor))?;
        *cursor += 1;
        value |= i32::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 32 && byte & 0x40 != 0 {
                value |= !0 << shift;
            }
            return Ok(value);
        }
    }
}

fn write_uleb(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn write_sleb(mut value: i32, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        let sign = byte & 0x40 != 0;
        value >>= 7;
        let done = (value == 0 && !sign) || (value == -1 && sign);
        out.push(if done { byte } else { byte | 0x80 });
        if done {
            break;
        }
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn patch_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn align4(out: &mut Vec<u8>) {
    while out.len() & 3 != 0 {
        out.push(0);
    }
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
            units.push((u16::from(b0 & 0x1f) << 6) | u16::from(data[cursor + 1] & 0x3f));
            cursor += 2;
        } else if b0 & 0xf0 == 0xe0 && cursor + 2 < data.len() {
            units.push(
                (u16::from(b0 & 0x0f) << 12)
                    | (u16::from(data[cursor + 1] & 0x3f) << 6)
                    | u16::from(data[cursor + 2] & 0x3f),
            );
            cursor += 3;
        } else {
            units.push(0xfffd);
            cursor += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

fn write_mutf8(value: &str, out: &mut Vec<u8>) {
    write_uleb(value.encode_utf16().count() as u32, out);
    for unit in value.encode_utf16() {
        match unit {
            0 => out.extend_from_slice(&[0xc0, 0x80]),
            0x01..=0x7f => out.push(unit as u8),
            0x80..=0x7ff => {
                out.push(0xc0 | (unit >> 6) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
            _ => {
                out.push(0xe0 | (unit >> 12) as u8);
                out.push(0x80 | ((unit >> 6) & 0x3f) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
        }
    }
    out.push(0);
}

impl Header {
    fn parse(data: &[u8]) -> Result<Self> {
        ensure!(data.len() >= 0x70, "DEX is shorter than its header");
        ensure!(&data[..4] == b"dex\n", "invalid DEX magic");
        Ok(Self {
            string_ids_size: u32_at(data, 0x38)?,
            string_ids_off: u32_at(data, 0x3c)?,
            type_ids_size: u32_at(data, 0x40)?,
            type_ids_off: u32_at(data, 0x44)?,
            proto_ids_size: u32_at(data, 0x48)?,
            proto_ids_off: u32_at(data, 0x4c)?,
            field_ids_size: u32_at(data, 0x50)?,
            field_ids_off: u32_at(data, 0x54)?,
            method_ids_size: u32_at(data, 0x58)?,
            method_ids_off: u32_at(data, 0x5c)?,
            class_defs_size: u32_at(data, 0x60)?,
            class_defs_off: u32_at(data, 0x64)?,
        })
    }
}

impl<'a> DexView<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        let header = Header::parse(data)?;
        bytes_at(
            data,
            header.string_ids_off as usize,
            header.string_ids_size as usize * 4,
        )?;
        bytes_at(
            data,
            header.type_ids_off as usize,
            header.type_ids_size as usize * 4,
        )?;
        bytes_at(
            data,
            header.proto_ids_off as usize,
            header.proto_ids_size as usize * 12,
        )?;
        bytes_at(
            data,
            header.field_ids_off as usize,
            header.field_ids_size as usize * 8,
        )?;
        bytes_at(
            data,
            header.method_ids_off as usize,
            header.method_ids_size as usize * 8,
        )?;
        bytes_at(
            data,
            header.class_defs_off as usize,
            header.class_defs_size as usize * 32,
        )?;

        let mut strings = Vec::with_capacity(header.string_ids_size as usize);
        for index in 0..header.string_ids_size as usize {
            let mut cursor = u32_at(data, header.string_ids_off as usize + index * 4)? as usize;
            let _utf16_len = read_uleb(data, &mut cursor)?;
            let end = data[cursor..]
                .iter()
                .position(|&byte| byte == 0)
                .map(|length| cursor + length)
                .with_context(|| format!("unterminated string #{index}"))?;
            strings.push(decode_mutf8(&data[cursor..end]));
        }

        let mut type_descriptor_indices = Vec::with_capacity(header.type_ids_size as usize);
        for index in 0..header.type_ids_size as usize {
            let value = u32_at(data, header.type_ids_off as usize + index * 4)?;
            ensure!(
                value < header.string_ids_size,
                "invalid type descriptor index"
            );
            type_descriptor_indices.push(value);
        }

        let mut protos = Vec::with_capacity(header.proto_ids_size as usize);
        for index in 0..header.proto_ids_size as usize {
            let offset = header.proto_ids_off as usize + index * 12;
            protos.push(ProtoId {
                shorty_idx: u32_at(data, offset)?,
                return_type_idx: u32_at(data, offset + 4)?,
                parameters_off: u32_at(data, offset + 8)?,
            });
        }

        let mut fields = Vec::with_capacity(header.field_ids_size as usize);
        for index in 0..header.field_ids_size as usize {
            let offset = header.field_ids_off as usize + index * 8;
            fields.push(FieldId {
                class_idx: u16_at(data, offset)?,
                type_idx: u16_at(data, offset + 2)?,
                name_idx: u32_at(data, offset + 4)?,
            });
        }

        let mut methods = Vec::with_capacity(header.method_ids_size as usize);
        for index in 0..header.method_ids_size as usize {
            let offset = header.method_ids_off as usize + index * 8;
            methods.push(MethodId {
                class_idx: u16_at(data, offset)?,
                proto_idx: u16_at(data, offset + 2)?,
                name_idx: u32_at(data, offset + 4)?,
            });
        }

        Ok(Self {
            data,
            header,
            strings,
            type_descriptor_indices,
            protos,
            fields,
            methods,
        })
    }

    fn type_descriptor(&self, index: u32) -> Result<&str> {
        let string_idx = *self
            .type_descriptor_indices
            .get(index as usize)
            .with_context(|| format!("invalid type index {index}"))?;
        self.strings
            .get(string_idx as usize)
            .map(String::as_str)
            .with_context(|| format!("invalid descriptor string index {string_idx}"))
    }

    fn class_def(&self, index: usize) -> Result<ClassDef> {
        ensure!(
            index < self.header.class_defs_size as usize,
            "invalid class index"
        );
        let offset = self.header.class_defs_off as usize + index * 32;
        Ok(ClassDef {
            class_idx: u32_at(self.data, offset)?,
            access_flags: u32_at(self.data, offset + 4)?,
            superclass_idx: u32_at(self.data, offset + 8)?,
            interfaces_off: u32_at(self.data, offset + 12)?,
            source_file_idx: u32_at(self.data, offset + 16)?,
            annotations_off: u32_at(self.data, offset + 20)?,
            class_data_off: u32_at(self.data, offset + 24)?,
            static_values_off: u32_at(self.data, offset + 28)?,
        })
    }

    fn find_class(&self, descriptor: &str) -> Result<Option<ClassDef>> {
        for index in 0..self.header.class_defs_size as usize {
            let class = self.class_def(index)?;
            if self.type_descriptor(class.class_idx)? == descriptor {
                return Ok(Some(class));
            }
        }
        Ok(None)
    }

    fn type_list(&self, offset: u32) -> Result<Vec<u16>> {
        if offset == 0 {
            return Ok(Vec::new());
        }
        let size = u32_at(self.data, offset as usize)? as usize;
        let mut result = Vec::with_capacity(size);
        for index in 0..size {
            result.push(u16_at(self.data, offset as usize + 4 + index * 2)?);
        }
        Ok(result)
    }

    fn class_data(&self, offset: u32) -> Result<ClassData> {
        if offset == 0 {
            return Ok(ClassData::default());
        }
        let mut cursor = offset as usize;
        let static_count = read_uleb(self.data, &mut cursor)?;
        let instance_count = read_uleb(self.data, &mut cursor)?;
        let direct_count = read_uleb(self.data, &mut cursor)?;
        let virtual_count = read_uleb(self.data, &mut cursor)?;

        fn fields(data: &[u8], cursor: &mut usize, count: u32) -> Result<Vec<EncodedField>> {
            let mut result = Vec::with_capacity(count as usize);
            let mut field_idx = 0u32;
            for _ in 0..count {
                field_idx = field_idx
                    .checked_add(read_uleb(data, cursor)?)
                    .context("field index overflow")?;
                result.push(EncodedField {
                    field_idx,
                    access_flags: read_uleb(data, cursor)?,
                });
            }
            Ok(result)
        }

        fn methods(data: &[u8], cursor: &mut usize, count: u32) -> Result<Vec<EncodedMethod>> {
            let mut result = Vec::with_capacity(count as usize);
            let mut method_idx = 0u32;
            for _ in 0..count {
                method_idx = method_idx
                    .checked_add(read_uleb(data, cursor)?)
                    .context("method index overflow")?;
                result.push(EncodedMethod {
                    method_idx,
                    access_flags: read_uleb(data, cursor)?,
                    code_off: read_uleb(data, cursor)?,
                });
            }
            Ok(result)
        }

        Ok(ClassData {
            static_fields: fields(self.data, &mut cursor, static_count)?,
            instance_fields: fields(self.data, &mut cursor, instance_count)?,
            direct_methods: methods(self.data, &mut cursor, direct_count)?,
            virtual_methods: methods(self.data, &mut cursor, virtual_count)?,
        })
    }

    fn code_item(&self, offset: u32) -> Result<CodeItem> {
        let offset = offset as usize;
        let registers_size = u16_at(self.data, offset)?;
        let ins_size = u16_at(self.data, offset + 2)?;
        let outs_size = u16_at(self.data, offset + 4)?;
        let tries_size = u16_at(self.data, offset + 6)?;
        let debug_info_off = u32_at(self.data, offset + 8)?;
        let insns_size = u32_at(self.data, offset + 12)? as usize;
        let insns = bytes_at(self.data, offset + 16, insns_size * 2)?.to_vec();
        let mut tries = Vec::new();
        let mut handlers = Vec::new();
        if tries_size != 0 {
            let tries_off = (offset + 16 + insns_size * 2 + 3) & !3;
            for index in 0..tries_size as usize {
                let pos = tries_off + index * 8;
                tries.push(TryItem {
                    start_addr: u32_at(self.data, pos)?,
                    insn_count: u16_at(self.data, pos + 4)?,
                    handler_off: u16_at(self.data, pos + 6)?,
                });
            }
            let handlers_base = tries_off + tries_size as usize * 8;
            let mut cursor = handlers_base;
            let count = read_uleb(self.data, &mut cursor)?;
            for _ in 0..count {
                let old_offset = u16::try_from(cursor - handlers_base)
                    .context("catch handler offset exceeds 16 bits")?;
                let size = read_sleb(self.data, &mut cursor)?;
                let mut pairs = Vec::with_capacity(size.unsigned_abs() as usize);
                for _ in 0..size.unsigned_abs() {
                    pairs.push((
                        read_uleb(self.data, &mut cursor)?,
                        read_uleb(self.data, &mut cursor)?,
                    ));
                }
                let catch_all_addr = if size <= 0 {
                    Some(read_uleb(self.data, &mut cursor)?)
                } else {
                    None
                };
                handlers.push(CatchHandler {
                    old_offset,
                    size,
                    pairs,
                    catch_all_addr,
                });
            }
        }
        Ok(CodeItem {
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns,
            tries,
            handlers,
        })
    }
}

fn instruction_width(units: &[u16], pc: usize) -> Result<usize> {
    let unit = *units.get(pc).context("instruction starts past code item")?;
    let opcode = (unit & 0xff) as u8;
    if opcode == 0 {
        return match unit >> 8 {
            0 => Ok(1),
            1 => {
                let size = usize::from(*units.get(pc + 1).context("truncated packed-switch")?);
                Ok(4 + size * 2)
            }
            2 => {
                let size = usize::from(*units.get(pc + 1).context("truncated sparse-switch")?);
                Ok(2 + size * 4)
            }
            3 => {
                let width = usize::from(*units.get(pc + 1).context("truncated array payload")?);
                let low = u32::from(*units.get(pc + 2).context("truncated array payload")?);
                let high = u32::from(*units.get(pc + 3).context("truncated array payload")?);
                let count = usize::try_from(low | (high << 16)).context("array size overflow")?;
                Ok(4 + width.saturating_mul(count).div_ceil(2))
            }
            ident => bail!("unknown DEX payload identifier 0x{ident:02x}"),
        };
    }
    Ok(match opcode {
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
        0x00 => unreachable!(),
    })
}

fn remap_code_indices(code: &mut CodeItem, refs: &mut BytecodeRefs) -> Result<()> {
    let mut units = code
        .insns
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    ensure!(
        units.len() * 2 == code.insns.len(),
        "odd instruction byte count"
    );
    let mut pc = 0usize;
    while pc < units.len() {
        let opcode = (units[pc] & 0xff) as u8;
        let short_index = |units: &[u16], pc: usize| -> Result<u32> {
            Ok(u32::from(
                *units.get(pc + 1).context("truncated indexed instruction")?,
            ))
        };
        match opcode {
            0x1a => {
                let old = short_index(&units, pc)?;
                units[pc + 1] = refs.strings.insert(old) as u16;
            }
            0x1b => {
                let low = u32::from(*units.get(pc + 1).context("truncated const-string/jumbo")?);
                let high = u32::from(*units.get(pc + 2).context("truncated const-string/jumbo")?);
                let new = refs.strings.insert(low | (high << 16));
                units[pc + 1] = new as u16;
                units[pc + 2] = (new >> 16) as u16;
            }
            0x1c | 0x1f | 0x20 | 0x22..=0x25 => {
                let old = short_index(&units, pc)?;
                units[pc + 1] = refs.types.insert(old) as u16;
            }
            0x52..=0x6d => {
                let old = short_index(&units, pc)?;
                units[pc + 1] = refs.fields.insert(old) as u16;
            }
            0x6e..=0x72 | 0x74..=0x78 => {
                let old = short_index(&units, pc)?;
                units[pc + 1] = refs.methods.insert(old) as u16;
            }
            0xfa..=0xfb => {
                let old_method = short_index(&units, pc)?;
                units[pc + 1] = refs.methods.insert(old_method) as u16;
                let old_proto =
                    u32::from(*units.get(pc + 3).context("truncated invoke-polymorphic")?);
                units[pc + 3] = refs.protos.insert(old_proto) as u16;
            }
            0xff => {
                let old_proto = short_index(&units, pc)?;
                units[pc + 1] = refs.protos.insert(old_proto) as u16;
            }
            0xfc..=0xfe => bail!(
                "class uses call-site or method-handle opcode 0x{opcode:02x}, which ASC's minimal DEX format cannot represent"
            ),
            _ => {}
        }
        let width = instruction_width(&units, pc)?;
        ensure!(
            width != 0 && pc + width <= units.len(),
            "invalid instruction width"
        );
        pc += width;
    }
    code.insns.clear();
    for unit in units {
        code.insns.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

#[derive(Debug, Default)]
struct MetadataRefs {
    strings: BTreeSet<u32>,
    types: BTreeSet<u32>,
    fields: BTreeSet<u32>,
    methods: BTreeSet<u32>,
}

fn parse_encoded_value(
    data: &[u8],
    cursor: &mut usize,
    refs: &mut MetadataRefs,
) -> Result<EncodedValue> {
    let header = *data.get(*cursor).context("truncated encoded_value")?;
    *cursor += 1;
    let value_type = header & 0x1f;
    let value_arg = header >> 5;
    match value_type {
        0x17..=0x1b => {
            let size = usize::from(value_arg) + 1;
            let bytes = bytes_at(data, *cursor, size)?;
            *cursor += size;
            let old = bytes.iter().enumerate().fold(0u32, |value, (shift, byte)| {
                value | (u32::from(*byte) << (shift * 8))
            });
            let kind = match value_type {
                0x17 => {
                    refs.strings.insert(old);
                    IndexKind::String
                }
                0x18 => {
                    refs.types.insert(old);
                    IndexKind::Type
                }
                0x19 | 0x1b => {
                    refs.fields.insert(old);
                    IndexKind::Field
                }
                0x1a => {
                    refs.methods.insert(old);
                    IndexKind::Method
                }
                _ => unreachable!(),
            };
            Ok(EncodedValue::Indexed(kind, old))
        }
        0x1c => {
            let count = read_uleb(data, cursor)?;
            let mut values = Vec::with_capacity(count as usize);
            for _ in 0..count {
                values.push(parse_encoded_value(data, cursor, refs)?);
            }
            Ok(EncodedValue::Array(values))
        }
        0x1d => Ok(EncodedValue::Annotation(parse_encoded_annotation(
            data, cursor, refs,
        )?)),
        0x1e => Ok(EncodedValue::Null),
        0x1f => Ok(EncodedValue::Boolean(value_arg)),
        _ => {
            let size = usize::from(value_arg) + 1;
            let value = bytes_at(data, *cursor, size)?.to_vec();
            *cursor += size;
            Ok(EncodedValue::Primitive(value_type, value))
        }
    }
}

fn parse_encoded_annotation(
    data: &[u8],
    cursor: &mut usize,
    refs: &mut MetadataRefs,
) -> Result<EncodedAnnotation> {
    let type_idx = read_uleb(data, cursor)?;
    refs.types.insert(type_idx);
    let count = read_uleb(data, cursor)?;
    let mut elements = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name_idx = read_uleb(data, cursor)?;
        refs.strings.insert(name_idx);
        elements.push((name_idx, parse_encoded_value(data, cursor, refs)?));
    }
    Ok(EncodedAnnotation { type_idx, elements })
}

fn parse_encoded_array(
    data: &[u8],
    offset: u32,
    refs: &mut MetadataRefs,
) -> Result<Vec<EncodedValue>> {
    let mut cursor = offset as usize;
    let count = read_uleb(data, &mut cursor)?;
    let mut values = Vec::with_capacity(count as usize);
    for _ in 0..count {
        values.push(parse_encoded_value(data, &mut cursor, refs)?);
    }
    Ok(values)
}

fn parse_debug_info(data: &[u8], offset: u32, refs: &mut MetadataRefs) -> Result<DebugInfo> {
    let mut cursor = offset as usize;
    let line_start = read_uleb(data, &mut cursor)?;
    let count = read_uleb(data, &mut cursor)?;
    let mut parameter_names = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let value = read_uleb(data, &mut cursor)?;
        if value != 0 {
            refs.strings.insert(value - 1);
        }
        parameter_names.push(value);
    }
    let mut ops = Vec::new();
    loop {
        let opcode = *data.get(cursor).context("truncated debug_info_item")?;
        cursor += 1;
        let op = match opcode {
            0x00 => {
                ops.push(DebugOp::End);
                break;
            }
            0x01 => DebugOp::AdvancePc(read_uleb(data, &mut cursor)?),
            0x02 => DebugOp::AdvanceLine(read_sleb(data, &mut cursor)?),
            0x03 => {
                let register = read_uleb(data, &mut cursor)?;
                let name = read_uleb(data, &mut cursor)?;
                let typ = read_uleb(data, &mut cursor)?;
                if name != 0 {
                    refs.strings.insert(name - 1);
                }
                if typ != 0 {
                    refs.types.insert(typ - 1);
                }
                DebugOp::StartLocal(register, name, typ)
            }
            0x04 => {
                let register = read_uleb(data, &mut cursor)?;
                let name = read_uleb(data, &mut cursor)?;
                let typ = read_uleb(data, &mut cursor)?;
                let signature = read_uleb(data, &mut cursor)?;
                if name != 0 {
                    refs.strings.insert(name - 1);
                }
                if typ != 0 {
                    refs.types.insert(typ - 1);
                }
                if signature != 0 {
                    refs.strings.insert(signature - 1);
                }
                DebugOp::StartLocalExtended(register, name, typ, signature)
            }
            0x05 | 0x06 => DebugOp::EndOrRestartLocal(opcode, read_uleb(data, &mut cursor)?),
            0x09 => {
                let name = read_uleb(data, &mut cursor)?;
                if name != 0 {
                    refs.strings.insert(name - 1);
                }
                DebugOp::SetFile(name)
            }
            _ => DebugOp::Plain(opcode),
        };
        ops.push(op);
    }
    Ok(DebugInfo {
        line_start,
        parameter_names,
        ops,
    })
}

#[derive(Debug, Clone)]
struct AnnotationSet {
    item_offsets: Vec<u32>,
}

#[derive(Debug, Clone)]
struct AnnotationDirectory {
    class_annotations_off: u32,
    field_annotations: Vec<(u32, u32)>,
    method_annotations: Vec<(u32, u32)>,
    parameter_annotations: Vec<(u32, u32)>,
}

#[derive(Debug, Default)]
struct Annotations {
    directory: Option<AnnotationDirectory>,
    sets: BTreeMap<u32, AnnotationSet>,
    set_refs: BTreeMap<u32, Vec<u32>>,
    items: BTreeMap<u32, AnnotationItem>,
}

impl Annotations {
    fn parse(data: &[u8], offset: u32, refs: &mut MetadataRefs) -> Result<Self> {
        if offset == 0 {
            return Ok(Self::default());
        }
        let class_annotations_off = u32_at(data, offset as usize)?;
        let field_count = u32_at(data, offset as usize + 4)?;
        let method_count = u32_at(data, offset as usize + 8)?;
        let parameter_count = u32_at(data, offset as usize + 12)?;
        let mut result = Self::default();
        result.parse_set(data, class_annotations_off, refs)?;
        let mut cursor = offset as usize + 16;
        let mut field_annotations = Vec::with_capacity(field_count as usize);
        for _ in 0..field_count {
            let field_idx = u32_at(data, cursor)?;
            let set_off = u32_at(data, cursor + 4)?;
            cursor += 8;
            refs.fields.insert(field_idx);
            result.parse_set(data, set_off, refs)?;
            field_annotations.push((field_idx, set_off));
        }
        let mut method_annotations = Vec::with_capacity(method_count as usize);
        for _ in 0..method_count {
            let method_idx = u32_at(data, cursor)?;
            let set_off = u32_at(data, cursor + 4)?;
            cursor += 8;
            refs.methods.insert(method_idx);
            result.parse_set(data, set_off, refs)?;
            method_annotations.push((method_idx, set_off));
        }
        let mut parameter_annotations = Vec::with_capacity(parameter_count as usize);
        for _ in 0..parameter_count {
            let method_idx = u32_at(data, cursor)?;
            let refs_off = u32_at(data, cursor + 4)?;
            cursor += 8;
            refs.methods.insert(method_idx);
            result.parse_set_ref(data, refs_off, refs)?;
            parameter_annotations.push((method_idx, refs_off));
        }
        result.directory = Some(AnnotationDirectory {
            class_annotations_off,
            field_annotations,
            method_annotations,
            parameter_annotations,
        });
        Ok(result)
    }

    fn parse_set(&mut self, data: &[u8], offset: u32, refs: &mut MetadataRefs) -> Result<()> {
        if offset == 0 || self.sets.contains_key(&offset) {
            return Ok(());
        }
        let count = u32_at(data, offset as usize)?;
        let mut item_offsets = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            let item_off = u32_at(data, offset as usize + 4 + index * 4)?;
            item_offsets.push(item_off);
            if item_off != 0 && !self.items.contains_key(&item_off) {
                let visibility = *data
                    .get(item_off as usize)
                    .context("truncated annotation_item")?;
                let mut cursor = item_off as usize + 1;
                let annotation = parse_encoded_annotation(data, &mut cursor, refs)?;
                self.items.insert(
                    item_off,
                    AnnotationItem {
                        visibility,
                        annotation,
                    },
                );
            }
        }
        self.sets.insert(offset, AnnotationSet { item_offsets });
        Ok(())
    }

    fn parse_set_ref(&mut self, data: &[u8], offset: u32, refs: &mut MetadataRefs) -> Result<()> {
        if offset == 0 || self.set_refs.contains_key(&offset) {
            return Ok(());
        }
        let count = u32_at(data, offset as usize)?;
        let mut offsets = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            let set_off = u32_at(data, offset as usize + 4 + index * 4)?;
            offsets.push(set_off);
            self.parse_set(data, set_off, refs)?;
        }
        self.set_refs.insert(offset, offsets);
        Ok(())
    }
}

#[derive(Debug)]
struct IndexMapper<'a> {
    dex: &'a DexView<'a>,
    strings: Vec<String>,
    string_by_value: HashMap<String, u32>,
    types: Vec<u32>,
    origin_types: HashMap<u32, u16>,
    synthetic_types: HashMap<u32, u16>,
    primitive_types: HashMap<char, u16>,
    protos: Vec<NewProto>,
    origin_protos: HashMap<u32, u16>,
    fields: Vec<NewField>,
    origin_fields: HashMap<u32, u16>,
    methods: Vec<NewMethod>,
    origin_methods: HashMap<u32, u16>,
}

impl<'a> IndexMapper<'a> {
    fn new(dex: &'a DexView<'a>) -> Self {
        Self {
            dex,
            strings: Vec::new(),
            string_by_value: HashMap::new(),
            types: Vec::new(),
            origin_types: HashMap::new(),
            synthetic_types: HashMap::new(),
            primitive_types: HashMap::new(),
            protos: Vec::new(),
            origin_protos: HashMap::new(),
            fields: Vec::new(),
            origin_fields: HashMap::new(),
            methods: Vec::new(),
            origin_methods: HashMap::new(),
        }
    }

    fn add_string_value(&mut self, value: &str) -> u32 {
        if let Some(&index) = self.string_by_value.get(value) {
            return index;
        }
        let index = self.strings.len() as u32;
        self.strings.push(value.to_owned());
        self.string_by_value.insert(value.to_owned(), index);
        index
    }

    fn add_origin_string(&mut self, old: u32) -> Result<u32> {
        let value = self
            .dex
            .strings
            .get(old as usize)
            .with_context(|| format!("invalid string index {old}"))?
            .clone();
        Ok(self.add_string_value(&value))
    }

    fn mapped_string(&self, old: u32) -> Result<u32> {
        let value = self
            .dex
            .strings
            .get(old as usize)
            .with_context(|| format!("invalid string index {old}"))?;
        self.string_by_value
            .get(value)
            .copied()
            .with_context(|| format!("string {old} was not included in minimal DEX"))
    }

    fn add_origin_type(&mut self, old: u32) -> Result<u16> {
        if let Some(&index) = self.origin_types.get(&old) {
            return Ok(index);
        }
        let descriptor_idx = *self
            .dex
            .type_descriptor_indices
            .get(old as usize)
            .with_context(|| format!("invalid type index {old}"))?;
        let new_descriptor_idx = self.add_origin_string(descriptor_idx)?;
        let index = u16::try_from(self.types.len()).context("minimal DEX has too many types")?;
        self.types.push(new_descriptor_idx);
        self.origin_types.insert(old, index);
        Ok(index)
    }

    fn add_synthetic_type(&mut self, descriptor: &str) -> Result<u16> {
        let descriptor_idx = self.add_string_value(descriptor);
        if let Some(&index) = self.synthetic_types.get(&descriptor_idx) {
            return Ok(index);
        }
        let index = u16::try_from(self.types.len()).context("minimal DEX has too many types")?;
        self.types.push(descriptor_idx);
        self.synthetic_types.insert(descriptor_idx, index);
        Ok(index)
    }

    fn mapped_type(&self, old: u32) -> Result<u16> {
        self.origin_types
            .get(&old)
            .copied()
            .with_context(|| format!("type {old} was not included in minimal DEX"))
    }

    fn fill_primitives(&mut self) -> Result<()> {
        for descriptor in ['V', 'Z', 'B', 'S', 'C', 'I', 'J', 'F', 'D'] {
            let index = self.add_synthetic_type(&descriptor.to_string())?;
            self.primitive_types.insert(descriptor, index);
        }
        Ok(())
    }

    fn proto_params(&self, proto: ProtoId) -> Result<Vec<u16>> {
        self.dex.type_list(proto.parameters_off)
    }

    fn add_proto(&mut self, old: u32) -> Result<u16> {
        if let Some(&index) = self.origin_protos.get(&old) {
            return Ok(index);
        }
        let proto = *self
            .dex
            .protos
            .get(old as usize)
            .with_context(|| format!("invalid proto index {old}"))?;
        let shorty_idx = self.add_origin_string(proto.shorty_idx)?;
        let return_type_idx = u32::from(self.add_origin_type(proto.return_type_idx)?);
        let mut params = Vec::new();
        for old_type in self.proto_params(proto)? {
            let descriptor = self.dex.type_descriptor(u32::from(old_type))?.to_owned();
            let mapped = if descriptor.len() == 1 {
                let character = descriptor.chars().next().unwrap();
                if let Some(&primitive) = self.primitive_types.get(&character) {
                    primitive
                } else {
                    self.add_origin_type(u32::from(old_type))?
                }
            } else {
                self.add_synthetic_type(&descriptor)?
            };
            params.push(mapped);
        }
        let index = u16::try_from(self.protos.len()).context("minimal DEX has too many protos")?;
        self.protos.push(NewProto {
            shorty_idx,
            return_type_idx,
            params,
        });
        self.origin_protos.insert(old, index);
        Ok(index)
    }

    fn add_field(&mut self, old: u32) -> Result<u16> {
        if let Some(&index) = self.origin_fields.get(&old) {
            return Ok(index);
        }
        let field = *self
            .dex
            .fields
            .get(old as usize)
            .with_context(|| format!("invalid field index {old}"))?;
        let class_descriptor = self
            .dex
            .type_descriptor(u32::from(field.class_idx))?
            .to_owned();
        let type_descriptor = self
            .dex
            .type_descriptor(u32::from(field.type_idx))?
            .to_owned();
        let class_idx = self.add_synthetic_type(&class_descriptor)?;
        let type_idx = self.add_synthetic_type(&type_descriptor)?;
        let name_idx = self.add_origin_string(field.name_idx)?;
        let index = u16::try_from(self.fields.len()).context("minimal DEX has too many fields")?;
        self.fields.push(NewField {
            class_idx,
            type_idx,
            name_idx,
        });
        self.origin_fields.insert(old, index);
        Ok(index)
    }

    fn mapped_field(&self, old: u32) -> Result<u16> {
        self.origin_fields
            .get(&old)
            .copied()
            .with_context(|| format!("field {old} was not included in minimal DEX"))
    }

    fn add_method(&mut self, old: u32) -> Result<u16> {
        if let Some(&index) = self.origin_methods.get(&old) {
            return Ok(index);
        }
        let method = *self
            .dex
            .methods
            .get(old as usize)
            .with_context(|| format!("invalid method index {old}"))?;
        let proto_idx = self.add_proto(u32::from(method.proto_idx))?;
        let class_descriptor = self
            .dex
            .type_descriptor(u32::from(method.class_idx))?
            .to_owned();
        let class_idx = self.add_synthetic_type(&class_descriptor)?;
        let name_idx = self.add_origin_string(method.name_idx)?;
        let index =
            u16::try_from(self.methods.len()).context("minimal DEX has too many methods")?;
        self.methods.push(NewMethod {
            class_idx,
            proto_idx,
            name_idx,
        });
        self.origin_methods.insert(old, index);
        Ok(index)
    }

    fn mapped_method(&self, old: u32) -> Result<u16> {
        self.origin_methods
            .get(&old)
            .copied()
            .with_context(|| format!("method {old} was not included in minimal DEX"))
    }

    fn include_bytecode_refs(&mut self, refs: &BytecodeRefs) -> Result<()> {
        for (expected, &old) in refs.strings.values.iter().enumerate() {
            let _ = self.add_origin_string(old)?;
            ensure!(expected <= u32::MAX as usize, "too many strings");
        }
        for (expected, &old) in refs.types.values.iter().enumerate() {
            ensure!(
                usize::from(self.add_origin_type(old)?) == expected,
                "type remap order changed"
            );
        }
        self.fill_primitives()?;
        for (expected, &old) in refs.protos.values.iter().enumerate() {
            ensure!(
                usize::from(self.add_proto(old)?) == expected,
                "proto remap order changed"
            );
        }
        for (expected, &old) in refs.fields.values.iter().enumerate() {
            ensure!(
                usize::from(self.add_field(old)?) == expected,
                "field remap order changed"
            );
        }
        for (expected, &old) in refs.methods.values.iter().enumerate() {
            ensure!(
                usize::from(self.add_method(old)?) == expected,
                "method remap order changed"
            );
        }
        Ok(())
    }
}

fn normalize_code_indices(
    code: &mut CodeItem,
    refs: &BytecodeRefs,
    mapper: &IndexMapper<'_>,
) -> Result<()> {
    let mut units = code
        .insns
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let mut pc = 0usize;
    while pc < units.len() {
        let opcode = (units[pc] & 0xff) as u8;
        if opcode == 0x1a {
            let temporary = usize::from(units[pc + 1]);
            let old = *refs
                .strings
                .values
                .get(temporary)
                .context("invalid temporary string index")?;
            units[pc + 1] = mapper.mapped_string(old)? as u16;
        } else if opcode == 0x1b {
            let temporary = u32::from(units[pc + 1]) | (u32::from(units[pc + 2]) << 16);
            let old = *refs
                .strings
                .values
                .get(temporary as usize)
                .context("invalid temporary jumbo string index")?;
            let new = mapper.mapped_string(old)?;
            units[pc + 1] = new as u16;
            units[pc + 2] = (new >> 16) as u16;
        }
        pc += instruction_width(&units, pc)?;
    }
    code.insns.clear();
    for unit in units {
        code.insns.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

fn write_indexed_value(
    kind: IndexKind,
    old: u32,
    mapper: &IndexMapper<'_>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let (value_type, new) = match kind {
        IndexKind::String => (0x17, mapper.mapped_string(old)?),
        IndexKind::Type => (0x18, u32::from(mapper.mapped_type(old)?)),
        IndexKind::Field => (0x19, u32::from(mapper.mapped_field(old)?)),
        IndexKind::Method => (0x1a, u32::from(mapper.mapped_method(old)?)),
    };
    let size = if new <= 0xff {
        1
    } else if new <= 0xffff {
        2
    } else if new <= 0xff_ffff {
        3
    } else {
        4
    };
    out.push(((size - 1) << 5) | value_type);
    for shift in 0..size {
        out.push((new >> (shift * 8)) as u8);
    }
    Ok(())
}

fn write_encoded_value(
    value: &EncodedValue,
    mapper: &IndexMapper<'_>,
    out: &mut Vec<u8>,
) -> Result<()> {
    match value {
        EncodedValue::Indexed(kind, old) => write_indexed_value(*kind, *old, mapper, out)?,
        EncodedValue::Array(values) => {
            out.push(0x1c);
            write_uleb(values.len() as u32, out);
            for value in values {
                write_encoded_value(value, mapper, out)?;
            }
        }
        EncodedValue::Annotation(annotation) => {
            out.push(0x1d);
            write_encoded_annotation(annotation, mapper, out)?;
        }
        EncodedValue::Null => out.push(0x1e),
        EncodedValue::Boolean(value) => out.push((*value << 5) | 0x1f),
        EncodedValue::Primitive(value_type, bytes) => {
            ensure!(
                !bytes.is_empty() && bytes.len() <= 8,
                "invalid primitive encoded_value"
            );
            out.push((((bytes.len() - 1) as u8) << 5) | value_type);
            out.extend_from_slice(bytes);
        }
    }
    Ok(())
}

fn write_encoded_annotation(
    annotation: &EncodedAnnotation,
    mapper: &IndexMapper<'_>,
    out: &mut Vec<u8>,
) -> Result<()> {
    write_uleb(u32::from(mapper.mapped_type(annotation.type_idx)?), out);
    write_uleb(annotation.elements.len() as u32, out);
    for (name_idx, value) in &annotation.elements {
        write_uleb(mapper.mapped_string(*name_idx)?, out);
        write_encoded_value(value, mapper, out)?;
    }
    Ok(())
}
fn write_encoded_array(
    values: &[EncodedValue],
    mapper: &IndexMapper<'_>,
    out: &mut Vec<u8>,
) -> Result<()> {
    write_uleb(values.len() as u32, out);
    for value in values {
        write_encoded_value(value, mapper, out)?;
    }
    Ok(())
}

fn mapped_p1_string(value: u32, mapper: &IndexMapper<'_>) -> Result<u32> {
    Ok(if value == 0 {
        0
    } else {
        mapper.mapped_string(value - 1)? + 1
    })
}

fn mapped_p1_type(value: u32, mapper: &IndexMapper<'_>) -> Result<u32> {
    Ok(if value == 0 {
        0
    } else {
        u32::from(mapper.mapped_type(value - 1)?) + 1
    })
}

fn write_debug_info(info: &DebugInfo, mapper: &IndexMapper<'_>, out: &mut Vec<u8>) -> Result<()> {
    write_uleb(info.line_start, out);
    write_uleb(info.parameter_names.len() as u32, out);
    for &name in &info.parameter_names {
        write_uleb(mapped_p1_string(name, mapper)?, out);
    }
    for op in &info.ops {
        match *op {
            DebugOp::End => out.push(0),
            DebugOp::AdvancePc(value) => {
                out.push(1);
                write_uleb(value, out);
            }
            DebugOp::AdvanceLine(value) => {
                out.push(2);
                write_sleb(value, out);
            }
            DebugOp::StartLocal(register, name, typ) => {
                out.push(3);
                write_uleb(register, out);
                write_uleb(mapped_p1_string(name, mapper)?, out);
                write_uleb(mapped_p1_type(typ, mapper)?, out);
            }
            DebugOp::StartLocalExtended(register, name, typ, signature) => {
                out.push(4);
                write_uleb(register, out);
                write_uleb(mapped_p1_string(name, mapper)?, out);
                write_uleb(mapped_p1_type(typ, mapper)?, out);
                write_uleb(mapped_p1_string(signature, mapper)?, out);
            }
            DebugOp::EndOrRestartLocal(opcode, register) => {
                out.push(opcode);
                write_uleb(register, out);
            }
            DebugOp::SetFile(name) => {
                out.push(9);
                write_uleb(mapped_p1_string(name, mapper)?, out);
            }
            DebugOp::Plain(opcode) => out.push(opcode),
        }
    }
    Ok(())
}

fn include_metadata_refs(mapper: &mut IndexMapper<'_>, refs: &MetadataRefs) -> Result<()> {
    for &index in &refs.strings {
        mapper.add_origin_string(index)?;
    }
    for &index in &refs.types {
        mapper.add_origin_type(index)?;
    }
    for &index in &refs.fields {
        mapper.add_field(index)?;
    }
    for &index in &refs.methods {
        mapper.add_method(index)?;
    }
    Ok(())
}

#[derive(Debug)]
struct Hollowed {
    interfaces: Vec<u16>,
    codes: BTreeMap<u32, CodeItem>,
    debug_info: BTreeMap<u32, DebugInfo>,
    annotations: Annotations,
    static_values: Option<Vec<EncodedValue>>,
    metadata_refs: MetadataRefs,
}

fn hollow_class(
    dex: &DexView<'_>,
    class: ClassDef,
    class_data: &ClassData,
    bytecode_refs: &mut BytecodeRefs,
) -> Result<Hollowed> {
    let interfaces = dex.type_list(class.interfaces_off)?;
    let mut codes = BTreeMap::new();
    for method in class_data.methods() {
        if method.code_off == 0 {
            continue;
        }
        let mut code = dex.code_item(method.code_off)?;
        remap_code_indices(&mut code, bytecode_refs)
            .with_context(|| format!("failed to scan method #{}", method.method_idx))?;
        codes.insert(method.method_idx, code);
    }

    let mut metadata_refs = MetadataRefs::default();
    let annotations = Annotations::parse(dex.data, class.annotations_off, &mut metadata_refs)?;
    let static_values = if class.static_values_off == 0 {
        None
    } else {
        Some(parse_encoded_array(
            dex.data,
            class.static_values_off,
            &mut metadata_refs,
        )?)
    };
    let mut debug_info = BTreeMap::new();
    for (&method_idx, code) in &codes {
        if code.debug_info_off != 0 {
            debug_info.insert(
                method_idx,
                parse_debug_info(dex.data, code.debug_info_off, &mut metadata_refs)?,
            );
        }
    }
    Ok(Hollowed {
        interfaces,
        codes,
        debug_info,
        annotations,
        static_values,
        metadata_refs,
    })
}

#[derive(Debug, Clone, Copy)]
struct MapItem {
    typ: u16,
    size: u32,
    offset: u32,
}

fn build_dex(
    class: ClassDef,
    class_data: &ClassData,
    hollowed: &Hollowed,
    mapper: &IndexMapper<'_>,
) -> Result<Vec<u8>> {
    let mut out = vec![0; 0x70];

    let mut string_data_offsets = Vec::with_capacity(mapper.strings.len());
    for value in &mapper.strings {
        string_data_offsets.push(out.len() as u32);
        write_mutf8(value, &mut out);
    }

    align4(&mut out);
    let mut proto_param_offsets = Vec::with_capacity(mapper.protos.len());
    for proto in &mapper.protos {
        if proto.params.is_empty() {
            proto_param_offsets.push(0);
        } else {
            align4(&mut out);
            proto_param_offsets.push(out.len() as u32);
            push_u32(&mut out, proto.params.len() as u32);
            for &param in &proto.params {
                push_u16(&mut out, param);
            }
        }
    }

    let interfaces_off = if hollowed.interfaces.is_empty() {
        0
    } else {
        align4(&mut out);
        let offset = out.len() as u32;
        push_u32(&mut out, hollowed.interfaces.len() as u32);
        for &old in &hollowed.interfaces {
            push_u16(&mut out, mapper.mapped_type(u32::from(old))?);
        }
        offset
    };

    let mut annotation_item_offsets = BTreeMap::new();
    let mut annotation_set_offsets = BTreeMap::new();
    let mut annotation_set_ref_offsets = BTreeMap::new();
    let mut annotation_directory_off = 0u32;
    if let Some(directory) = &hollowed.annotations.directory {
        for (&old_off, item) in &hollowed.annotations.items {
            annotation_item_offsets.insert(old_off, out.len() as u32);
            out.push(item.visibility);
            write_encoded_annotation(&item.annotation, mapper, &mut out)?;
        }
        align4(&mut out);
        for (&old_off, set) in &hollowed.annotations.sets {
            annotation_set_offsets.insert(old_off, out.len() as u32);
            let mut items = set.item_offsets.clone();
            items.sort_by_key(|offset| {
                hollowed
                    .annotations
                    .items
                    .get(offset)
                    .and_then(|item| mapper.mapped_type(item.annotation.type_idx).ok())
                    .unwrap_or(0)
            });
            push_u32(&mut out, items.len() as u32);
            for old_item_off in items {
                push_u32(
                    &mut out,
                    annotation_item_offsets
                        .get(&old_item_off)
                        .copied()
                        .unwrap_or(0),
                );
            }
        }
        align4(&mut out);
        for (&old_off, sets) in &hollowed.annotations.set_refs {
            annotation_set_ref_offsets.insert(old_off, out.len() as u32);
            push_u32(&mut out, sets.len() as u32);
            for old_set_off in sets {
                push_u32(
                    &mut out,
                    annotation_set_offsets
                        .get(old_set_off)
                        .copied()
                        .unwrap_or(0),
                );
            }
        }
        align4(&mut out);
        annotation_directory_off = out.len() as u32;
        let mut field_annotations = directory
            .field_annotations
            .iter()
            .filter_map(|&(index, offset)| mapper.mapped_field(index).ok().map(|new| (new, offset)))
            .collect::<Vec<_>>();
        field_annotations.sort_by_key(|item| item.0);
        let mut method_annotations = directory
            .method_annotations
            .iter()
            .filter_map(|&(index, offset)| {
                mapper.mapped_method(index).ok().map(|new| (new, offset))
            })
            .collect::<Vec<_>>();
        method_annotations.sort_by_key(|item| item.0);
        let mut parameter_annotations = directory
            .parameter_annotations
            .iter()
            .filter_map(|&(index, offset)| {
                mapper.mapped_method(index).ok().map(|new| (new, offset))
            })
            .collect::<Vec<_>>();
        parameter_annotations.sort_by_key(|item| item.0);
        push_u32(
            &mut out,
            annotation_set_offsets
                .get(&directory.class_annotations_off)
                .copied()
                .unwrap_or(0),
        );
        push_u32(&mut out, field_annotations.len() as u32);
        push_u32(&mut out, method_annotations.len() as u32);
        push_u32(&mut out, parameter_annotations.len() as u32);
        for (index, old_off) in field_annotations {
            push_u32(&mut out, u32::from(index));
            push_u32(
                &mut out,
                annotation_set_offsets.get(&old_off).copied().unwrap_or(0),
            );
        }
        for (index, old_off) in method_annotations {
            push_u32(&mut out, u32::from(index));
            push_u32(
                &mut out,
                annotation_set_offsets.get(&old_off).copied().unwrap_or(0),
            );
        }
        for (index, old_off) in parameter_annotations {
            push_u32(&mut out, u32::from(index));
            push_u32(
                &mut out,
                annotation_set_ref_offsets
                    .get(&old_off)
                    .copied()
                    .unwrap_or(0),
            );
        }
    }

    let static_values_off = if let Some(values) = &hollowed.static_values {
        align4(&mut out);
        let offset = out.len() as u32;
        write_encoded_array(values, mapper, &mut out)?;
        offset
    } else {
        0
    };

    let mut debug_offsets = BTreeMap::new();
    let mut ordered_methods = class_data.methods().copied().collect::<Vec<_>>();
    ordered_methods.sort_by_key(|method| mapper.mapped_method(method.method_idx).unwrap_or(0));
    for method in &ordered_methods {
        if let Some(debug) = hollowed.debug_info.get(&method.method_idx) {
            debug_offsets.insert(method.method_idx, out.len() as u32);
            write_debug_info(debug, mapper, &mut out)?;
        }
    }

    let mut code_offsets = BTreeMap::new();
    for method in &ordered_methods {
        let Some(code) = hollowed.codes.get(&method.method_idx) else {
            continue;
        };
        align4(&mut out);
        code_offsets.insert(method.method_idx, out.len() as u32);
        push_u16(&mut out, code.registers_size);
        push_u16(&mut out, code.ins_size);
        push_u16(&mut out, code.outs_size);
        push_u16(&mut out, code.tries_size);
        push_u32(
            &mut out,
            debug_offsets.get(&method.method_idx).copied().unwrap_or(0),
        );
        push_u32(&mut out, (code.insns.len() / 2) as u32);
        out.extend_from_slice(&code.insns);
        if !code.tries.is_empty() {
            if (code.insns.len() / 2) & 1 != 0 {
                push_u16(&mut out, 0);
            }
            let mut handler_bytes = Vec::new();
            let mut handler_offsets = HashMap::new();
            write_uleb(code.handlers.len() as u32, &mut handler_bytes);
            for handler in &code.handlers {
                let new_offset = u16::try_from(handler_bytes.len())
                    .context("catch handler list exceeds 65535 bytes")?;
                handler_offsets.insert(handler.old_offset, new_offset);
                write_sleb(handler.size, &mut handler_bytes);
                for &(type_idx, address) in &handler.pairs {
                    write_uleb(type_idx, &mut handler_bytes);
                    write_uleb(address, &mut handler_bytes);
                }
                if let Some(address) = handler.catch_all_addr {
                    write_uleb(address, &mut handler_bytes);
                }
            }
            for try_item in &code.tries {
                push_u32(&mut out, try_item.start_addr);
                push_u16(&mut out, try_item.insn_count);
                push_u16(
                    &mut out,
                    handler_offsets
                        .get(&try_item.handler_off)
                        .copied()
                        .unwrap_or(try_item.handler_off),
                );
            }
            out.extend_from_slice(&handler_bytes);
        }
    }

    let class_data_off =
        if class_data.fields().next().is_some() || class_data.methods().next().is_some() {
            let offset = out.len() as u32;
            write_uleb(class_data.static_fields.len() as u32, &mut out);
            write_uleb(class_data.instance_fields.len() as u32, &mut out);
            write_uleb(class_data.direct_methods.len() as u32, &mut out);
            write_uleb(class_data.virtual_methods.len() as u32, &mut out);

            fn write_fields(
                source: &[EncodedField],
                mapper: &IndexMapper<'_>,
                out: &mut Vec<u8>,
            ) -> Result<()> {
                let mut values = source.to_vec();
                values.sort_by_key(|field| mapper.mapped_field(field.field_idx).unwrap_or(0));
                let mut previous = 0u32;
                for field in values {
                    let index = u32::from(mapper.mapped_field(field.field_idx)?);
                    write_uleb(index - previous, out);
                    write_uleb(field.access_flags, out);
                    previous = index;
                }
                Ok(())
            }

            fn write_methods(
                source: &[EncodedMethod],
                mapper: &IndexMapper<'_>,
                offsets: &BTreeMap<u32, u32>,
                out: &mut Vec<u8>,
            ) -> Result<()> {
                let mut values = source.to_vec();
                values.sort_by_key(|method| mapper.mapped_method(method.method_idx).unwrap_or(0));
                let mut previous = 0u32;
                for method in values {
                    let index = u32::from(mapper.mapped_method(method.method_idx)?);
                    write_uleb(index - previous, out);
                    write_uleb(method.access_flags, out);
                    write_uleb(offsets.get(&method.method_idx).copied().unwrap_or(0), out);
                    previous = index;
                }
                Ok(())
            }

            write_fields(&class_data.static_fields, mapper, &mut out)?;
            write_fields(&class_data.instance_fields, mapper, &mut out)?;
            write_methods(&class_data.direct_methods, mapper, &code_offsets, &mut out)?;
            write_methods(&class_data.virtual_methods, mapper, &code_offsets, &mut out)?;
            offset
        } else {
            0
        };

    align4(&mut out);
    let string_ids_off = out.len() as u32;
    for offset in &string_data_offsets {
        push_u32(&mut out, *offset);
    }
    let type_ids_off = out.len() as u32;
    for descriptor_idx in &mapper.types {
        push_u32(&mut out, *descriptor_idx);
    }
    let proto_ids_off = out.len() as u32;
    for (index, proto) in mapper.protos.iter().enumerate() {
        push_u32(&mut out, proto.shorty_idx);
        push_u32(&mut out, proto.return_type_idx);
        push_u32(&mut out, proto_param_offsets[index]);
    }
    let field_ids_off = out.len() as u32;
    for field in &mapper.fields {
        push_u16(&mut out, field.class_idx);
        push_u16(&mut out, field.type_idx);
        push_u32(&mut out, field.name_idx);
    }
    let method_ids_off = out.len() as u32;
    for method in &mapper.methods {
        push_u16(&mut out, method.class_idx);
        push_u16(&mut out, method.proto_idx);
        push_u32(&mut out, method.name_idx);
    }
    let class_defs_off = out.len() as u32;
    push_u32(&mut out, u32::from(mapper.mapped_type(class.class_idx)?));
    push_u32(&mut out, class.access_flags);
    push_u32(
        &mut out,
        if class.superclass_idx == NO_INDEX {
            NO_INDEX
        } else {
            u32::from(mapper.mapped_type(class.superclass_idx)?)
        },
    );
    push_u32(&mut out, interfaces_off);
    push_u32(
        &mut out,
        if class.source_file_idx == NO_INDEX {
            NO_INDEX
        } else {
            mapper.mapped_string(class.source_file_idx)?
        },
    );
    push_u32(&mut out, annotation_directory_off);
    push_u32(&mut out, class_data_off);
    push_u32(&mut out, static_values_off);

    align4(&mut out);
    let map_off = out.len() as u32;
    let mut maps = vec![MapItem {
        typ: 0x0000,
        size: 1,
        offset: 0,
    }];
    if !mapper.strings.is_empty() {
        maps.push(MapItem {
            typ: 0x0001,
            size: mapper.strings.len() as u32,
            offset: string_ids_off,
        });
        maps.push(MapItem {
            typ: 0x2002,
            size: mapper.strings.len() as u32,
            offset: string_data_offsets[0],
        });
    }
    if !mapper.types.is_empty() {
        maps.push(MapItem {
            typ: 0x0002,
            size: mapper.types.len() as u32,
            offset: type_ids_off,
        });
    }
    if !mapper.protos.is_empty() {
        maps.push(MapItem {
            typ: 0x0003,
            size: mapper.protos.len() as u32,
            offset: proto_ids_off,
        });
    }
    if !mapper.fields.is_empty() {
        maps.push(MapItem {
            typ: 0x0004,
            size: mapper.fields.len() as u32,
            offset: field_ids_off,
        });
    }
    if !mapper.methods.is_empty() {
        maps.push(MapItem {
            typ: 0x0005,
            size: mapper.methods.len() as u32,
            offset: method_ids_off,
        });
    }
    maps.push(MapItem {
        typ: 0x0006,
        size: 1,
        offset: class_defs_off,
    });
    let mut type_list_offsets = proto_param_offsets
        .iter()
        .copied()
        .filter(|offset| *offset != 0)
        .collect::<Vec<_>>();
    if interfaces_off != 0 {
        type_list_offsets.push(interfaces_off);
    }
    if let Some(&first) = type_list_offsets.iter().min() {
        maps.push(MapItem {
            typ: 0x1001,
            size: type_list_offsets.len() as u32,
            offset: first,
        });
    }
    if !annotation_set_ref_offsets.is_empty() {
        maps.push(MapItem {
            typ: 0x1002,
            size: annotation_set_ref_offsets.len() as u32,
            offset: *annotation_set_ref_offsets.values().min().unwrap(),
        });
    }
    if !annotation_set_offsets.is_empty() {
        maps.push(MapItem {
            typ: 0x1003,
            size: annotation_set_offsets.len() as u32,
            offset: *annotation_set_offsets.values().min().unwrap(),
        });
    }
    if annotation_directory_off != 0 {
        maps.push(MapItem {
            typ: 0x2006,
            size: 1,
            offset: annotation_directory_off,
        });
    }
    if !annotation_item_offsets.is_empty() {
        maps.push(MapItem {
            typ: 0x2004,
            size: annotation_item_offsets.len() as u32,
            offset: *annotation_item_offsets.values().min().unwrap(),
        });
    }
    if class_data_off != 0 {
        maps.push(MapItem {
            typ: 0x2000,
            size: 1,
            offset: class_data_off,
        });
    }
    if !code_offsets.is_empty() {
        maps.push(MapItem {
            typ: 0x2001,
            size: code_offsets.len() as u32,
            offset: *code_offsets.values().min().unwrap(),
        });
    }
    if !debug_offsets.is_empty() {
        maps.push(MapItem {
            typ: 0x2003,
            size: debug_offsets.len() as u32,
            offset: *debug_offsets.values().min().unwrap(),
        });
    }
    if static_values_off != 0 {
        maps.push(MapItem {
            typ: 0x2005,
            size: 1,
            offset: static_values_off,
        });
    }
    maps.sort_by_key(|item| item.offset);
    maps.push(MapItem {
        typ: 0x1000,
        size: 1,
        offset: map_off,
    });
    push_u32(&mut out, maps.len() as u32);
    for item in maps {
        push_u16(&mut out, item.typ);
        push_u16(&mut out, 0);
        push_u32(&mut out, item.size);
        push_u32(&mut out, item.offset);
    }

    ensure!(out.len() <= u32::MAX as usize, "minimal DEX is too large");
    let file_size = out.len() as u32;
    out[0..8].copy_from_slice(b"dex\n035\0");
    patch_u32(&mut out, 0x20, file_size);
    patch_u32(&mut out, 0x24, 0x70);
    patch_u32(&mut out, 0x28, 0x1234_5678);
    patch_u32(&mut out, 0x34, map_off);
    patch_u32(&mut out, 0x38, mapper.strings.len() as u32);
    patch_u32(&mut out, 0x3c, string_ids_off);
    patch_u32(&mut out, 0x40, mapper.types.len() as u32);
    patch_u32(&mut out, 0x44, type_ids_off);
    patch_u32(&mut out, 0x48, mapper.protos.len() as u32);
    patch_u32(&mut out, 0x4c, proto_ids_off);
    patch_u32(&mut out, 0x50, mapper.fields.len() as u32);
    patch_u32(&mut out, 0x54, field_ids_off);
    patch_u32(&mut out, 0x58, mapper.methods.len() as u32);
    patch_u32(&mut out, 0x5c, method_ids_off);
    patch_u32(&mut out, 0x60, 1);
    patch_u32(&mut out, 0x64, class_defs_off);
    patch_u32(&mut out, 0x68, file_size - 0x70);
    patch_u32(&mut out, 0x6c, 0x70);
    let signature = Sha1::digest(&out[32..]);
    out[12..32].copy_from_slice(&signature);
    let checksum = adler32_slice(&out[12..]);
    patch_u32(&mut out, 8, checksum);
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
pub struct MinimalDexStats {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub strings: usize,
    pub types: usize,
    pub protos: usize,
    pub fields: usize,
    pub methods: usize,
}

#[derive(Debug)]
pub struct MinimalDex {
    pub bytes: Vec<u8>,
    pub stats: MinimalDexStats,
}

/// Extract one class and its direct DEX dependencies into a dense, standalone DEX.
pub fn extract_minimal_dex(data: &[u8], descriptor: &str) -> Result<MinimalDex> {
    let dex = DexView::parse(data)?;
    let class = dex
        .find_class(descriptor)?
        .with_context(|| format!("class {descriptor} not found in DEX"))?;
    let class_data = dex.class_data(class.class_data_off)?;
    let mut bytecode_refs = BytecodeRefs::default();
    let mut hollowed = hollow_class(&dex, class, &class_data, &mut bytecode_refs)?;

    let mut mapper = IndexMapper::new(&dex);
    mapper.include_bytecode_refs(&bytecode_refs)?;
    for field in class_data.fields() {
        mapper.add_field(field.field_idx)?;
    }
    for method in class_data.methods() {
        mapper.add_method(method.method_idx)?;
    }
    if class.source_file_idx != NO_INDEX {
        mapper.add_origin_string(class.source_file_idx)?;
    }
    mapper.add_origin_type(class.class_idx)?;
    if class.superclass_idx != NO_INDEX {
        mapper.add_origin_type(class.superclass_idx)?;
    }
    for &interface in &hollowed.interfaces {
        mapper.add_origin_type(u32::from(interface))?;
    }
    include_metadata_refs(&mut mapper, &hollowed.metadata_refs)?;
    for code in hollowed.codes.values_mut() {
        for handler in &mut code.handlers {
            for pair in &mut handler.pairs {
                pair.0 = u32::from(mapper.add_origin_type(pair.0)?);
            }
        }
        normalize_code_indices(code, &bytecode_refs, &mapper)?;
    }

    let bytes = build_dex(class, &class_data, &hollowed, &mapper)?;
    let stats = MinimalDexStats {
        input_bytes: data.len(),
        output_bytes: bytes.len(),
        strings: mapper.strings.len(),
        types: mapper.types.len(),
        protos: mapper.protos.len(),
        fields: mapper.fields.len(),
        methods: mapper.methods.len(),
    };
    Ok(MinimalDex { bytes, stats })
}

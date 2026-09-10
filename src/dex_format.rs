use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy)]
pub(crate) struct DexHeader {
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

impl DexHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 0x70 {
            bail!("DEX is shorter than its header");
        }
        if &data[..4] != b"dex\n" || data[7] != 0 {
            bail!("invalid DEX magic");
        }
        let header = Self {
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
        };
        for (name, size, offset, item_size) in [
            (
                "string_ids",
                header.string_ids_size,
                header.string_ids_off,
                4usize,
            ),
            ("type_ids", header.type_ids_size, header.type_ids_off, 4),
            ("proto_ids", header.proto_ids_size, header.proto_ids_off, 12),
            ("field_ids", header.field_ids_size, header.field_ids_off, 8),
            (
                "method_ids",
                header.method_ids_size,
                header.method_ids_off,
                8,
            ),
            (
                "class_defs",
                header.class_defs_size,
                header.class_defs_off,
                32,
            ),
        ] {
            if (size == 0) != (offset == 0) {
                bail!("{name} count and offset must both be zero or non-zero");
            }
            if size != 0 {
                let bytes = (size as usize)
                    .checked_mul(item_size)
                    .context("DEX table size overflow")?;
                bytes_at(data, offset as usize, bytes)?;
            }
        }
        Ok(header)
    }
}

pub(crate) fn bytes_at(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    data.get(offset..offset.saturating_add(size))
        .with_context(|| {
            format!(
                "DEX range 0x{offset:x}..0x{:x} is out of bounds",
                offset.saturating_add(size)
            )
        })
}

pub(crate) fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes_at(data, offset, 2)?.try_into().unwrap(),
    ))
}

pub(crate) fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes_at(data, offset, 4)?.try_into().unwrap(),
    ))
}

pub(crate) fn read_uleb(data: &[u8], cursor: &mut usize) -> Result<u32> {
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

pub(crate) fn decode_mutf8(data: &[u8]) -> String {
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

pub(crate) fn read_string(data: &[u8], header: &DexHeader, index: usize) -> Result<String> {
    if index >= header.string_ids_size as usize {
        bail!("invalid string index {index}");
    }
    let id_offset = header.string_ids_off as usize + index * 4;
    let mut cursor = u32_at(data, id_offset)? as usize;
    let _utf16_size = read_uleb(data, &mut cursor)?;
    let tail = data
        .get(cursor..)
        .with_context(|| format!("string #{index} data offset is out of bounds"))?;
    let end = tail
        .iter()
        .position(|&byte| byte == 0)
        .map(|length| cursor + length)
        .with_context(|| format!("unterminated DEX string #{index}"))?;
    Ok(decode_mutf8(&data[cursor..end]))
}

pub(crate) fn read_strings(data: &[u8], header: &DexHeader) -> Result<Vec<String>> {
    (0..header.string_ids_size as usize)
        .map(|index| read_string(data, header, index))
        .collect()
}

pub(crate) fn read_types(data: &[u8], header: &DexHeader) -> Result<Vec<u32>> {
    (0..header.type_ids_size as usize)
        .map(|index| {
            let string_idx = u32_at(data, header.type_ids_off as usize + index * 4)?;
            if string_idx >= header.string_ids_size {
                bail!("type #{index} has invalid string index");
            }
            Ok(string_idx)
        })
        .collect()
}

pub(crate) fn read_proto_ids(data: &[u8], header: &DexHeader) -> Result<Vec<ProtoId>> {
    (0..header.proto_ids_size as usize)
        .map(|index| {
            let offset = header.proto_ids_off as usize + index * 12;
            let proto = ProtoId {
                shorty_idx: u32_at(data, offset)?,
                return_type_idx: u32_at(data, offset + 4)?,
                parameters_off: u32_at(data, offset + 8)?,
            };
            if proto.shorty_idx >= header.string_ids_size
                || proto.return_type_idx >= header.type_ids_size
            {
                bail!("proto #{index} has an invalid string or type index");
            }
            Ok(proto)
        })
        .collect()
}

pub(crate) fn read_field_ids(data: &[u8], header: &DexHeader) -> Result<Vec<FieldId>> {
    (0..header.field_ids_size as usize)
        .map(|index| {
            let offset = header.field_ids_off as usize + index * 8;
            let field = FieldId {
                class_idx: u16_at(data, offset)?,
                type_idx: u16_at(data, offset + 2)?,
                name_idx: u32_at(data, offset + 4)?,
            };
            if u32::from(field.class_idx) >= header.type_ids_size
                || u32::from(field.type_idx) >= header.type_ids_size
                || field.name_idx >= header.string_ids_size
            {
                bail!("field #{index} has an invalid type or string index");
            }
            Ok(field)
        })
        .collect()
}

pub(crate) fn read_method_ids(data: &[u8], header: &DexHeader) -> Result<Vec<MethodId>> {
    (0..header.method_ids_size as usize)
        .map(|index| {
            let offset = header.method_ids_off as usize + index * 8;
            let method = MethodId {
                class_idx: u16_at(data, offset)?,
                proto_idx: u16_at(data, offset + 2)?,
                name_idx: u32_at(data, offset + 4)?,
            };
            if u32::from(method.class_idx) >= header.type_ids_size
                || u32::from(method.proto_idx) >= header.proto_ids_size
                || method.name_idx >= header.string_ids_size
            {
                bail!("method #{index} has an invalid type, proto, or string index");
            }
            Ok(method)
        })
        .collect()
}

pub(crate) fn utf16_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

pub(crate) fn read_type_list(data: &[u8], offset: u32, type_count: u32) -> Result<Vec<u16>> {
    if offset == 0 {
        return Ok(Vec::new());
    }
    let size = u32_at(data, offset as usize)? as usize;
    let bytes = size.checked_mul(2).context("DEX type_list size overflow")?;
    bytes_at(data, offset as usize + 4, bytes)?;
    let mut result = Vec::with_capacity(size);
    for index in 0..size {
        let type_idx = u16_at(data, offset as usize + 4 + index * 2)?;
        if u32::from(type_idx) >= type_count {
            bail!("type_list contains an invalid type index");
        }
        result.push(type_idx);
    }
    Ok(result)
}

pub(crate) fn instruction_width(units: &[u16], pc: usize) -> Result<usize> {
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
        0x00 => unreachable!(),
    };
    Ok(width)
}

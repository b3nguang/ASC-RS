use anyhow::{Context, Result, ensure};

use crate::dex_format::u32_at;

const DEX_HEADER_MIN_SIZE: usize = 0x70;
const DEX041_HEADER_SIZE: usize = 0x78;
const DEX041_MAGIC: &[u8; 8] = b"dex\n041\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogicalDex {
    pub name: String,
    pub header_offset: usize,
}

pub(crate) fn logical_dexes(name: &str, data: &[u8]) -> Result<Vec<LogicalDex>> {
    if data.get(..8) != Some(DEX041_MAGIC) {
        return Ok(vec![LogicalDex {
            name: name.to_owned(),
            header_offset: 0,
        }]);
    }

    let mut offsets = Vec::new();
    let mut offset = 0usize;
    while data.get(offset..offset + 8) == Some(DEX041_MAGIC) {
        ensure!(
            offset
                .checked_add(DEX041_HEADER_SIZE)
                .is_some_and(|end| end <= data.len()),
            "truncated DEX 041 header at offset 0x{offset:x}"
        );
        let file_size = usize::try_from(u32_at(data, offset + 0x20)?)
            .context("DEX 041 logical file size is too large")?;
        ensure!(
            file_size >= DEX_HEADER_MIN_SIZE,
            "invalid DEX 041 logical file size {file_size} at offset 0x{offset:x}"
        );
        let next = offset
            .checked_add(file_size)
            .context("DEX 041 logical file range overflow")?;
        ensure!(
            next <= data.len(),
            "DEX 041 logical file at 0x{offset:x} exceeds its container"
        );
        let container_size = usize::try_from(u32_at(data, offset + 0x70)?)
            .context("DEX 041 container size is too large")?;
        let declared_offset = usize::try_from(u32_at(data, offset + 0x74)?)
            .context("DEX 041 header offset is too large")?;
        ensure!(
            container_size == data.len(),
            "DEX 041 header at 0x{offset:x} declares container size {container_size}, actual {}",
            data.len()
        );
        ensure!(
            declared_offset == offset,
            "DEX 041 header offset mismatch: expected 0x{offset:x}, got 0x{declared_offset:x}"
        );
        offsets.push(offset);
        offset = next;
    }
    ensure!(
        offset == data.len(),
        "DEX 041 logical files do not cover the complete container"
    );

    if offsets.len() == 1 {
        return Ok(vec![LogicalDex {
            name: name.to_owned(),
            header_offset: 0,
        }]);
    }
    Ok(offsets
        .into_iter()
        .enumerate()
        .map(|(index, header_offset)| LogicalDex {
            name: format!("{name}!classes{}.dex", index + 1),
            header_offset,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(file_size: u32, container_size: u32, header_offset: u32) -> Vec<u8> {
        let mut data = vec![0; DEX041_HEADER_SIZE];
        data[..8].copy_from_slice(DEX041_MAGIC);
        data[0x20..0x24].copy_from_slice(&file_size.to_le_bytes());
        data[0x24..0x28].copy_from_slice(&(DEX041_HEADER_SIZE as u32).to_le_bytes());
        data[0x70..0x74].copy_from_slice(&container_size.to_le_bytes());
        data[0x74..0x78].copy_from_slice(&header_offset.to_le_bytes());
        data
    }

    #[test]
    fn enumerates_dex041_logical_files() {
        let size = (DEX041_HEADER_SIZE * 2) as u32;
        let mut data = header(DEX041_HEADER_SIZE as u32, size, 0);
        data.extend(header(
            DEX041_HEADER_SIZE as u32,
            size,
            DEX041_HEADER_SIZE as u32,
        ));
        assert_eq!(
            logical_dexes("classes.dex", &data).unwrap(),
            vec![
                LogicalDex {
                    name: "classes.dex!classes1.dex".to_owned(),
                    header_offset: 0,
                },
                LogicalDex {
                    name: "classes.dex!classes2.dex".to_owned(),
                    header_offset: DEX041_HEADER_SIZE,
                },
            ]
        );
    }

    #[test]
    fn rejects_inconsistent_dex041_container_bounds() {
        let data = header(DEX041_HEADER_SIZE as u32, 1, 0);
        assert!(
            logical_dexes("classes.dex", &data)
                .unwrap_err()
                .to_string()
                .contains("container size")
        );
    }
}

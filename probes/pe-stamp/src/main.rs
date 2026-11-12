//! P-W3 probe: stamp fixed VERSIONINFO values and a generated icon into a PE file.
//!
//! Usage: `pe-stamp <input.exe> <output.exe>` stamps; `pe-stamp --read <file.exe>` prints the
//! stamped fields found in a file (`key=value` lines: CompanyName, FileVersion, icon presence and
//! the first icon pixel). Throwaway; runs on the hosted runner only. Never prints file contents.

use editpe::types::{FixedFileInfo, VersionU16, VersionU32};
use editpe::{Image, ResourceDirectory, VersionInfo, VersionStringTable};

/// Fixed test values; `probes/windows/p-w3-stamp-sign.ps1` compares against these.
const STRINGS: [(&str, &str); 8] = [
    ("CompanyName", "Lunepack Probe Co"),
    ("FileDescription", "Lunepack probe hello"),
    ("FileVersion", "1.2.3.4"),
    ("InternalName", "hello"),
    ("LegalCopyright", "Lunepack probe"),
    ("OriginalFilename", "hello.exe"),
    ("ProductName", "Lunepack Probe"),
    ("ProductVersion", "5.6.7.8"),
];

/// The icon is a solid color so a pixel read back from the signed exe identifies it.
const ICON_BGRA: [u8; 4] = [0xC1, 0x86, 0x2E, 0xFF];

fn version_info() -> VersionInfo {
    let info = FixedFileInfo {
        file_version: VersionU32 {
            major: (1 << 16) | 2,
            minor: (3 << 16) | 4,
        },
        product_version: VersionU32 {
            major: (5 << 16) | 6,
            minor: (7 << 16) | 8,
        },
        ..FixedFileInfo::default()
    };
    let mut table = VersionStringTable {
        key: "040904b0".to_string(),
        ..Default::default()
    };
    for (key, value) in STRINGS {
        table.strings.insert(key.to_string(), value.to_string());
    }
    VersionInfo {
        info,
        strings: vec![table],
        vars: vec![VersionU16 {
            major: 0x0409,
            minor: 0x04b0,
        }],
    }
}

/// A 16x16, 32-bit ICO file holding one solid-color image (BMP payload, no PNG).
fn icon_bytes() -> Vec<u8> {
    const SIZE: usize = 16;
    let pixels = SIZE * SIZE * 4;
    let mask = SIZE * 4; // 1 bit per pixel, rows padded to 32 bits
    let payload = 40 + pixels + mask;
    let mut ico = Vec::with_capacity(22 + payload);
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]); // ICONDIR: reserved, type 1 (icon), count 1
    ico.extend_from_slice(&[SIZE as u8, SIZE as u8, 0, 0]); // width, height, colors, reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // planes
    ico.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    ico.extend_from_slice(&(payload as u32).to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes()); // offset of the payload
    ico.extend_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER
    ico.extend_from_slice(&(SIZE as u32).to_le_bytes());
    ico.extend_from_slice(&((SIZE * 2) as u32).to_le_bytes()); // XOR + AND heights
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&32u16.to_le_bytes());
    ico.extend_from_slice(&[0; 24]); // compression, image size, resolution, color counts
    for _ in 0..SIZE * SIZE {
        ico.extend_from_slice(&ICON_BGRA);
    }
    ico.extend(std::iter::repeat_n(0u8, mask)); // AND mask: all opaque
    ico
}

/// Stamp `resources` with the fixed version info and the generated icon.
fn stamp(resources: &mut ResourceDirectory) -> Result<(), Box<dyn std::error::Error>> {
    resources.set_main_icon(icon_bytes())?;
    resources.set_version_info(&version_info())?;
    Ok(())
}

/// Named fields read back from a resource directory, as `key=value` lines.
fn summary(resources: &ResourceDirectory) -> Vec<String> {
    let mut lines = Vec::new();
    let version = resources.get_version_info().ok().flatten();
    let field = |name: &str| {
        version
            .as_ref()
            .and_then(|v| v.strings.first())
            .and_then(|t| t.strings.get(name))
            .cloned()
            .unwrap_or_default()
    };
    lines.push(format!("version_present={}", version.is_some()));
    lines.push(format!("CompanyName={}", field("CompanyName")));
    lines.push(format!("FileVersion={}", field("FileVersion")));
    lines.push(format!("ProductName={}", field("ProductName")));
    let icon = resources.get_main_icon().ok().flatten();
    lines.push(format!("icon_present={}", icon.is_some()));
    // First pixel of the BMP payload (40-byte header, then BGRA), as hex.
    let pixel = icon
        .and_then(|data| data.get(40..44))
        .map(|p| p.iter().map(|b| format!("{b:02X}")).collect::<String>())
        .unwrap_or_default();
    lines.push(format!("icon_pixel0={pixel}"));
    lines
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [flag, file] = args.as_slice()
        && flag == "--read"
    {
        let image = Image::parse_file(file)?;
        let resources = image.resource_directory().cloned().unwrap_or_default();
        for line in summary(&resources) {
            println!("{line}");
        }
        return Ok(());
    }
    let [input, output] = args.as_slice() else {
        eprintln!("usage: pe-stamp <input.exe> <output.exe> | pe-stamp --read <file.exe>");
        std::process::exit(2);
    };
    let mut image = Image::parse_file(input)?;
    let mut resources = image.resource_directory().cloned().unwrap_or_default();
    stamp(&mut resources)?;
    image.set_resource_directory(resources)?;
    image.write_file(output)?;
    println!(
        "pe-stamp: stamped {} version strings and a 16x16 icon",
        STRINGS.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_is_accepted_by_editpe() {
        let mut dir = ResourceDirectory::default();
        dir.set_main_icon(icon_bytes()).expect("icon accepted");
        assert!(dir.get_main_icon().expect("readable").is_some());
    }

    #[test]
    fn summary_reports_the_stamped_fields_and_empty_for_an_unstamped_directory() {
        let mut dir = ResourceDirectory::default();
        let empty = summary(&dir);
        assert!(empty.contains(&"version_present=false".to_string()));
        assert!(empty.contains(&"icon_present=false".to_string()));
        stamp(&mut dir).expect("stamp");
        let stamped = summary(&dir);
        assert!(stamped.contains(&"CompanyName=Lunepack Probe Co".to_string()));
        assert!(stamped.contains(&"FileVersion=1.2.3.4".to_string()));
        assert!(stamped.contains(&"icon_present=true".to_string()));
        assert!(
            stamped.contains(&"icon_pixel0=C1862EFF".to_string()),
            "{stamped:?}"
        );
    }

    #[test]
    fn version_info_round_trips_through_a_resource_directory() {
        let mut dir = ResourceDirectory::default();
        stamp(&mut dir).expect("stamp");
        let read = dir.get_version_info().expect("readable").expect("present");
        assert_eq!(
            read.info.file_version,
            VersionU32 {
                major: 0x0001_0002,
                minor: 0x0003_0004
            }
        );
        let table = &read.strings[0];
        for (key, value) in STRINGS {
            assert_eq!(
                table.strings.get(key).map(String::as_str),
                Some(value),
                "{key}"
            );
        }
    }
}

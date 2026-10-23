//! `detectServerMachineKind` (`ServerMachineKind.ts`).
use super::{ReadFile, Run, is_js_space, normalize};
use std::time::Duration;

/// `os` is Node's `process.platform`. `None` means the descriptor omits `platform.machine`.
pub fn detect(os: &str, run: Run, read: ReadFile) -> Option<&'static str> {
    match os {
        "darwin" => darwin(run),
        "linux" => linux(read),
        _ => None,
    }
}

const DMI_ROOT: &str = "/sys/class/dmi/id";

/// `DMI_CHASSIS_KINDS` (SMBIOS System Enclosure types).
fn chassis_kind(t: &str) -> Option<&'static str> {
    Some(match t {
        "3" | "4" | "5" | "6" | "7" | "13" | "15" | "16" | "35" => "desktop",
        "8" | "9" | "10" | "14" | "31" | "32" => "laptop",
        "17" | "18" | "19" | "20" | "21" | "22" | "23" | "24" | "28" => "server",
        _ => return None,
    })
}

const VIRTUALIZATION_MARKERS: [&str; 18] = [
    "qemu",
    "kvm",
    "bochs",
    "vmware",
    "virtualbox",
    "innotek",
    "xen",
    "parallels",
    "amazon ec2",
    "google compute engine",
    "digitalocean",
    "hetzner",
    "linode",
    "vultr",
    "scaleway",
    "openstack",
    "cloud",
    "virtual machine",
];

fn from_apple_product_name(name: &str) -> Option<&'static str> {
    let n: String = name
        .to_lowercase()
        .chars()
        .filter(|c| !is_js_space(*c))
        .collect();
    if n.starts_with("macmini") {
        Some("mac-mini")
    } else if n.starts_with("macstudio") {
        Some("mac-studio")
    } else if n.starts_with("macbook") {
        Some("laptop")
    } else if n.starts_with("imac") || n.starts_with("macpro") {
        Some("desktop")
    } else {
        None
    }
}

/// The first match of `/"product-name"\s*=\s*<"([^"]+)">/`.
fn ioreg_product_name(s: &str) -> Option<&str> {
    const KEY: &str = "\"product-name\"";
    s.match_indices(KEY).find_map(|(i, _)| {
        let r = s[i + KEY.len()..].trim_start_matches(is_js_space);
        let r = r.strip_prefix('=')?.trim_start_matches(is_js_space);
        let r = r.strip_prefix("<\"")?;
        let end = r.find('"').filter(|&e| e > 0)?;
        r[end..].starts_with("\">").then(|| &r[..end])
    })
}

fn darwin(run: Run) -> Option<&'static str> {
    let probe = |c: &str, a: &[&str]| {
        run(c, a, Duration::from_secs(5)).and_then(|o| normalize(&o).map(str::to_owned))
    };
    let ioreg = probe("ioreg", &["-rd1", "-n", "product"]);
    if let Some(k) = ioreg
        .as_deref()
        .and_then(ioreg_product_name)
        .and_then(from_apple_product_name)
    {
        return Some(k);
    }
    probe("sysctl", &["-n", "hw.model"]).and_then(|m| from_apple_product_name(&m))
}

fn linux(read: ReadFile) -> Option<&'static str> {
    let file = |p: &str| read(p).and_then(|s| normalize(&s).map(str::to_owned));
    let kernel = file("/proc/sys/kernel/osrelease");
    let chassis = file(&format!("{DMI_ROOT}/chassis_type"));
    let vendor = file(&format!("{DMI_ROOT}/sys_vendor"));
    let product = file(&format!("{DMI_ROOT}/product_name")).unwrap_or_default();
    // WSL 2 presents as a Hyper-V VM, so check its kernel first.
    if kernel.is_some_and(|k| k.to_lowercase().contains("microsoft")) {
        return Some("linux");
    }
    let vendor_and_product = format!("{} {product}", vendor.unwrap_or_default()).to_lowercase();
    if VIRTUALIZATION_MARKERS
        .iter()
        .any(|m| vendor_and_product.contains(m))
    {
        return Some("cloud");
    }
    from_apple_product_name(&product).or_else(|| chassis.as_deref().and_then(chassis_kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IOREG_APPLE_SILICON: &str = r#"+-o product  <class IOPlatformDevice, id 0x100000200, registered, matched, active, busy 0 (0 ms), retain 7>
    {
      "product-soc-name" = <"Test SoC">
      "product-name" = <"MacBook Pro (16-inch, 2099)">
      "compatible" = <"TestBoard">
    }
"#;

    fn darwin(ioreg: Option<&str>, model: Option<&str>) -> Option<&'static str> {
        let run = |c: &str, a: &[&str], t: Duration| {
            assert_eq!(t, Duration::from_secs(5));
            match (c, a) {
                ("ioreg", ["-rd1", "-n", "product"]) => ioreg.map(str::to_owned),
                ("sysctl", ["-n", "hw.model"]) => model.map(str::to_owned),
                _ => panic!("unexpected {c} {a:?}"),
            }
        };
        detect("darwin", &run, &|_| panic!("no files on darwin"))
    }

    #[test]
    fn darwin_reads_ioreg_product_name() {
        assert_eq!(darwin(Some(IOREG_APPLE_SILICON), None), Some("laptop"));
        let mini = r#"  "product-name" = <"Mac mini (2099)">"#;
        assert_eq!(darwin(Some(mini), None), Some("mac-mini"));
        let studio = r#""product-name"=<"Mac Studio (2099)">"#;
        assert_eq!(darwin(Some(studio), None), Some("mac-studio"));
        let imac = r#""product-name" = <"iMac (24-inch, 2099)">"#;
        assert_eq!(darwin(Some(imac), None), Some("desktop"));
    }

    #[test]
    fn darwin_falls_back_to_hw_model() {
        assert_eq!(darwin(None, Some("Macmini8,1\n")), Some("mac-mini"));
        assert_eq!(
            darwin(Some("no product here"), Some("MacPro7,1")),
            Some("desktop")
        );
        // An unknown product name also falls through to hw.model.
        let vm = r#""product-name" = <"Test Virtual">"#;
        assert_eq!(darwin(Some(vm), Some("MacBookAir10,1")), Some("laptop"));
        assert_eq!(darwin(None, Some("VirtualMac2,1")), None);
        assert_eq!(darwin(None, None), None);
    }

    fn linux(files: &[(&str, &str)]) -> Option<&'static str> {
        let read = |p: &str| {
            files
                .iter()
                .find(|(k, _)| *k == p)
                .map(|(_, v)| (*v).to_owned())
        };
        detect("linux", &|_, _, _| panic!("no commands on linux"), &read)
    }

    #[test]
    fn linux_reads_dmi() {
        let chassis = |t| linux(&[("/sys/class/dmi/id/chassis_type", t)]);
        assert_eq!(chassis("10\n"), Some("laptop"));
        assert_eq!(chassis("3"), Some("desktop"));
        assert_eq!(chassis("23"), Some("server"));
        assert_eq!(chassis("2"), None);
        assert_eq!(linux(&[]), None);
        let vm = [
            ("/sys/class/dmi/id/chassis_type", "1"),
            ("/sys/class/dmi/id/sys_vendor", "QEMU\n"),
            (
                "/sys/class/dmi/id/product_name",
                "Standard PC (Q35 + ICH9, 2009)",
            ),
        ];
        assert_eq!(linux(&vm), Some("cloud"));
        let hyperv = [
            ("/sys/class/dmi/id/sys_vendor", "Microsoft Corporation"),
            ("/sys/class/dmi/id/product_name", "Virtual Machine"),
        ];
        assert_eq!(linux(&hyperv), Some("cloud"));
        let apple = [
            ("/sys/class/dmi/id/chassis_type", "3"),
            ("/sys/class/dmi/id/sys_vendor", "Apple Inc."),
            ("/sys/class/dmi/id/product_name", "MacBookPro11,1"),
        ];
        assert_eq!(linux(&apple), Some("laptop"));
    }

    #[test]
    fn wsl_reads_as_linux_before_dmi() {
        let wsl = [
            (
                "/proc/sys/kernel/osrelease",
                "5.15.0-test-microsoft-standard-WSL2",
            ),
            ("/sys/class/dmi/id/product_name", "Virtual Machine"),
        ];
        assert_eq!(linux(&wsl), Some("linux"));
    }

    #[test]
    fn other_platforms_have_no_kind() {
        assert_eq!(detect("win32", &|_, _, _| panic!(), &|_| panic!()), None);
    }
}

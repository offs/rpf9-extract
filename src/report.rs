use crate::scan::Scan;
use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    ops::Range,
};

pub struct Report<'a> {
    pub name: &'a str,
    pub scan: &'a Scan<'a>,
}

impl Display for Report<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let scan = self.scan;
        let bytes = grouped(scan.data.len());
        let archives = match scan.archives.len() {
            0 => "no 9FPR header".into(),
            1 => "1 archive".into(),
            n => format!("{n} archives"),
        };
        writeln!(f, "{}  {bytes} B  {archives}", self.name)?;
        archives_table(f, scan)?;
        types(f, scan)?;
        coverage(f, scan)?;
        if f.alternate() {
            headers(f, scan)?;
        }
        Ok(())
    }
}

fn grouped(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

pub fn size(bytes: usize) -> String {
    const UNITS: [&str; 3] = ["KiB", "MiB", "GiB"];
    match (bytes.max(1).ilog2() / 10).min(3) {
        0 => format!("{bytes} B"),
        unit => {
            let value = bytes as f64 / (1u64 << (10 * unit)) as f64;
            format!("{value:.1} {}", UNITS[unit as usize - 1])
        }
    }
}

fn hex(range: &Range<usize>) -> String {
    format!("{:#x}..{:#x}", range.start, range.end)
}

fn archives_table(f: &mut Formatter, scan: &Scan) -> fmt::Result {
    if scan.archives.is_empty() {
        return Ok(());
    }
    let nested = scan.archives.iter().skip(1).map(|archive| (archive.header.at, "rpf"));
    let files = scan.files.iter().map(|file| (file.span.start, file.kind.label().0));
    let mut found: BTreeMap<(usize, &str), usize> = BTreeMap::new();
    for (at, ext) in nested.chain(files) {
        *found.entry((scan.owner(at), ext)).or_default() += 1;
    }

    writeln!(f, "\n    archive        size   files   found   contents")?;
    for archive in &scan.archives {
        let (at, files) = (archive.header.at, archive.header.files as usize);
        let size = size(archive.extent().len());
        let (mut contents, mut total) = (Vec::new(), 0);
        for (&(owner, ext), &n) in &found {
            if owner == at {
                contents.push(format!("{n} {ext}"));
                total += n;
            }
        }
        let all = if total == files { '✓' } else { ' ' };
        let contents = contents.join(", ");
        writeln!(f, "{at:>#11x}  {size:>10}  {files:>6}  {total:>6} {all}  {contents}")?;
    }
    Ok(())
}

fn types(f: &mut Formatter, scan: &Scan) -> fmt::Result {
    if scan.files.is_empty() {
        return writeln!(f, "\nno files found");
    }
    let mut types: BTreeMap<&str, (&str, usize, usize)> = BTreeMap::new();
    for file in &scan.files {
        let (ext, kind) = file.kind.label();
        let (_, files, bytes) = types.entry(ext).or_insert((kind, 0, 0));
        *files += 1;
        *bytes += file.size();
    }
    writeln!(f, "\n  type   files        size  kind")?;
    for (ext, (kind, files, bytes)) in types {
        writeln!(f, "{ext:>6}  {files:>6}  {:>10}  {kind}", size(bytes))?;
    }
    Ok(())
}

fn coverage(f: &mut Formatter, scan: &Scan) -> fmt::Result {
    let coverage = &scan.coverage;
    let rows = [
        ("structure", coverage.structure),
        ("zlib", coverage.zlib),
        ("media", coverage.media),
        ("stored", coverage.stored),
        ("padding", coverage.padding),
        ("unexplained", coverage.unexplained),
    ];
    writeln!(f, "\n    coverage           bytes  share")?;
    for (name, bytes) in rows {
        let share = bytes as f64 * 100.0 / scan.data.len().max(1) as f64;
        writeln!(f, "{name:>12}  {:>14}  {share:>5.1}%", grouped(bytes))?;
    }
    Ok(())
}

fn headers(f: &mut Formatter, scan: &Scan) -> fmt::Result {
    for archive in &scan.archives {
        let header = &archive.header;
        let [first, second] = header.records();
        let (x20, x28, x2c) = header.unknown;
        writeln!(f, "\narchive {}", hex(&archive.extent()))?;
        writeln!(f, "  0x04 length   {:#x}", header.len)?;
        writeln!(f, "  0x08 split    {:#x}  ({first} + {second} records)", header.split)?;
        writeln!(f, "  0x0c trailer  {:#x}", header.trailer)?;
        writeln!(f, "  0x10 id       {:#018x}", header.id)?;
        writeln!(f, "  0x20 unknown  {} {}", x20[0], x20[1])?;
        writeln!(f, "  0x24 files    {}", header.files)?;
        writeln!(f, "  0x28 unknown  {x28:#010x}")?;
        writeln!(
            f,
            "  0x2c selector {:#06x}  (stride {}{})",
            x2c[0],
            header.stride(),
            if header.toc_matches() { "" } else { ", region does not match" }
        )?;
        writeln!(f, "  body          {}", hex(&archive.body))?;
        writeln!(f, "  trailer       {}", hex(&archive.trailer))?;
    }
    Ok(())
}

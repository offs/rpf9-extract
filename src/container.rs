use crate::{
    bytes::{le16, le32, le64},
    ranges::gaps,
};
use std::{iter::once, ops::Range};

pub const SECTOR: usize = 0x1000;
pub const ALIGN: usize = 16;
const MAGIC: &[u8] = b"9FPR";
const HEADER: usize = 0x40;
const RECORD: usize = 16;

#[derive(Clone, Copy)]
pub struct Header {
    pub at: usize,
    pub len: usize,
    pub split: usize,
    pub trailer: usize,
    pub id: u64,
    pub files: u32,
    pub unknown: ([u16; 2], u32, [u16; 2]),
}

impl Header {
    fn parse(data: &[u8], at: usize) -> Option<Self> {
        let h = data.get(at..)?.first_chunk::<HEADER>()?;
        if !h.starts_with(MAGIC) {
            return None;
        }
        let (len, split) = (le32(h, 0x04)? as usize, le32(h, 0x08)? as usize);
        let tables = [split.checked_sub(HEADER)?, len.checked_sub(split)?];
        if at + len > data.len() || tables.iter().any(|table| table % RECORD != 0) {
            return None;
        }
        Some(Self {
            at,
            len,
            split,
            trailer: le32(h, 0x0c)? as usize,
            id: le64(h, 0x10)?,
            files: le32(h, 0x24)?,
            unknown: (
                [le16(h, 0x20)?, le16(h, 0x22)?],
                le32(h, 0x28)?,
                [le16(h, 0x2c)?, le16(h, 0x2e)?],
            ),
        })
    }

    /// Bytes per entry in the TOC region, from the low byte of `0x2c`.
    ///
    /// The region is 16-byte aligned, the entries are not: they are 9 bytes when
    /// the low byte is 1 and 10 when it is 2. Measured on 77 headers read from a
    /// retail package: 54/54 and 15/15 exact.
    pub fn stride(&self) -> usize {
        match (self.unknown.2[0] & 0xff) as u32 {
            2 => 10,
            _ => 9,
        }
    }

    /// Length the TOC region should have for the declared entry count.
    pub fn toc_len(&self) -> usize {
        let stride = self.stride();
        let entries = self.files as usize;
        (stride * entries).div_ceil(ALIGN) * ALIGN
    }

    /// Whether the region length matches the entry count and the stride.
    ///
    /// A mismatch is reported, not rejected: a handful of headers use a wider
    /// stride this crate does not model yet, and dropping them would lose files.
    pub fn toc_matches(&self) -> bool {
        self.len - self.split == self.toc_len()
    }

    /// Entries per table.
    ///
    /// The second table's length is padded to 16, so dividing it by 16 returns a
    /// number smaller than the header's own count. `0x24` is the count.
    pub fn records(&self) -> [usize; 2] {
        [self.split - HEADER, self.files as usize]
    }
}

pub struct Archive {
    pub header: Header,
    pub body: Range<usize>,
    pub trailer: Range<usize>,
}

impl Archive {
    pub fn extent(&self) -> Range<usize> {
        self.header.at..self.trailer.end
    }

    pub fn structure(&self) -> [Range<usize>; 2] {
        [self.header.at..self.body.start, self.trailer.clone()]
    }
}

pub fn layout(data: &[u8], known: &[Range<usize>]) -> Vec<Archive> {
    let headers: Vec<_> = gaps(&(0..data.len()), known)
        .into_iter()
        .flat_map(|gap| (gap.start.next_multiple_of(SECTOR)..gap.end).step_by(SECTOR))
        .filter_map(|at| Header::parse(data, at))
        .collect();
    let Some((&outer, nested)) = headers.split_first() else {
        return Vec::new();
    };
    let outer = place(data, outer, data.len(), known);
    let next = nested.iter().skip(1).map(|header| header.at);
    let limits = next.chain([outer.trailer.start]);
    let nested: Vec<_> = nested
        .iter()
        .zip(limits)
        .map(|(&header, limit)| place(data, header, limit, known))
        .collect();
    once(outer).chain(nested).collect()
}

// The tables that say where an archive ends are encrypted. Its trailer is the
// last thing it stores, and what may follow before `limit` is zero padding and
// files of the enclosing archive, so the trailer ends at the last byte that is
// neither zero nor part of a known file.
fn place(data: &[u8], header: Header, limit: usize, known: &[Range<usize>]) -> Archive {
    let start = header.at + header.len;
    let limit = limit.max(start);
    let end_of_data = |gap: &Range<usize>| {
        let last = data[gap.clone()].iter().rposition(|&byte| byte != 0)?;
        Some(gap.start + last + 1)
    };
    let end = gaps(&(start..limit), known).iter().rev().find_map(end_of_data).unwrap_or(start);
    let end = end.next_multiple_of(ALIGN).min(limit);
    let trailer = end.saturating_sub(header.trailer).max(start)..end;
    Archive { header, body: start..trailer.start, trailer }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(len: u32, split: u32, files: u32, sel: u16) -> Vec<u8> {
        // parse() bounds-checks the whole region, so the buffer has to hold it
        let mut h = vec![0u8; len as usize];
        h[..4].copy_from_slice(MAGIC);
        h[0x04..0x08].copy_from_slice(&len.to_le_bytes());
        h[0x08..0x0c].copy_from_slice(&split.to_le_bytes());
        h[0x24..0x28].copy_from_slice(&files.to_le_bytes());
        h[0x2c..0x2e].copy_from_slice(&sel.to_le_bytes());
        h[0x30..0x34].copy_from_slice(&(ALIGN as u32).to_le_bytes());
        h
    }

    #[test]
    fn stride_follows_the_selector_byte() {
        let nine = Header::parse(&header(0x2000, 0x80, 10, 0x0f01), 0).unwrap();
        assert_eq!(nine.stride(), 9);
        let ten = Header::parse(&header(0x2000, 0x80, 10, 0x0f02), 0).unwrap();
        assert_eq!(ten.stride(), 10);
    }

    #[test]
    fn record_count_comes_from_the_header_not_from_division() {
        // 2078 entries of 9 bytes is 18702 bytes, padded to 18704; dividing by 16
        // would report 1169.
        let region = (9 * 2078usize).div_ceil(ALIGN) * ALIGN;
        let split = 0x40 + 0x200;
        let h = Header::parse(&header((split + region) as u32, split as u32, 2078, 0x0f01), 0).unwrap();
        assert_eq!(h.records()[1], 2078);
        assert!(h.toc_matches());
    }

    #[test]
    fn toc_len_matches_the_formula() {
        let nine = Header::parse(&header(0x2000, 0x80, 194, 0x0f01), 0).unwrap();
        assert_eq!(nine.toc_len(), (9 * 194usize).div_ceil(ALIGN) * ALIGN);
        let ten = Header::parse(&header(0x2000, 0x80, 265, 0x0f02), 0).unwrap();
        assert_eq!(ten.toc_len(), (10 * 265usize).div_ceil(ALIGN) * ALIGN);
    }
}

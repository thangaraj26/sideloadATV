//! CgBI PNG normalizer.
//!
//! Apple's iOS asset pipeline produces a non-standard PNG variant identified by
//! a `CgBI` chunk inserted before `IHDR`. These PNGs differ from the spec in
//! three ways:
//!
//! 1. A proprietary `CgBI` chunk precedes `IHDR`.
//! 2. IDAT is compressed with raw Deflate — the zlib wrapper is stripped.
//! 3. Pixel data is BGRA with premultiplied alpha instead of straight RGBA.
//!
//! [`normalize`] converts such files to standards-compliant PNGs in-memory so
//! that libraries like `iced` / the `image` crate can decode them. Non-CgBI
//! data should return unchanged.

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::ZlibEncoder;
use std::io::{Read, Write};

const PNG_SIG: &[u8] = &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/// Normalises a PNG buffer. Returns a standard PNG on success, otherwise returns
/// the original buffer unchanged.
pub fn normalize(data: Vec<u8>) -> Vec<u8> {
    if !is_cgbi(&data) {
        return data;
    }

    match normalize_impl(data.as_slice()) {
        Some(out) => out,
        None => data,
    }
}

fn is_cgbi(data: &[u8]) -> bool {
    if data.len() < 20 || &data[..8] != PNG_SIG {
        return false;
    }
    // The CgBI chunk immediately follows the signature.
    // Layout: [4 len][4 name][len data][4 crc] — we only need the name.
    &data[12..16] == b"CgBI"
}

/// Normalises a PNG buffer. Returns `None` if any step fails.
fn normalize_impl(data: &[u8]) -> Option<Vec<u8>> {
    let (header, raw_idat) = parse_chunks(data)?;

    let width = header.width;
    let height = header.height;

    // Only 8-bit RGBA (color_type 6) can be fixed trivially.
    if header.bit_depth != 8 || header.color_type != 6 {
        return None;
    }

    // Decompress raw Deflate (CgBI removes the zlib header/trailer).
    let mut dec = DeflateDecoder::new(raw_idat.as_slice());
    let mut filtered = Vec::new();
    dec.read_to_end(&mut filtered).ok()?;

    let stride = width as usize * 4;
    if filtered.len() < height as usize * (1 + stride) {
        return None;
    }

    // Un-filter rows, then swap BGRA premul → RGBA straight.
    let pixels = unfilter_and_fix_pixels(&filtered, width, height, stride)?;

    // Re-filter with None (type 0) and zlib-compress.
    let compressed = recompress(&pixels, stride)?;

    Some(build_png(&header.ihdr_data, &header.ancillary, &compressed))
}

struct ImageHeader {
    width: u32,
    height: u32,
    bit_depth: u8,
    color_type: u8,
    /// raw IHDR chunk data (13 bytes) preserved verbatim.
    ihdr_data: Vec<u8>,
    /// other chunks to carry through (everything except CgBI and IDAT).
    ancillary: Vec<(Vec<u8>, Vec<u8>)>,
}

fn parse_chunks(data: &[u8]) -> Option<(ImageHeader, Vec<u8>)> {
    let mut width = 0u32;
    let mut height = 0u32;
    let mut bit_depth = 0u8;
    let mut color_type = 0u8;
    let mut ihdr_data = Vec::new();
    let mut ancillary: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut raw_idat: Vec<u8> = Vec::new();

    let mut pos = 8usize; // skip signature
    while pos + 12 <= data.len() {
        let length = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        let name = &data[pos + 4..pos + 8];
        let end = pos + 8 + length;
        if end > data.len() {
            break;
        }
        let body = &data[pos + 8..end];

        match name {
            b"CgBI" => { /* who care */ }
            b"IHDR" if body.len() >= 13 => {
                width = u32::from_be_bytes(body[0..4].try_into().ok()?);
                height = u32::from_be_bytes(body[4..8].try_into().ok()?);
                bit_depth = body[8];
                color_type = body[9];
                ihdr_data = body.to_vec();
                ancillary.push((name.to_vec(), body.to_vec()));
            }
            b"IDAT" => raw_idat.extend_from_slice(body),
            b"IEND" => {
                ancillary.push((name.to_vec(), body.to_vec()));
                break;
            }
            _ => ancillary.push((name.to_vec(), body.to_vec())),
        }

        pos = end + 4; // skip 4-byte CRC
    }

    if ihdr_data.is_empty() || raw_idat.is_empty() {
        return None;
    }

    Some((
        ImageHeader {
            width,
            height,
            bit_depth,
            color_type,
            ihdr_data,
            ancillary,
        },
        raw_idat,
    ))
}

fn unfilter_and_fix_pixels(
    filtered: &[u8],
    _width: u32,
    height: u32,
    stride: usize,
) -> Option<Vec<u8>> {
    let mut pixels = Vec::with_capacity(height as usize * stride);
    let mut src = 0usize;
    let mut prev_row = vec![0u8; stride];

    for _ in 0..height {
        let filter = *filtered.get(src)?;
        src += 1;
        let raw = filtered.get(src..src + stride)?;
        src += stride;

        let row = apply_filter(filter, raw, &prev_row, 4);

        // BGRA premultiplied -> RGBA straight alpha
        for px in row.chunks_exact(4) {
            let (b, g, r, a) = (px[0], px[1], px[2], px[3]);
            match a {
                0 => pixels.extend_from_slice(&[0, 0, 0, 0]),
                255 => pixels.extend_from_slice(&[r, g, b, 255]),
                _ => {
                    let inv = 255.0 / a as f32;
                    pixels.push((r as f32 * inv).round().min(255.0) as u8);
                    pixels.push((g as f32 * inv).round().min(255.0) as u8);
                    pixels.push((b as f32 * inv).round().min(255.0) as u8);
                    pixels.push(a);
                }
            }
        }

        prev_row = row;
    }

    Some(pixels)
}

fn recompress(pixels: &[u8], stride: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(pixels.len() + pixels.len() / stride);
    for row in pixels.chunks(stride) {
        buf.push(0); // filter type: None
        buf.extend_from_slice(row);
    }

    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&buf).ok()?;
    enc.finish().ok()
}

fn build_png(ihdr_data: &[u8], ancillary: &[(Vec<u8>, Vec<u8>)], idat: &[u8]) -> Vec<u8> {
    let _ = ihdr_data; // IHDR is already in ancillary
    let mut out = Vec::new();
    out.extend_from_slice(PNG_SIG);
    for (name, body) in ancillary {
        if name.as_slice() == b"IEND" {
            write_chunk(&mut out, b"IDAT", idat);
        }
        write_chunk(&mut out, name, body);
    }
    out
}

fn write_chunk(out: &mut Vec<u8>, name: &[u8], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32(name, data).to_be_bytes());
}

fn apply_filter(filter: u8, raw: &[u8], prev: &[u8], bpp: usize) -> Vec<u8> {
    let mut row = vec![0u8; raw.len()];
    match filter {
        0 => row.copy_from_slice(raw),
        1 => {
            for i in 0..raw.len() {
                let a = if i >= bpp { row[i - bpp] } else { 0 };
                row[i] = raw[i].wrapping_add(a);
            }
        }
        2 => {
            for i in 0..raw.len() {
                row[i] = raw[i].wrapping_add(prev[i]);
            }
        }
        3 => {
            for i in 0..raw.len() {
                let a = if i >= bpp { row[i - bpp] } else { 0 };
                row[i] = raw[i].wrapping_add(((a as u16 + prev[i] as u16) / 2) as u8);
            }
        }
        4 => {
            for i in 0..raw.len() {
                let a = if i >= bpp { row[i - bpp] } else { 0 };
                let b = prev[i];
                let c = if i >= bpp { prev[i - bpp] } else { 0 };
                row[i] = raw[i].wrapping_add(paeth(a, b, c));
            }
        }
        _ => row.copy_from_slice(raw),
    }
    row
}

#[inline]
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (a, b, c) = (a as i32, b as i32, c as i32);
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

/// CRC-32 - IEEE 802.3
fn crc32(name: &[u8], data: &[u8]) -> u32 {
    const fn make_table() -> [u32; 256] {
        let mut t = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xEDB88320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    }
    static TABLE: [u32; 256] = make_table();
    let mut crc = 0xFFFF_FFFFu32;
    for &b in name.iter().chain(data.iter()) {
        crc = TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

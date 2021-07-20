//! Some helpers for writing response data, shared between `BlockDevice` and
//! `MissingLun`

use std::cmp::min;

/// A wrapper around a `Write` that silently truncates its input after a given
/// number of bytes. This matches the semantics of SCSI's ALLOCATION LENGTH
/// field; anything beyond the allocation length is silently omitted.
pub struct SilentlyTruncate<W: Write>(W, usize);

impl<W: Write> SilentlyTruncate<W> {
    pub fn new(writer: W, len: usize) -> Self {
        Self(writer, len)
    }
}

impl<W: Write> Write for SilentlyTruncate<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.1 == 0 {
            // our goal is to silently fail, so once we've stopped actually
            // writing, just pretend all writes work
            return Ok(buf.len());
        }
        let len = min(buf.len(), self.1);
        let buf = &buf[..len];
        let written = self.0.write(buf)?;
        self.1 -= written;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

use std::{convert::TryFrom, io, io::Write};

fn encode_lun(lun: u16) -> [u8; 8] {
    // TODO: Support LUNs over 256
    // We do check we have under 256 LUNs in main, so this assert/unwrap should be
    // safe
    assert!(lun < 256);
    [0, u8::try_from(lun).unwrap(), 0, 0, 0, 0, 0, 0]
}

/// Write the response data for a REPORT LUNS command.
pub fn respond_report_luns(
    data_in: &mut impl Write,
    luns: impl Iterator<Item = u16> + ExactSizeIterator,
) -> io::Result<()> {
    // unwrap is safe: we ensure we have under 256 LUNs
    data_in.write_all(&(u32::try_from(luns.len() * 8)).unwrap().to_be_bytes())?;
    data_in.write_all(&[0; 4])?; // reserved
    for lun in luns {
        data_in.write_all(&encode_lun(lun))?;
    }
    Ok(())
}

/// Write the response data for a standard (i.e. not VPD) inquiry, excluding the
/// first byte (the peripheal qualifier and device type).
pub fn respond_standard_inquiry_data(data_in: &mut impl Write) -> io::Result<()> {
    // TODO: Feature bits here we might want to support:
    // - NormACA
    // - command queueing
    data_in.write_all(&[
        // various bits: not removable, not part of a
        // conglomerate, no info on hotpluggability
        0,
        0x7, // version: SPC-6
        // bits: don't support NormACA, support modern LUN format
        // INQUIRY data version 2
        0b0001_0000 | 0x2,
        91, // additional INQURIY data length
        // bunch of feature bits we don't support:
        0,
        0,
        0,
    ])?;

    // TODO: register this or another name with T10
    data_in.write_all(b"rust-vmm")?;
    data_in.write_all(b"vhost-user-scsi ")?;
    data_in.write_all(b"v0  ")?;

    // The Linux kernel doesn't request any more than this, so any data we return
    // after this point is mostly academic.

    data_in.write_all(&[0; 22])?;

    let product_descs: &[u16; 8] = &[
        0x00c0, // SAM-6 (no version claimed)
        0x05c0, // SPC-5 (no version claimed)
        0x0600, // SBC-4 (no version claimed)
        0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    for desc in product_descs {
        data_in.write_all(&desc.to_be_bytes())?;
    }

    data_in.write_all(&[0; 22])?;

    Ok(())
}

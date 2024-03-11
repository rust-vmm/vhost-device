// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Null media backend.
//!
//! A no-op backend that presents itself as a V4L2 device but rejects all
//! media operations with `ENOTTY`.

use std::os::fd::BorrowedFd;

use virtio_media::{
    io::WriteToDescriptorChain, protocol::V4l2Ioctl, VirtioMediaDevice, VirtioMediaDeviceSession,
};

use crate::vhu_media::{Reader, Writer};

/// Session handle for the null backend — no file descriptor to poll.
pub struct NullSession;

impl VirtioMediaDeviceSession for NullSession {
    fn poll_fd(&self) -> Option<BorrowedFd<'_>> {
        None
    }
}

/// Null media device: accepts guest connections but returns `ENOTTY` for
/// every ioctl and rejects every mmap request.
pub struct NullMediaDevice;

impl VirtioMediaDevice<Reader, Writer> for NullMediaDevice {
    type Session = NullSession;

    fn new_session(&mut self, _session_id: u32) -> Result<NullSession, i32> {
        Ok(NullSession)
    }

    fn close_session(&mut self, _session: NullSession) {}

    fn do_ioctl(
        &mut self,
        _session: &mut NullSession,
        _ioctl: V4l2Ioctl,
        _reader: &mut Reader,
        writer: &mut Writer,
    ) -> std::io::Result<()> {
        writer.write_err_response(libc::ENOTTY)
    }

    fn do_mmap(
        &mut self,
        _session: &mut NullSession,
        _flags: u32,
        _offset: u32,
    ) -> Result<(u64, u64), i32> {
        Err(libc::ENOTTY)
    }

    fn do_munmap(&mut self, _guest_addr: u64) -> Result<(), i32> {
        Ok(())
    }

    fn process_events(&mut self, _session: &mut NullSession) -> Result<(), i32> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_session_poll_fd_is_none() {
        let session = NullSession;
        assert!(session.poll_fd().is_none());
    }

    #[test]
    fn test_null_device_new_session_succeeds() {
        let mut device = NullMediaDevice;
        device.new_session(0).unwrap();
        device.new_session(42).unwrap();
    }

    #[test]
    fn test_null_device_close_session_is_noop() {
        let mut device = NullMediaDevice;
        let session = device.new_session(0).unwrap();
        device.close_session(session); // must not panic
    }

    #[test]
    fn test_null_device_do_mmap_returns_enotty() {
        let mut device = NullMediaDevice;
        let mut session = device.new_session(0).unwrap();
        assert_eq!(device.do_mmap(&mut session, 0, 0), Err(libc::ENOTTY));
    }

    #[test]
    fn test_null_device_do_munmap_succeeds() {
        let mut device = NullMediaDevice;
        assert_eq!(device.do_munmap(0), Ok(()));
        assert_eq!(device.do_munmap(u64::MAX), Ok(()));
    }

    #[test]
    fn test_null_device_process_events_succeeds() {
        let mut device = NullMediaDevice;
        let mut session = device.new_session(0).unwrap();
        assert_eq!(device.process_events(&mut session), Ok(()));
    }
}

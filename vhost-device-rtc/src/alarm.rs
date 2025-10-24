// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>

//! Alarm functionality
//!
//! The struct [`Alarm`] holds the alarm time and its enabled status.
//! If the alarm is enabled, it holds an alarm worker thread handle that sleeps
//! until the alarm time is reached and notifies the guest.
//!
//! When dropped, the alarm worker is cancelled (or made obsolete in VIRTIO spec
//! terminology).

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::JoinHandle,
};

use thiserror::Error as ThisError;
use vhost_user_backend::VringT;

use crate::backend::VirtioRtcDevice;

#[derive(Debug, ThisError)]
/// Alarm errors
pub enum Error {
    #[error("Could not write alarm notification to queue: {0}")]
    QueueIO(#[from] std::io::Error),
    #[error("Could not add used bytes to queue: {0}")]
    Queue(#[from] virtio_queue::Error),
    #[error("Poisoned mutex")]
    Poisoned,
}

#[derive(Debug)]
pub struct Alarm {
    /// Used to report alarm time with `VIRTIO_RTC_REQ_READ_ALARM` requests.
    alarm_time: u64,
    /// Used to report alarm status with `VIRTIO_RTC_REQ_READ_ALARM` requests.
    enabled: bool,
    /// Thread worker that sleeps and expires alarm (unless cancelled)
    worker: Option<AlarmWorker>,
}

impl Default for Alarm {
    fn default() -> Self {
        Self::new()
    }
}

impl Alarm {
    #[inline]
    pub fn new() -> Self {
        Self {
            enabled: false,
            alarm_time: 0,
            worker: None,
        }
    }

    #[inline]
    pub fn set_time(&mut self, alarm_time: u64) {
        self.alarm_time = alarm_time;
    }

    #[inline]
    pub fn disable(&mut self) {
        self.enabled = false;
        // Drop worker, and cancel it
        self.worker = None;
    }

    #[inline]
    pub fn enable(
        &mut self,
        device: Arc<(Mutex<VirtioRtcDevice>, Condvar)>,
        notif: crate::virtio_rtc::VirtioRtcNotifAlarm,
        dur: std::time::Duration,
    ) {
        self.enabled = true;
        self.worker = Some(AlarmWorker::new(device, notif, dur));
    }

    #[inline]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    #[inline]
    pub fn alarm_time(&self) -> u64 {
        self.alarm_time
    }
}

#[derive(Debug)]
struct AlarmWorker {
    cancellation_token: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<(), Error>>>,
}

impl AlarmWorker {
    fn new(
        device: Arc<(Mutex<VirtioRtcDevice>, Condvar)>,
        notif: crate::virtio_rtc::VirtioRtcNotifAlarm,
        dur: std::time::Duration,
    ) -> Self {
        let cancellation_token = Arc::new(AtomicBool::new(false));
        let handle = Some(std::thread::spawn({
            let cancellation_token = Arc::clone(&cancellation_token);
            move || {
                let clock_id: usize = u16::from(notif.clock_id).into();
                std::thread::sleep(dur);
                let obsolete = cancellation_token.load(Ordering::SeqCst);
                if obsolete {
                    return Ok(());
                }
                log::trace!("Clock {clock_id} alarm expired");
                let (lock, cvar) = &*device;
                let mut device = lock.lock().map_err(|_| Error::Poisoned)?;
                let buf = loop {
                    if !matches!(
                        device
                            .clocks
                            .get(clock_id)
                            .and_then(|c| Some(c.alarm.as_ref()?.enabled())),
                        Some(true)
                    ) {
                        // If the driver successfully disables an alarm for clock C
                        // with request VIRTIO_RTC_REQ_SET_ALARM or
                        // VIRTIO_RTC_REQ_SET_ALARM_ENABLED, the device MUST stop
                        // serving any previous alarm expiration event for C before
                        // the device uses the response buffer.
                        return Ok(());
                    }
                    // If the device is currently serving an alarm expiration event E,
                    // the device MUST use a single
                    // VIRTIO_RTC_NOTIF_ALARM notification for E,
                    // as soon as an alarmq buffer is available for this purpose.
                    if let Some(buf) = device.alarm_notif_buffers.pop() {
                        break buf;
                    };
                    device = cvar.wait(device).map_err(|_| Error::Poisoned)?;
                };

                let mem = buf.desc_chain.memory();
                let mut writer = buf.desc_chain.clone().writer(mem)?;
                writer.write_obj(notif)?;

                let used_len = writer.bytes_written();

                buf.vring
                    .add_used(buf.desc_chain.head_index(), used_len as u32)?;
                buf.vring.signal_used_queue()?;
                Ok(())
            }
        }));
        Self {
            cancellation_token,
            handle,
        }
    }
}

impl Drop for AlarmWorker {
    fn drop(&mut self) {
        self.cancellation_token.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            if handle.is_finished() {
                if let Ok(Err(err)) = handle.join() {
                    log::error!("{err}");
                }
            }
        }
    }
}

#[test]
fn test_alarm() {
    let mut alarm = Alarm::new();
    assert_eq!(alarm.alarm_time(), 0);
    assert!(!alarm.enabled());
    alarm.set_time(42);
    assert_eq!(alarm.alarm_time(), 42);
    assert!(!alarm.enabled());
}

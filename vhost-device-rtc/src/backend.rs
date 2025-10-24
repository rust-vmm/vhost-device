// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>

use std::{
    io::Result as IoResult,
    sync::{Arc, Condvar, Mutex},
};

use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
use vmm_sys_util::{
    epoll::EventSet,
    event::{new_event_consumer_and_notifier, EventConsumer, EventFlag, EventNotifier},
};

use crate::{
    clocks::Clock,
    virtio_rtc::{VirtioRtcReqHead, VirtioRtcRespHead},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ThisError)]
/// Errors related to vhost-device-rtc daemon.
pub enum Error {
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknown,
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Reading from descriptor failed")]
    DescriptorReadFailed,
    #[error("Writing to descriptor failed")]
    DescriptorWriteFailed,
    #[error("Failed to send notification")]
    NotificationFailed,
    #[error("No memory configured")]
    NoMemoryConfigured,
    #[error("Failed to create new EventFd")]
    EventFdFailed,
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::other(e)
    }
}

/// Alarm notification buffer populated by the driver in `alarmq`.
pub struct AlarmNotificationBuffer {
    pub desc_chain: DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>,
    pub vring: VringRwLock,
}

pub struct VirtioRtcDevice {
    pub clocks: Vec<Clock>,
    /// Store alarm notification buffer for use when an alarm expiration
    /// happens.
    pub alarm_notif_buffers: Vec<Arc<AlarmNotificationBuffer>>,
}

pub struct VhostUserRtcBackend {
    event_idx: bool,
    negotiated_features: u64,
    offer_alarm: bool,
    device: Arc<(Mutex<VirtioRtcDevice>, Condvar)>,
    exit_consumer: EventConsumer,
    pub(crate) exit_notifier: EventNotifier,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
}

impl VhostUserRtcBackend {
    pub fn new(offer_alarm: bool, clocks: Vec<Clock>) -> Result<Self> {
        let (exit_consumer, exit_notifier) = new_event_consumer_and_notifier(EventFlag::NONBLOCK)
            .map_err(|_| Error::EventFdFailed)?;
        Ok(VhostUserRtcBackend {
            event_idx: false,
            negotiated_features: 0,
            offer_alarm,
            device: Arc::new((
                Mutex::new(VirtioRtcDevice {
                    clocks,
                    alarm_notif_buffers: vec![],
                }),
                Condvar::new(),
            )),
            exit_consumer,
            exit_notifier,
            mem: None,
        })
    }

    const fn have_alarm(&self) -> bool {
        self.negotiated_features & (1 << crate::virtio_rtc::VIRTIO_RTC_F_ALARM) > 0
    }

    /// Process requestq buffers.
    fn process_request_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let Some(ref atomic_mem) = self.mem else {
            return Err(Error::NoMemoryConfigured);
        };
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if requests.is_empty() {
            return Ok(());
        }

        for desc_chain in requests {
            let mem = atomic_mem.memory();

            let mut reader = desc_chain
                .clone()
                .reader(&mem)
                .map_err(|_| Error::DescriptorReadFailed)?;
            let request = reader
                .read_obj::<VirtioRtcReqHead>()
                .map_err(|_| Error::DescriptorReadFailed)?;
            let mut writer = desc_chain
                .clone()
                .writer(&mem)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            let msg_type: u16 = u16::from(request.msg_type);
            let msg_type = RequestType::try_from(msg_type);

            log::trace!("Received request msg_type: {msg_type:?}");

            let have_alarm = self.have_alarm();
            match msg_type {
                Ok(RequestType::Cfg) => {
                    let num_clocks = {
                        let (lock, _cvar) = &*self.device;
                        let device = lock.lock().unwrap();
                        u16::try_from(device.clocks.len()).unwrap()
                    };
                    writer
                        .write_obj(crate::virtio_rtc::VirtioRtcRespCfg {
                            num_clocks: num_clocks.into(),
                            ..Default::default()
                        })
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                }
                Ok(RequestType::ClockCap) => {
                    let mut reader = desc_chain
                        .clone()
                        .reader(&mem)
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let request = reader
                        .read_obj::<crate::virtio_rtc::VirtioRtcReqClockCap>()
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let clock_id: usize = u16::from(request.clock_id).into();
                    let (lock, _cvar) = &*self.device;
                    let device = lock.lock().unwrap();
                    if let Some(clock) = device.clocks.get(clock_id) {
                        writer
                            .write_obj(crate::virtio_rtc::VirtioRtcRespClockCap {
                                leap_second_smearing:
                                    crate::virtio_rtc::VIRTIO_RTC_SMEAR_UNSPECIFIED,
                                r#type: clock.r#type,
                                flags: if have_alarm && clock.alarm.is_some() {
                                    crate::virtio_rtc::VIRTIO_RTC_FLAG_ALARM_CAP
                                } else {
                                    0
                                },
                                ..Default::default()
                            })
                            .map_err(|_| Error::DescriptorWriteFailed)?;
                    } else {
                        log::error!(
                            "Could not read clock capabilities for {clock_id:?}: not found"
                        );
                        writer
                            .write_obj(VirtioRtcRespHead {
                                status: crate::virtio_rtc::VIRTIO_RTC_S_EINVAL,
                                ..VirtioRtcRespHead::default()
                            })
                            .map_err(|_| Error::DescriptorWriteFailed)?;
                    }
                }
                Ok(RequestType::Read) => {
                    let mut reader = desc_chain
                        .clone()
                        .reader(&mem)
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let request = reader
                        .read_obj::<crate::virtio_rtc::VirtioRtcReqRead>()
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let clock_id: usize = u16::from(request.clock_id).into();
                    let (lock, _cvar) = &*self.device;
                    let device = lock.lock().unwrap();
                    if let Some(clock) = device.clocks.get(clock_id) {
                        match clock.read() {
                            Ok(clock_reading) => {
                                writer
                                    .write_obj(crate::virtio_rtc::VirtioRtcRespRead {
                                        clock_reading: clock_reading.into(),
                                        ..Default::default()
                                    })
                                    .map_err(|_| Error::DescriptorWriteFailed)?;
                            }
                            Err(err) => {
                                log::error!("Could not read clock {clock_id:?}: {err}");
                                writer
                                    .write_obj(VirtioRtcRespHead {
                                        status: crate::virtio_rtc::VIRTIO_RTC_S_EIO,
                                        ..VirtioRtcRespHead::default()
                                    })
                                    .map_err(|_| Error::DescriptorWriteFailed)?;
                            }
                        }
                    } else {
                        log::error!("Could not read clock for {clock_id:?}: not found");
                        writer
                            .write_obj(VirtioRtcRespHead {
                                status: crate::virtio_rtc::VIRTIO_RTC_S_EINVAL,
                                ..VirtioRtcRespHead::default()
                            })
                            .map_err(|_| Error::DescriptorWriteFailed)?;
                    }
                }
                Ok(RequestType::ReadCross) => {
                    writer
                        .write_obj(VirtioRtcRespHead {
                            status: crate::virtio_rtc::VIRTIO_RTC_S_EOPNOTSUPP,
                            ..VirtioRtcRespHead::default()
                        })
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                }
                Ok(RequestType::CrossCap) => {
                    writer
                        .write_obj(crate::virtio_rtc::VirtioRtcRespCrossCap::default())
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                }
                // If VIRTIO_RTC_F_ALARM has not been negotiated, the device MUST NOT support the
                // alarm messages.
                Ok(RequestType::ReadAlarm) if have_alarm => {
                    let mut reader = desc_chain
                        .clone()
                        .reader(&mem)
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let request = reader
                        .read_obj::<crate::virtio_rtc::VirtioRtcReqReadAlarm>()
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let clock_id: usize = u16::from(request.clock_id).into();
                    let (lock, _cvar) = &*self.device;
                    let device = lock.lock().unwrap();
                    if let Some(alarm) = device.clocks.get(clock_id).and_then(|c| c.alarm.as_ref())
                    {
                        writer
                            .write_obj(crate::virtio_rtc::VirtioRtcRespReadAlarm {
                                alarm_time: alarm.alarm_time().into(),
                                flags: if alarm.enabled() {
                                    crate::virtio_rtc::VIRTIO_RTC_FLAG_ALARM_ENABLED
                                } else {
                                    0
                                },
                                ..Default::default()
                            })
                            .map_err(|_| Error::DescriptorWriteFailed)?;
                    } else {
                        log::error!("Could not read alarm for {clock_id:?}: not found");
                        writer
                            .write_obj(VirtioRtcRespHead {
                                status: crate::virtio_rtc::VIRTIO_RTC_S_EINVAL,
                                ..VirtioRtcRespHead::default()
                            })
                            .map_err(|_| Error::DescriptorWriteFailed)?;
                    }
                }
                Ok(RequestType::SetAlarm) if have_alarm => {
                    let mut reader = desc_chain
                        .clone()
                        .reader(&mem)
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let request = reader
                        .read_obj::<crate::virtio_rtc::VirtioRtcReqSetAlarm>()
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let mut res = crate::virtio_rtc::VirtioRtcRespSetAlarm::default();
                    let clock_id: usize = u16::from(request.clock_id).into();
                    let (lock, _cvar) = &*self.device;
                    let mut device = lock.lock().unwrap();
                    if let Some((now, alarm)) = device.clocks.get_mut(clock_id).and_then(|c| {
                        let now = c.read();
                        Some((now, c.alarm.as_mut()?))
                    }) {
                        match now {
                            Ok(now) => {
                                let mut alarm_time = request.alarm_time.into();
                                alarm.set_time(alarm_time);
                                let enabled = request.flags
                                    & crate::virtio_rtc::VIRTIO_RTC_FLAG_ALARM_ENABLED
                                    > 0;
                                if alarm_time < now {
                                    // 5.23.6.6 Alarm Operation
                                    // An alarm expires in any of the following cases: [..] when
                                    // the driver sets an alarm time which is not in the future,
                                    // while also setting the alarm to enabled,
                                    alarm_time = now;
                                }
                                if enabled {
                                    let dur = std::time::Duration::from_nanos(alarm_time - now);
                                    log::trace!("Clock {clock_id} setting alarm {dur:?} from now");
                                    let mut notif =
                                        crate::virtio_rtc::VirtioRtcNotifAlarm::default();
                                    notif.head.msg_type =
                                        crate::virtio_rtc::VIRTIO_RTC_NOTIF_ALARM.into();
                                    notif.clock_id = request.clock_id;
                                    let device = Arc::clone(&self.device);
                                    alarm.enable(device, notif, dur);
                                } else {
                                    log::trace!("Clock {clock_id} disabling alarm");
                                    alarm.disable();
                                }
                            }
                            Err(err) => {
                                log::error!("Could not read clock {clock_id:?}: {err}");
                                res.head.status = crate::virtio_rtc::VIRTIO_RTC_S_EIO;
                            }
                        }
                    } else {
                        log::error!("Tried to set alarm on {clock_id:?} but it has no alarm");
                        res.head.status = crate::virtio_rtc::VIRTIO_RTC_S_EINVAL;
                    }
                    writer
                        .write_obj(res)
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                }
                Ok(RequestType::SetAlarmEnabled) if have_alarm => {
                    let mut reader = desc_chain
                        .clone()
                        .reader(&mem)
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let request = reader
                        .read_obj::<crate::virtio_rtc::VirtioRtcReqSetAlarmEnabled>()
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let mut res = crate::virtio_rtc::VirtioRtcRespSetAlarmEnabled::default();
                    let clock_id: usize = u16::from(request.clock_id).into();
                    let (lock, _cvar) = &*self.device;
                    let mut device = lock.lock().unwrap();
                    if let Some(clock) = device.clocks.get_mut(clock_id) {
                        if clock.alarm.is_none() {
                            log::error!(
                                "Tried to set alarm enabled on {clock_id:?} but it has no alarm"
                            );
                            res.head.status = crate::virtio_rtc::VIRTIO_RTC_S_EINVAL;
                        } else {
                            match clock.read() {
                                Ok(now) => {
                                    let enabled = request.flags
                                        & crate::virtio_rtc::VIRTIO_RTC_FLAG_ALARM_ENABLED
                                        > 0;
                                    #[allow(clippy::unnecessary_unwrap)]
                                    let alarm = clock.alarm.as_mut().unwrap();
                                    if enabled {
                                        let alarm_time = alarm.alarm_time();
                                        let dur = std::time::Duration::from_nanos(
                                            alarm_time.saturating_sub(now),
                                        );
                                        log::trace!(
                                            "Clock {clock_id} setting alarm {dur:?} from now"
                                        );
                                        let mut notif =
                                            crate::virtio_rtc::VirtioRtcNotifAlarm::default();
                                        notif.head.msg_type =
                                            crate::virtio_rtc::VIRTIO_RTC_NOTIF_ALARM.into();
                                        notif.clock_id = request.clock_id;
                                        let device = Arc::clone(&self.device);
                                        alarm.enable(device, notif, dur);
                                    } else {
                                        log::trace!("Clock {clock_id} disabling alarm");
                                        alarm.disable();
                                    }
                                }
                                Err(err) => {
                                    log::error!("Could not read clock {clock_id:?}: {err}");
                                    res.head.status = crate::virtio_rtc::VIRTIO_RTC_S_EIO;
                                }
                            }
                        }
                    } else {
                        log::error!(
                            "Tried to set alarm enabled on {clock_id:?} but it does not exist"
                        );
                        res.head.status = crate::virtio_rtc::VIRTIO_RTC_S_EINVAL;
                    }
                    writer
                        .write_obj(res)
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                }
                other => {
                    log::error!("Received invalid request {other:?} from guest.");
                    writer
                        .write_obj(VirtioRtcRespHead {
                            status: crate::virtio_rtc::VIRTIO_RTC_S_EINVAL,
                            ..VirtioRtcRespHead::default()
                        })
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                }
            }

            let used_len = writer.bytes_written();
            assert!(used_len > 0);

            let used_len = match u32::try_from(used_len) {
                Ok(len) => len,
                Err(len) => {
                    log::warn!("used_len {len} overflows u32");
                    u32::MAX
                }
            };

            if vring.add_used(desc_chain.head_index(), used_len).is_err() {
                log::error!("Couldn't return used descriptors to the ring");
            }
        }

        // Send notification once all the requests are processed
        vring
            .signal_used_queue()
            .map_err(|_| Error::NotificationFailed)?;

        Ok(())
    }

    /// Process alarm buffers.
    fn process_alarm_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        assert!(self.have_alarm());
        let Some(ref atomic_mem) = self.mem else {
            return Err(Error::NoMemoryConfigured);
        };
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if requests.is_empty() {
            return Ok(());
        }

        log::trace!("Received {} alarmq buffer(s)", requests.len());

        for desc_chain in requests {
            let (lock, cvar) = &*self.device;
            let mut device = lock.lock().unwrap();
            device
                .alarm_notif_buffers
                .push(Arc::new(AlarmNotificationBuffer {
                    vring: vring.clone(),
                    desc_chain,
                }));
            cvar.notify_one();
        }

        Ok(())
    }
}

/// VhostUserBackendMut trait methods
impl VhostUserBackendMut for VhostUserRtcBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        2
    }

    fn max_queue_size(&self) -> usize {
        1024
    }

    fn features(&self) -> u64 {
        let mut ret = (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_INDIRECT_DESC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        if self.offer_alarm {
            ret |= 1 << crate::virtio_rtc::VIRTIO_RTC_F_ALARM;
        }
        ret
    }

    fn acked_features(&mut self, features: u64) {
        self.negotiated_features = features;
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<()> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match device_event {
            0 => {
                let vring = &vrings[0];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_request_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_request_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_request_queue(vring)?;
                }
            }
            // The alarmq exists only if VIRTIO_RTC_F_ALARM has been negotiated.
            1 if self.have_alarm() => {
                let vring = &vrings[1];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_request_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_alarm_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_alarm_queue(vring)?;
                }
            }
            _ => {
                log::warn!("unhandled device_event: {device_event}");
                return Err(Error::HandleEventUnknown.into());
            }
        }
        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
        let consumer = self.exit_consumer.try_clone().ok()?;
        let notifier = self.exit_notifier.try_clone().ok()?;
        Some((consumer, notifier))
    }
}

#[repr(u16)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RequestType {
    Cfg = crate::virtio_rtc::VIRTIO_RTC_REQ_CFG,
    ClockCap = crate::virtio_rtc::VIRTIO_RTC_REQ_CLOCK_CAP,
    Read = crate::virtio_rtc::VIRTIO_RTC_REQ_READ,
    ReadCross = crate::virtio_rtc::VIRTIO_RTC_REQ_READ_CROSS,
    CrossCap = crate::virtio_rtc::VIRTIO_RTC_REQ_CROSS_CAP,
    ReadAlarm = crate::virtio_rtc::VIRTIO_RTC_REQ_READ_ALARM,
    SetAlarm = crate::virtio_rtc::VIRTIO_RTC_REQ_SET_ALARM,
    SetAlarmEnabled = crate::virtio_rtc::VIRTIO_RTC_REQ_SET_ALARM_ENABLED,
}

impl TryFrom<u16> for RequestType {
    type Error = u16;

    fn try_from(msg_type: u16) -> std::result::Result<Self, Self::Error> {
        let val = match msg_type {
            crate::virtio_rtc::VIRTIO_RTC_REQ_CFG => Self::Cfg,
            crate::virtio_rtc::VIRTIO_RTC_REQ_CLOCK_CAP => Self::ClockCap,
            crate::virtio_rtc::VIRTIO_RTC_REQ_READ => Self::Read,
            crate::virtio_rtc::VIRTIO_RTC_REQ_READ_CROSS => Self::ReadCross,
            crate::virtio_rtc::VIRTIO_RTC_REQ_CROSS_CAP => Self::CrossCap,
            crate::virtio_rtc::VIRTIO_RTC_REQ_READ_ALARM => Self::ReadAlarm,
            crate::virtio_rtc::VIRTIO_RTC_REQ_SET_ALARM => Self::SetAlarm,
            crate::virtio_rtc::VIRTIO_RTC_REQ_SET_ALARM_ENABLED => Self::SetAlarmEnabled,
            _ => {
                return Err(msg_type);
            }
        };
        assert_eq!(msg_type, val as u16);
        Ok(val)
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;
    use crate::virtio_rtc::*;

    #[test]
    fn test_backend_conversions() {
        let mut max = 0;
        for (raw, val) in [
            (VIRTIO_RTC_REQ_CFG, RequestType::Cfg),
            (VIRTIO_RTC_REQ_CLOCK_CAP, RequestType::ClockCap),
            (VIRTIO_RTC_REQ_READ, RequestType::Read),
            (VIRTIO_RTC_REQ_READ_CROSS, RequestType::ReadCross),
            (VIRTIO_RTC_REQ_CROSS_CAP, RequestType::CrossCap),
            (VIRTIO_RTC_REQ_READ_ALARM, RequestType::ReadAlarm),
            (VIRTIO_RTC_REQ_SET_ALARM, RequestType::SetAlarm),
            (
                VIRTIO_RTC_REQ_SET_ALARM_ENABLED,
                RequestType::SetAlarmEnabled,
            ),
        ] {
            max = max.max(raw);
            assert_eq!(RequestType::try_from(raw).unwrap(), val);
        }
        assert_eq!(RequestType::try_from(max + 1).unwrap_err(), max + 1);

        assert_eq!(
            std::io::Error::from(Error::NoMemoryConfigured).to_string(),
            std::io::Error::other(Error::NoMemoryConfigured).to_string()
        );
    }

    #[test]
    fn test_backend() {
        const ALARM_BIT: u64 = 1 << crate::virtio_rtc::VIRTIO_RTC_F_ALARM;

        let mut clocks = vec![];

        for constructor_fn in [
            Clock::new_utc as fn() -> crate::clocks::Result<Clock>,
            Clock::new_tai,
            Clock::new_monotonic,
        ] {
            if let Ok(clock) = constructor_fn() {
                clocks.push(clock);
            }
        }

        let mut backend = VhostUserRtcBackend::new(false, clocks).unwrap();
        assert!(!backend.have_alarm());
        assert_eq!(backend.features() & ALARM_BIT, 0);
        backend.offer_alarm = true;
        assert_eq!(backend.features() & ALARM_BIT, ALARM_BIT);
        assert!(!backend.have_alarm());
        backend.acked_features(ALARM_BIT);
        assert!(backend.have_alarm());

        // Mock memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Update memory
        backend.update_memory(mem.clone()).unwrap();

        assert_eq!(backend.num_queues(), 2);
        assert_eq!(backend.max_queue_size(), 1024);
        assert_eq!(backend.protocol_features(), VhostUserProtocolFeatures::MQ);
    }
}

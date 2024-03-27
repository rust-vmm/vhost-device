// Low level SPI definitions
//
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//          Haixu Cui <quic_haixcui@quicinc.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

use libc::{c_ulong, ioctl};
use thiserror::Error as ThisError;
use vmm_sys_util::errno::Error as IoError;

use std::convert::From;
use std::ptr;
use vm_memory::{ByteValued, Le32};

// The type of the `req` parameter is different for the `musl` library. This will enable
// successful build for other non-musl libraries.
#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = c_ulong;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, ThisError)]
/// Errors related to low level spi helpers
pub(crate) enum Error {
    #[error("Ioctl command failed for {0} operation: {1}")]
    IoctlFailure(&'static str, IoError),
    #[error("Failed to open spi controller")]
    DeviceOpenFailed,
}

/// Linux SPI definitions
/// IOCTL commands, refer Linux's Documentation/spi/spidev.rst for further details.
const _IOC_SIZEBITS: u32 = 14;
const _IOC_SIZESHIFT: u32 = 16;
const SPI_IOC_MESSAGE_BASE: IoctlRequest = 0x40006b00;
const SPI_IOC_RD_MODE32: IoctlRequest = 0x80046b05;
const SPI_IOC_WR_MODE32: IoctlRequest = 0x40046b05;
const SPI_IOC_RD_MAX_SPEED_HZ: IoctlRequest = 0x80046b04;
const SPI_IOC_WR_MAX_SPEED_HZ: IoctlRequest = 0x40046b04;
const SPI_IOC_RD_BITS_PER_WORD: IoctlRequest = 0x80016b03;
const SPI_IOC_WR_BITS_PER_WORD: IoctlRequest = 0x40016b03;

// Corresponds to the SPI_IOC_MESSAGE macro in Linux
fn spi_ioc_message(n: u32) -> IoctlRequest {
    let mut size: u32 = 0;
    if n * 32 < (1 << _IOC_SIZEBITS) {
        size = n * 32;
    }
    (SPI_IOC_MESSAGE_BASE | ((size as IoctlRequest) << _IOC_SIZESHIFT)) as IoctlRequest
}

/// Linux SPI mode, prefix with "LNX_"
/// refer to Linux include/uapi/linux/spi/spi.h
const LNX_SPI_CPHA: u32 = 1 << 0;
const LNX_SPI_CPOL: u32 = 1 << 1;
const LNX_SPI_CS_HIGH: u32 = 1 << 2;
const LNX_SPI_LSB_FIRST: u32 = 1 << 3;
const LNX_SPI_LOOP: u32 = 1 << 5;
const LNX_SPI_TX_DUAL: u32 = 1 << 8;
const LNX_SPI_TX_QUAD: u32 = 1 << 9;
const LNX_SPI_TX_OCTAL: u32 = 1 << 13;
const LNX_SPI_RX_DUAL: u32 = 1 << 10;
const LNX_SPI_RX_QUAD: u32 = 1 << 11;
const LNX_SPI_RX_OCTAL: u32 = 1 << 14;

/// Config space supported mode mask
const CONFIG_SPACE_TRANS_DUAL: u8 = 0x1;
const CONFIG_SPACE_TRANS_QUAD: u8 = 0x2;
const CONFIG_SPACE_TRANS_OCTAL: u8 = 0x4;
const CONFIG_SPACE_CPHA_0: u32 = 0x1;
const CONFIG_SPACE_CPHA_1: u32 = 0x2;
const CONFIG_SPACE_CPOL_0: u32 = 0x4;
const CONFIG_SPACE_CPOL_1: u32 = 0x8;
const CONFIG_SPACE_CS_HIGH: u32 = 0x10;
const CONFIG_SPACE_LSB: u32 = 0x20;
const CONFIG_SPACE_LOOP: u32 = 0x40;

/// Mode setting in Requests
pub const SPI_CPHA: u32 = 1 << 0;
pub const SPI_CPOL: u32 = 1 << 1;
pub const SPI_CS_HIGH: u32 = 1 << 2;
pub const SPI_LSB_FIRST: u32 = 1 << 3;
pub const SPI_LOOP: u32 = 1 << 4;

/// Copied (partially) from Linux's include/uapi/linux/spi/spidev.h
///
/// SpiIocTransfer - describes a single SPI transfer
///
/// @tx_buf: Holds pointer to userspace buffer with transmit data, or null.
///
/// @rx_buf: Holds pointer to userspace buffer for receive data, or null.
///
/// @len: Length of tx and rx buffers, in bytes.
///
/// @speed_hz: Temporary override of the device's bitrate.
///
/// @bits_per_word: Temporary override of the device's wordsize.
///
/// @delay_usecs: If nonzero, how long to delay after the last bit transfer
///   before optionally deselecting the device before the next transfer.
///
/// @cs_change: True to deselect device before starting the next transfer.
///
/// @word_delay_usecs: If nonzero, how long to wait between words within one
///   transfer. This property needs explicit support in the SPI controller,
///   otherwise it is silently ignored.
///
/// This structure is mapped directly to the kernel spi_transfer structure;
/// the fields have the same meanings, except of course that the pointers
/// are in a different address space (and may be of different sizes in some
/// cases, such as 32-bit i386 userspace over a 64-bit x86_64 kernel).
/// Zero-initialize the structure, including currently unused fields, to
/// accommodate potential future updates.

#[derive(Debug)]
#[repr(C)]
pub(crate) struct SpiIocTransfer {
    tx_buf: u64,
    rx_buf: u64,
    len: u32,
    speed_hz: u32,
    delay_usecs: u16,
    bits_per_word: u8,
    cs_change: u8,
    tx_nbits: u8,
    rx_nbits: u8,
    word_delay_usecs: u8,
    pad: u8,
}

/// SPI definitions
pub(crate) struct SpiTransReq {
    pub tx_buf: Vec<u8>,
    pub rx_buf: Vec<u8>,
    pub trans_len: u32,
    pub speed_hz: u32,
    pub mode: u32,
    pub delay_usecs: u16,
    pub bits_per_word: u8,
    pub cs_change: u8,
    pub tx_nbits: u8,
    pub rx_nbits: u8,
    pub word_delay_usecs: u8,
    pub cs_id: u8,
}

/// Virtio SPI Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioSpiConfig {
    pub(crate) cs_max_number: u8,
    pub(crate) cs_change_supported: u8,
    pub(crate) tx_nbits_supported: u8,
    pub(crate) rx_nbits_supported: u8,
    pub(crate) bits_per_word_mask: Le32,
    pub(crate) mode_func_supported: Le32,
    pub(crate) max_freq_hz: Le32,
    pub(crate) max_word_delay_ns: Le32,
    pub(crate) max_cs_setup_ns: Le32,
    pub(crate) max_cs_hold_ns: Le32,
    pub(crate) max_cs_inactive_ns: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSpiConfig {}

/// Trait that represents a SPI Device.
///
/// This trait is introduced for development purposes only, and should not
/// be used outside of this crate. The purpose of this trait is to provide a
/// mock implementation for the SPI driver so that we can test the SPI
/// functionality without the need of a physical device.
pub(crate) trait SpiDevice {
    // Open the device specified by the controller path.
    fn open(spidev_path: &str) -> Result<Self>
    where
        Self: Sized;

    // Corresponds to the SPI_IOC_RD_MAX_SPEED_HZ ioctl call.
    fn get_max_speed_hz(&self) -> Result<u32>;

    // Corresponds to the SPI_IOC_WR_MAX_SPEED_HZ ioctl call.
    fn set_max_speed_hz(&self, max_speed_hz: u32) -> Result<()>;

    // Corresponds to the SPI_IOC_RD_BITS_PER_WORD ioctl call.
    fn get_bits_per_word(&self) -> Result<u8>;

    // Corresponds to the SPI_IOC_WR_BITS_PER_WORD ioctl call.
    fn set_bits_per_word(&self, bpw: u8) -> Result<()>;

    // Corresponds to the SPI_IOC_RD_MODE/SPI_IOC_RD_MODE32 ioctl call.
    fn get_mode(&self) -> Result<u32>;

    // Corresponds to the SPI_IOC_WR_MODE/SPI_IOC_WR_MODE32 ioctl call.
    fn set_mode(&self, mode: u32) -> Result<()>;

    // Corresponds to the default ioctl call.
    fn rdwr(&self, reqs: &mut [SpiTransReq]) -> Result<()>;

    // Detect the spi controller supported mode and delay settings
    fn detect_supported_features(&self) -> Result<VirtioSpiConfig> {
        Ok(VirtioSpiConfig {
            cs_max_number: 1,
            cs_change_supported: 1,
            tx_nbits_supported: 0,
            rx_nbits_supported: 0,
            bits_per_word_mask: From::from(0),
            mode_func_supported: From::from(0xf),
            max_freq_hz: From::from(0),
            max_word_delay_ns: From::from(0),
            max_cs_setup_ns: From::from(0),
            max_cs_hold_ns: From::from(0),
            max_cs_inactive_ns: From::from(0),
        })
    }
}

/// A physical SPI device. This structure can only be initialized on hosts
/// where `/dev/spidevX.Y` is available.
#[derive(Debug)]
pub(crate) struct PhysDevice {
    file: File,
}

impl SpiDevice for PhysDevice {
    fn open(spidev_path: &str) -> Result<Self> {
        Ok(PhysDevice {
            file: OpenOptions::new()
                .read(true)
                .write(true)
                .open(spidev_path)
                .map_err(|_| Error::DeviceOpenFailed)?,
        })
    }

    fn get_max_speed_hz(&self) -> Result<u32> {
        let mut max_speed_hz: u32 = 0;

        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe {
            ioctl(
                self.file.as_raw_fd(),
                SPI_IOC_RD_MAX_SPEED_HZ,
                &mut max_speed_hz,
            )
        };

        if ret == -1 {
            Err(Error::IoctlFailure("get_max_speed_hz", IoError::last()))
        } else {
            Ok(max_speed_hz)
        }
    }

    fn set_max_speed_hz(&self, max_speed_hz: u32) -> Result<()> {
        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe {
            ioctl(
                self.file.as_raw_fd(),
                SPI_IOC_WR_MAX_SPEED_HZ,
                &max_speed_hz,
            )
        };

        if ret == -1 {
            Err(Error::IoctlFailure("set_max_speed_hz", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn get_bits_per_word(&self) -> Result<u8> {
        let mut bpw: u8 = 0;

        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe { ioctl(self.file.as_raw_fd(), SPI_IOC_RD_BITS_PER_WORD, &mut bpw) };

        if ret == -1 {
            Err(Error::IoctlFailure("get_bits_per_word", IoError::last()))
        } else {
            Ok(bpw)
        }
    }

    fn set_bits_per_word(&self, bpw: u8) -> Result<()> {
        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe { ioctl(self.file.as_raw_fd(), SPI_IOC_WR_BITS_PER_WORD, &bpw) };

        if ret == -1 {
            Err(Error::IoctlFailure("set_bits_per_word", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn get_mode(&self) -> Result<u32> {
        let mut mode: u32 = 0;

        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe { ioctl(self.file.as_raw_fd(), SPI_IOC_RD_MODE32, &mut mode) };

        if ret == -1 {
            Err(Error::IoctlFailure("get_mode", IoError::last()))
        } else {
            Ok(mode)
        }
    }

    fn set_mode(&self, mode: u32) -> Result<()> {
        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe { ioctl(self.file.as_raw_fd(), SPI_IOC_WR_MODE32, &mode) };

        if ret == -1 {
            Err(Error::IoctlFailure("set_mode", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn rdwr(&self, reqs: &mut [SpiTransReq]) -> Result<()> {
        let mut msgs: Vec<SpiIocTransfer> = Vec::with_capacity(reqs.len());
        let len = reqs.len();
        let mut tx_buf_ptr: *mut u8;
        let mut rx_buf_ptr: *mut u8;

        let saved_mode: u32 = self.get_mode()?;
        let mut trans_mode: u32 = saved_mode;

        for req in reqs {
            if req.tx_buf.is_empty() {
                tx_buf_ptr = ptr::null_mut();
            } else {
                tx_buf_ptr = req.tx_buf.as_mut_ptr();
            }

            if req.rx_buf.is_empty() {
                rx_buf_ptr = ptr::null_mut();
            } else {
                rx_buf_ptr = req.rx_buf.as_mut_ptr();
            }

            msgs.push(SpiIocTransfer {
                tx_buf: tx_buf_ptr as u64,
                rx_buf: rx_buf_ptr as u64,
                len: req.trans_len,
                speed_hz: req.speed_hz,
                delay_usecs: req.delay_usecs,
                bits_per_word: req.bits_per_word,
                cs_change: req.cs_change,
                tx_nbits: req.tx_nbits,
                rx_nbits: req.rx_nbits,
                word_delay_usecs: req.word_delay_usecs,
                pad: 0,
            });

            if (req.mode & SPI_CPHA) == SPI_CPHA {
                trans_mode |= LNX_SPI_CPHA;
            } else {
                trans_mode &= !LNX_SPI_CPHA;
            }
            if (req.mode & SPI_CPOL) == SPI_CPOL {
                trans_mode |= LNX_SPI_CPOL;
            } else {
                trans_mode &= !LNX_SPI_CPOL;
            }
            if (req.mode & SPI_CS_HIGH) == SPI_CS_HIGH {
                trans_mode |= LNX_SPI_CS_HIGH;
            } else {
                trans_mode &= !LNX_SPI_CS_HIGH;
            }
            if (req.mode & SPI_LSB_FIRST) == SPI_LSB_FIRST {
                trans_mode |= LNX_SPI_LSB_FIRST;
            } else {
                trans_mode &= !LNX_SPI_LSB_FIRST;
            }
            if (req.mode & SPI_LOOP) == SPI_LOOP {
                trans_mode |= LNX_SPI_LOOP;
            } else {
                trans_mode &= !LNX_SPI_LOOP;
            }
        }

        self.set_mode(trans_mode)?;

        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe {
            ioctl(
                self.file.as_raw_fd(),
                spi_ioc_message(len as u32),
                msgs.as_mut_ptr(),
            )
        };

        self.set_mode(saved_mode)?;

        if ret == -1 {
            Err(Error::IoctlFailure("rdwr", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn detect_supported_features(&self) -> Result<VirtioSpiConfig> {
        // supported cs_max_number 1
        // can't set cs timing from userland in Linux, reserve cs timing as 0
        // cs_change_supported always enabled, cause Linux can handle this in software
        // max_word_delay_ns reserved as 0, also can't set from userland

        //detect max_speed_hz
        let origin_speed: u32 = self.get_max_speed_hz()?;

        let max_speed_hz: u32 = match self.set_max_speed_hz(0) {
            Err(_) => 0,
            Ok(()) => self.get_max_speed_hz().unwrap_or(0),
        };

        self.set_max_speed_hz(origin_speed)?;

        //detect supported bpw
        let mut bits_per_word_mask: u32 = 0;

        let origin_bpw: u8 = self.get_bits_per_word()?;

        match self.set_bits_per_word(64) {
            Ok(()) => {
                bits_per_word_mask = 0;
            }
            Err(_) => {
                for bpw in 1..33 {
                    match self.set_bits_per_word(bpw) {
                        Ok(()) => {
                            bits_per_word_mask |= 1 << (bpw - 1);
                        }
                        Err(_) => {
                            bits_per_word_mask &= !(1 << (bpw - 1));
                        }
                    };
                }
            }
        }

        self.set_bits_per_word(origin_bpw)?;

        //detect supported tx_nbit and rx_nbits
        let mut tx_nbits_mask: u8 = 0;
        let mut rx_nbits_mask: u8 = 0;

        let origin_mode = self.get_mode()?;

        let set_tx_dual: u32 =
            (origin_mode | LNX_SPI_TX_DUAL) & !LNX_SPI_TX_QUAD & !LNX_SPI_TX_OCTAL;
        let set_tx_quad: u32 =
            (origin_mode | LNX_SPI_TX_QUAD) & !LNX_SPI_TX_DUAL & !LNX_SPI_TX_OCTAL;
        let set_tx_octal: u32 =
            (origin_mode | LNX_SPI_TX_OCTAL) & !LNX_SPI_TX_DUAL & !LNX_SPI_TX_QUAD;
        let set_rx_dual: u32 =
            (origin_mode | LNX_SPI_RX_DUAL) & !LNX_SPI_RX_QUAD & !LNX_SPI_RX_OCTAL;
        let set_rx_quad: u32 =
            (origin_mode | LNX_SPI_RX_QUAD) & !LNX_SPI_RX_DUAL & !LNX_SPI_RX_OCTAL;
        let set_rx_octal: u32 =
            (origin_mode | LNX_SPI_RX_OCTAL) & !LNX_SPI_RX_DUAL & !LNX_SPI_RX_QUAD;

        self.set_mode(set_tx_dual)?;
        let get_tx_dual = self.get_mode()?;
        if (get_tx_dual & LNX_SPI_TX_DUAL) == LNX_SPI_TX_DUAL {
            tx_nbits_mask |= CONFIG_SPACE_TRANS_DUAL;
        }

        self.set_mode(set_tx_quad)?;
        let get_tx_quad = self.get_mode()?;
        if (get_tx_quad & LNX_SPI_TX_QUAD) == LNX_SPI_TX_QUAD {
            tx_nbits_mask |= CONFIG_SPACE_TRANS_QUAD;
        }

        self.set_mode(set_tx_octal)?;
        let get_tx_octal = self.get_mode()?;
        if (get_tx_octal & LNX_SPI_TX_OCTAL) == LNX_SPI_TX_OCTAL {
            tx_nbits_mask |= CONFIG_SPACE_TRANS_OCTAL;
        }

        self.set_mode(set_rx_dual)?;
        let get_rx_dual = self.get_mode()?;
        if (get_rx_dual & LNX_SPI_RX_DUAL) == LNX_SPI_RX_DUAL {
            rx_nbits_mask |= CONFIG_SPACE_TRANS_DUAL;
        }

        self.set_mode(set_rx_quad)?;
        let get_rx_quad = self.get_mode()?;
        if (get_rx_quad & LNX_SPI_RX_QUAD) == LNX_SPI_RX_QUAD {
            rx_nbits_mask |= CONFIG_SPACE_TRANS_QUAD;
        }

        self.set_mode(set_rx_octal)?;
        let get_rx_octal = self.get_mode()?;
        if (get_rx_octal & LNX_SPI_RX_OCTAL) == LNX_SPI_RX_OCTAL {
            rx_nbits_mask |= CONFIG_SPACE_TRANS_OCTAL;
        }

        //detect supported CPHA setting
        let mut mode_function_mask: u32 = 0;

        let mut set_cpha_mode = origin_mode;
        let get_cpha_mode;

        if (origin_mode & LNX_SPI_CPHA) == LNX_SPI_CPHA {
            mode_function_mask |= CONFIG_SPACE_CPHA_1;
            set_cpha_mode &= !LNX_SPI_CPHA;

            match self.set_mode(set_cpha_mode) {
                Err(_) => mode_function_mask &= !CONFIG_SPACE_CPHA_0,
                Ok(()) => {
                    get_cpha_mode = self.get_mode()?;
                    if (get_cpha_mode & LNX_SPI_CPHA) == 0 {
                        mode_function_mask |= CONFIG_SPACE_CPHA_0;
                    } else {
                        mode_function_mask &= !CONFIG_SPACE_CPHA_0;
                    }
                }
            };
        } else {
            mode_function_mask |= CONFIG_SPACE_CPHA_0;
            set_cpha_mode |= LNX_SPI_CPHA;

            match self.set_mode(set_cpha_mode) {
                Err(_) => mode_function_mask &= !CONFIG_SPACE_CPHA_1,
                Ok(()) => {
                    get_cpha_mode = self.get_mode()?;
                    if (get_cpha_mode & LNX_SPI_CPHA) == LNX_SPI_CPHA {
                        mode_function_mask |= CONFIG_SPACE_CPHA_1;
                    } else {
                        mode_function_mask &= !CONFIG_SPACE_CPHA_1;
                    }
                }
            };
        }

        //detect supported CPOL setting
        let mut set_cpol_mode = origin_mode;
        let get_cpol_mode;

        if (origin_mode & LNX_SPI_CPOL) == LNX_SPI_CPOL {
            mode_function_mask |= CONFIG_SPACE_CPOL_1;

            set_cpol_mode &= !LNX_SPI_CPOL;

            match self.set_mode(set_cpol_mode) {
                Err(_) => mode_function_mask &= !CONFIG_SPACE_CPOL_0,
                Ok(()) => {
                    get_cpol_mode = self.get_mode()?;
                    if (get_cpol_mode & LNX_SPI_CPOL) == 0 {
                        mode_function_mask |= CONFIG_SPACE_CPOL_0;
                    } else {
                        mode_function_mask &= !CONFIG_SPACE_CPOL_0;
                    }
                }
            };
        } else {
            mode_function_mask |= CONFIG_SPACE_CPOL_0;

            set_cpol_mode |= LNX_SPI_CPOL;

            match self.set_mode(set_cpol_mode) {
                Err(_) => mode_function_mask &= !CONFIG_SPACE_CPOL_1,
                Ok(()) => {
                    get_cpol_mode = self.get_mode()?;
                    if (get_cpol_mode & LNX_SPI_CPOL) == LNX_SPI_CPOL {
                        mode_function_mask |= CONFIG_SPACE_CPOL_1;
                    } else {
                        mode_function_mask &= !CONFIG_SPACE_CPOL_1;
                    }
                }
            };
        }

        //detect supported CS_HIGH setting
        let mut set_cs_high_mode = origin_mode;
        let get_cs_high_mode;

        if (origin_mode & LNX_SPI_CS_HIGH) == LNX_SPI_CS_HIGH {
            mode_function_mask |= CONFIG_SPACE_CS_HIGH;
        } else {
            set_cs_high_mode |= LNX_SPI_CS_HIGH;
            match self.set_mode(set_cs_high_mode) {
                Err(_) => mode_function_mask &= !CONFIG_SPACE_CS_HIGH,
                Ok(()) => {
                    get_cs_high_mode = self.get_mode()?;
                    if (get_cs_high_mode & LNX_SPI_CS_HIGH) == LNX_SPI_CS_HIGH {
                        mode_function_mask |= CONFIG_SPACE_CS_HIGH;
                    } else {
                        mode_function_mask &= !CONFIG_SPACE_CS_HIGH;
                    }
                }
            };
        }

        //detect supported LSB setting
        let mut set_lsb_mode = origin_mode;
        let get_lsb_mode;

        if (origin_mode & LNX_SPI_LSB_FIRST) == LNX_SPI_LSB_FIRST {
            mode_function_mask |= CONFIG_SPACE_LSB;
        } else {
            set_lsb_mode |= LNX_SPI_LSB_FIRST;
            match self.set_mode(set_lsb_mode) {
                Err(_) => mode_function_mask &= !CONFIG_SPACE_LSB,
                Ok(()) => {
                    get_lsb_mode = self.get_mode()?;
                    if (get_lsb_mode & LNX_SPI_LSB_FIRST) == LNX_SPI_LSB_FIRST {
                        mode_function_mask |= CONFIG_SPACE_LSB;
                    } else {
                        mode_function_mask &= !CONFIG_SPACE_LSB;
                    }
                }
            };
        }

        //detect supported LOOP setting
        let mut set_loop_mode = origin_mode;
        let get_loop_mode;

        if (origin_mode & LNX_SPI_LOOP) == LNX_SPI_LOOP {
            mode_function_mask |= CONFIG_SPACE_LOOP;
        } else {
            set_loop_mode |= LNX_SPI_LOOP;
            match self.set_mode(set_loop_mode) {
                Err(_) => mode_function_mask &= !CONFIG_SPACE_LOOP,
                Ok(()) => {
                    get_loop_mode = self.get_mode()?;
                    if (get_loop_mode & LNX_SPI_LOOP) == LNX_SPI_LOOP {
                        mode_function_mask |= CONFIG_SPACE_LOOP;
                    } else {
                        mode_function_mask &= !CONFIG_SPACE_LOOP;
                    }
                }
            };
        }

        self.set_mode(origin_mode)?;

        Ok(VirtioSpiConfig {
            cs_max_number: 1,
            cs_change_supported: 1,
            tx_nbits_supported: tx_nbits_mask,
            rx_nbits_supported: rx_nbits_mask,
            bits_per_word_mask: From::from(bits_per_word_mask),
            mode_func_supported: From::from(mode_function_mask),
            max_freq_hz: From::from(max_speed_hz),
            max_word_delay_ns: From::from(0),
            max_cs_setup_ns: From::from(0),
            max_cs_hold_ns: From::from(0),
            max_cs_inactive_ns: From::from(0),
        })
    }
}

#[derive(Debug)]
pub(crate) struct SpiController<D: SpiDevice> {
    device: D,
    config: VirtioSpiConfig,
}

impl<D: SpiDevice> SpiController<D> {
    // Creates a new controller corresponding to `device`.
    pub(crate) fn new(device: D) -> Result<SpiController<D>> {
        let config: VirtioSpiConfig = device.detect_supported_features()?;

        Ok(SpiController { device, config })
    }

    pub(crate) fn config(&self) -> &VirtioSpiConfig {
        &self.config
    }

    pub(crate) fn transfer(&self, reqs: &mut [SpiTransReq]) -> Result<()> {
        self.device.rdwr(reqs)
    }

    pub(crate) fn check_trans_params(&self, trans_header: &mut SpiTransReq) -> bool {
        let mut trans_params_valid: bool = true;

        if self.config.cs_max_number < trans_header.cs_id {
            trans_params_valid = false;
        }

        if (self.config.bits_per_word_mask != 0)
            && ((1 << (trans_header.bits_per_word - 1))
                & self.config.bits_per_word_mask.to_native())
                == 0
        {
            trans_params_valid = false;
        }

        if ((self.config.tx_nbits_supported & CONFIG_SPACE_TRANS_DUAL) == 0
            && trans_header.tx_nbits == 2)
            || ((self.config.tx_nbits_supported & CONFIG_SPACE_TRANS_QUAD) == 0
                && trans_header.tx_nbits == 4)
            || ((self.config.tx_nbits_supported & CONFIG_SPACE_TRANS_OCTAL) == 0
                && trans_header.tx_nbits == 8)
            || ((trans_header.tx_nbits != 0)
                && (trans_header.tx_nbits != 1)
                && (trans_header.tx_nbits != 2)
                && (trans_header.tx_nbits != 4)
                && (trans_header.tx_nbits != 8))
        {
            trans_params_valid = false;
        }

        if ((self.config.rx_nbits_supported & CONFIG_SPACE_TRANS_DUAL) == 0
            && trans_header.rx_nbits == 2)
            || ((self.config.rx_nbits_supported & CONFIG_SPACE_TRANS_QUAD) == 0
                && trans_header.rx_nbits == 4)
            || ((self.config.rx_nbits_supported & CONFIG_SPACE_TRANS_OCTAL) == 0
                && trans_header.rx_nbits == 8)
            || ((trans_header.rx_nbits != 0)
                && (trans_header.rx_nbits != 1)
                && (trans_header.rx_nbits != 2)
                && (trans_header.rx_nbits != 4)
                && (trans_header.rx_nbits != 8))
        {
            trans_params_valid = false;
        }

        if (trans_header.mode & SPI_CPHA == 0)
            && (self.config.mode_func_supported.to_native() & CONFIG_SPACE_CPHA_0 == 0)
        {
            trans_params_valid = false;
        }

        if (trans_header.mode & SPI_CPHA == SPI_CPHA)
            && (self.config.mode_func_supported.to_native() & CONFIG_SPACE_CPHA_1 == 0)
        {
            trans_params_valid = false;
        }

        if (trans_header.mode & SPI_CPOL == 0)
            && (self.config.mode_func_supported.to_native() & CONFIG_SPACE_CPOL_0 == 0)
        {
            trans_params_valid = false;
        }

        if (trans_header.mode & SPI_CPOL == SPI_CPOL)
            && (self.config.mode_func_supported.to_native() & CONFIG_SPACE_CPOL_1 == 0)
        {
            trans_params_valid = false;
        }

        if (trans_header.mode & SPI_CS_HIGH == SPI_CS_HIGH)
            && (self.config.mode_func_supported.to_native() & CONFIG_SPACE_CS_HIGH == 0)
        {
            trans_params_valid = false;
        }

        if (trans_header.mode & SPI_LSB_FIRST == SPI_LSB_FIRST)
            && (self.config.mode_func_supported.to_native() & CONFIG_SPACE_LSB == 0)
        {
            trans_params_valid = false;
        }

        if (trans_header.mode & SPI_LOOP == SPI_LOOP)
            && (self.config.mode_func_supported.to_native() & CONFIG_SPACE_LOOP == 0)
        {
            trans_params_valid = false;
        }

        if (self.config.max_freq_hz != 0)
            && (trans_header.speed_hz > self.config.max_freq_hz.to_native())
        {
            trans_params_valid = false;
        }

        trans_params_valid
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use vmm_sys_util::tempfile::TempFile;

    // Update read-buffer of each write-buffer with index + 1 value.
    pub fn update_rdwr_buf(buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
    }

    // Verify the write-buffer passed to us
    pub fn verify_rdwr_buf(buf: &[u8]) {
        for (i, byte) in buf.iter().enumerate() {
            assert_eq!(*byte, i as u8 + 1);
        }
    }

    #[derive(Debug)]
    pub struct DummyDevice {
        get_mode_result: Result<u32>,
        set_mode_result: Result<()>,
        get_max_speed_result: Result<u32>,
        set_max_speed_result: Result<()>,
        get_bpw_result: Result<u8>,
        set_bpw_result: Result<()>,
        rdwr_result: Result<()>,
        detect_supported_features_result: Result<VirtioSpiConfig>,
    }

    impl Default for DummyDevice {
        fn default() -> Self {
            let default_config = VirtioSpiConfig {
                cs_max_number: 1,
                cs_change_supported: 1,
                tx_nbits_supported: 0,
                rx_nbits_supported: 0,
                bits_per_word_mask: From::from(0),
                mode_func_supported: From::from(0xf),
                max_freq_hz: From::from(0),
                max_word_delay_ns: From::from(0),
                max_cs_setup_ns: From::from(0),
                max_cs_hold_ns: From::from(0),
                max_cs_inactive_ns: From::from(0),
            };

            Self {
                get_mode_result: Ok(0),
                set_mode_result: Ok(()),
                get_max_speed_result: Ok(0),
                set_max_speed_result: Ok(()),
                get_bpw_result: Ok(0),
                set_bpw_result: Ok(()),
                rdwr_result: Ok(()),
                detect_supported_features_result: Ok(default_config),
            }
        }
    }

    impl SpiDevice for DummyDevice {
        fn open(_spidev_name: &str) -> Result<Self> {
            Ok(DummyDevice {
                ..Default::default()
            })
        }

        fn get_max_speed_hz(&self) -> Result<u32> {
            self.get_max_speed_result
        }

        fn set_max_speed_hz(&self, _max_speed_hz: u32) -> Result<()> {
            self.set_max_speed_result
        }

        fn get_bits_per_word(&self) -> Result<u8> {
            self.get_bpw_result
        }

        fn set_bits_per_word(&self, _bpw: u8) -> Result<()> {
            self.set_bpw_result
        }

        fn get_mode(&self) -> Result<u32> {
            self.get_mode_result
        }

        fn set_mode(&self, _mode: u32) -> Result<()> {
            self.set_mode_result
        }

        fn rdwr(&self, reqs: &mut [SpiTransReq]) -> Result<()> {
            for req in reqs {
                if !req.tx_buf.is_empty() {
                    verify_rdwr_buf(&req.tx_buf);
                }

                if !req.rx_buf.is_empty() {
                    update_rdwr_buf(&mut req.rx_buf);
                }
            }

            self.rdwr_result
        }

        fn detect_supported_features(&self) -> Result<VirtioSpiConfig> {
            self.detect_supported_features_result
        }
    }

    fn verify_rdwr_data(reqs: &[SpiTransReq]) {
        // Match what's done by DummyDevice::rdwr()
        for req in reqs {
            if !req.rx_buf.is_empty() {
                verify_rdwr_buf(&req.rx_buf);
            }
        }
    }

    #[test]
    fn test_spi_transfer() {
        let spi_dummy_ctrl = SpiController::new(DummyDevice::open("spidev0.0").unwrap()).unwrap();

        // Read-Write-Read-Write-Read block
        let mut reqs: Vec<SpiTransReq> = vec![
            SpiTransReq {
                tx_buf: vec![0; 10],
                rx_buf: vec![0; 10],
                trans_len: 10,
                speed_hz: 0,
                mode: 0,
                delay_usecs: 0,
                bits_per_word: 8,
                cs_change: 0,
                tx_nbits: 1,
                rx_nbits: 1,
                word_delay_usecs: 0,
                cs_id: 0,
            },
            SpiTransReq {
                tx_buf: Vec::<u8>::new(),
                rx_buf: vec![0; 15],
                trans_len: 15,
                speed_hz: 0,
                mode: 0,
                delay_usecs: 0,
                bits_per_word: 8,
                cs_change: 0,
                tx_nbits: 0,
                rx_nbits: 1,
                word_delay_usecs: 0,
                cs_id: 0,
            },
        ];

        for req in &mut reqs {
            if !req.tx_buf.is_empty() {
                update_rdwr_buf(&mut req.tx_buf);
            }
        }

        spi_dummy_ctrl.transfer(&mut reqs).unwrap();
        verify_rdwr_data(&reqs);
    }

    #[test]
    fn test_phys_device_failure() {
        // Open failure
        assert_eq!(
            PhysDevice::open("/dev/spidev-invalid").unwrap_err(),
            Error::DeviceOpenFailed
        );

        let file = TempFile::new().unwrap();
        let dev = PhysDevice::open(file.as_path().to_str().unwrap()).unwrap();

        assert_eq!(
            dev.get_mode().unwrap_err(),
            Error::IoctlFailure("get_mode", IoError::last())
        );

        assert_eq!(
            dev.set_mode(0).unwrap_err(),
            Error::IoctlFailure("set_mode", IoError::last())
        );

        assert_eq!(
            dev.get_max_speed_hz().unwrap_err(),
            Error::IoctlFailure("get_max_speed_hz", IoError::last())
        );

        assert_eq!(
            dev.set_max_speed_hz(0).unwrap_err(),
            Error::IoctlFailure("set_max_speed_hz", IoError::last())
        );

        assert_eq!(
            dev.get_bits_per_word().unwrap_err(),
            Error::IoctlFailure("get_bits_per_word", IoError::last())
        );

        assert_eq!(
            dev.set_bits_per_word(0).unwrap_err(),
            Error::IoctlFailure("set_bits_per_word", IoError::last())
        );

        assert_eq!(
            dev.detect_supported_features().unwrap_err(),
            Error::IoctlFailure("get_max_speed_hz", IoError::last())
        );

        // rdwr failure
        let mut reqs = [SpiTransReq {
            tx_buf: vec![7, 4],
            rx_buf: vec![7, 4],
            trans_len: 2,
            speed_hz: 10000,
            mode: 0,
            delay_usecs: 0,
            bits_per_word: 8,
            cs_change: 1,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        }];
        assert_eq!(
            dev.rdwr(&mut reqs).unwrap_err(),
            Error::IoctlFailure("get_mode", IoError::last())
        );
    }
}

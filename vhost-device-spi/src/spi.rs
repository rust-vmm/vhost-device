// Low level SPI definitions
//
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//          Haixu Cui <quic_haixcui@quicinc.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    fs::{File, OpenOptions},
    os::unix::io::AsRawFd,
    path::Path,
    ptr,
};

use thiserror::Error as ThisError;
use vmm_sys_util::errno::Error as IoError;
use vmm_sys_util::ioctl::{ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ref};

use crate::{linux_spi::*, vhu_spi::VirtioSpiConfig, virtio_spi::*};

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ThisError)]
/// Errors related to low level spi helpers
pub enum Error {
    #[error("Ioctl command failed for {0} operation: {1}")]
    IoctlFailure(&'static str, IoError),
    #[error("Failed to open spi controller")]
    DeviceOpenFailed,
}

/// SPI definitions
pub struct SpiTransReq {
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

/// Trait that represents a SPI Device.
///
/// This trait is introduced for development purposes only, and should not
/// be used outside of this crate. The purpose of this trait is to provide a
/// mock implementation for the SPI driver so that we can test the SPI
/// functionality without the need of a physical device.
pub trait SpiDevice {
    /// Open the device specified by the controller path.
    fn open(path: &Path) -> Result<Self>
    where
        Self: Sized;

    /// Corresponds to the `SPI_IOC_RD_MAX_SPEED_HZ` ioctl call.
    fn max_speed_hz(&self) -> Result<u32>;

    /// Corresponds to the `SPI_IOC_WR_MAX_SPEED_HZ` ioctl call.
    fn set_max_speed_hz(&self, max_speed_hz: u32) -> Result<()>;

    /// Corresponds to the `SPI_IOC_RD_BITS_PER_WORD` ioctl call.
    fn bits_per_word(&self) -> Result<u8>;

    /// Corresponds to the `SPI_IOC_WR_BITS_PER_WORD` ioctl call.
    fn set_bits_per_word(&self, bpw: u8) -> Result<()>;

    /// Corresponds to the `SPI_IOC_RD_MODE`/`SPI_IOC_RD_MODE32` ioctl call.
    fn mode(&self) -> Result<u32>;

    /// Corresponds to the `SPI_IOC_WR_MODE`/`SPI_IOC_WR_MODE32` ioctl call.
    fn set_mode(&self, mode: u32) -> Result<()>;

    /// Corresponds to the default ioctl call.
    fn rdwr(&self, reqs: &mut [SpiIocTransfer]) -> Result<()>;

    /// Detect the SPI controller supported mode and delay settings
    fn detect_supported_features(&self) -> Result<VirtioSpiConfig>;
}

/// A physical SPI device. This structure can only be initialized on hosts
/// where `/dev/spidevX.Y` is available.
#[derive(Debug)]
pub struct PhysDevice {
    file: File,
}

impl SpiDevice for PhysDevice {
    fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            file: OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|_| Error::DeviceOpenFailed)?,
        })
    }

    fn max_speed_hz(&self) -> Result<u32> {
        let mut max_speed_hz: u32 = 0;

        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe {
            ioctl_with_mut_ref(
                &self.file.as_raw_fd(),
                SPI_IOC_RD_MAX_SPEED_HZ(),
                &mut max_speed_hz,
            )
        };

        if ret == -1 {
            Err(Error::IoctlFailure("max_speed_hz", IoError::last()))
        } else {
            Ok(max_speed_hz)
        }
    }

    fn set_max_speed_hz(&self, max_speed_hz: u32) -> Result<()> {
        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe {
            ioctl_with_ref(
                &self.file.as_raw_fd(),
                SPI_IOC_WR_MAX_SPEED_HZ(),
                &max_speed_hz,
            )
        };

        if ret == -1 {
            Err(Error::IoctlFailure("set_max_speed_hz", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn bits_per_word(&self) -> Result<u8> {
        let mut bpw: u8 = 0;

        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe {
            ioctl_with_mut_ref(&self.file.as_raw_fd(), SPI_IOC_RD_BITS_PER_WORD(), &mut bpw)
        };

        if ret == -1 {
            Err(Error::IoctlFailure("bits_per_word", IoError::last()))
        } else {
            Ok(bpw)
        }
    }

    fn set_bits_per_word(&self, bpw: u8) -> Result<()> {
        // SAFETY: Safe as the file is a valid SPI controller.
        let ret =
            unsafe { ioctl_with_ref(&self.file.as_raw_fd(), SPI_IOC_WR_BITS_PER_WORD(), &bpw) };

        if ret == -1 {
            Err(Error::IoctlFailure("set_bits_per_word", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn mode(&self) -> Result<u32> {
        let mut mode: u32 = 0;

        // SAFETY: Safe as the file is a valid SPI controller.
        let ret =
            unsafe { ioctl_with_mut_ref(&self.file.as_raw_fd(), SPI_IOC_RD_MODE32(), &mut mode) };

        if ret == -1 {
            Err(Error::IoctlFailure("mode", IoError::last()))
        } else {
            Ok(mode)
        }
    }

    fn set_mode(&self, mode: u32) -> Result<()> {
        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe { ioctl_with_ref(&self.file.as_raw_fd(), SPI_IOC_WR_MODE32(), &mode) };

        if ret == -1 {
            Err(Error::IoctlFailure("set_mode", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn rdwr(&self, msgs: &mut [SpiIocTransfer]) -> Result<()> {
        let len = msgs.len();
        // SAFETY: Safe as the file is a valid SPI controller.
        let ret = unsafe {
            ioctl_with_mut_ptr(
                &self.file.as_raw_fd(),
                spi_ioc_message(len as u32),
                msgs.as_mut_ptr(),
            )
        };

        if ret == -1 {
            Err(Error::IoctlFailure("rdwr", IoError::last()))
        } else {
            Ok(())
        }
    }

    #[allow(clippy::cognitive_complexity)]
    fn detect_supported_features(&self) -> Result<VirtioSpiConfig> {
        // supported cs_max_number 1
        // can't set cs timing from userland in Linux, reserve cs timing as 0
        // cs_change_supported always enabled, cause Linux can handle this in software
        // max_word_delay_ns reserved as 0, also can't set from userland

        // detect max_speed_hz
        let origin_speed: u32 = self.max_speed_hz()?;

        let max_speed_hz: u32 = match self.set_max_speed_hz(0) {
            Err(_) => 0,
            Ok(()) => self.max_speed_hz().unwrap_or(0),
        };

        self.set_max_speed_hz(origin_speed)?;

        // detect supported bpw
        let mut bits_per_word_mask: u32 = 0;

        let origin_bpw: u8 = self.bits_per_word()?;

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

        // detect supported tx_nbit and rx_nbits
        let mut tx_nbits_mask: u8 = 0;
        let mut rx_nbits_mask: u8 = 0;

        let origin_mode = self.mode()?;

        let set_tx_dual: u32 = (origin_mode | LnxSpiMode::TX_DUAL.bits())
            & !LnxSpiMode::TX_QUAD.bits()
            & !LnxSpiMode::TX_OCTAL.bits();
        let set_tx_quad: u32 = (origin_mode | LnxSpiMode::TX_QUAD.bits())
            & !LnxSpiMode::TX_DUAL.bits()
            & !LnxSpiMode::TX_OCTAL.bits();
        let set_tx_octal: u32 = (origin_mode | LnxSpiMode::TX_OCTAL.bits())
            & !LnxSpiMode::TX_DUAL.bits()
            & !LnxSpiMode::TX_QUAD.bits();
        let set_rx_dual: u32 = (origin_mode | LnxSpiMode::RX_DUAL.bits())
            & !LnxSpiMode::RX_QUAD.bits()
            & !LnxSpiMode::RX_OCTAL.bits();
        let set_rx_quad: u32 = (origin_mode | LnxSpiMode::RX_QUAD.bits())
            & !LnxSpiMode::RX_DUAL.bits()
            & !LnxSpiMode::RX_OCTAL.bits();
        let set_rx_octal: u32 = (origin_mode | LnxSpiMode::RX_OCTAL.bits())
            & !LnxSpiMode::RX_DUAL.bits()
            & !LnxSpiMode::RX_QUAD.bits();

        self.set_mode(set_tx_dual)?;
        let get_tx_dual = self.mode()?;
        if (get_tx_dual & LnxSpiMode::TX_DUAL.bits()) == LnxSpiMode::TX_DUAL.bits() {
            tx_nbits_mask |= ConfigNbits::DUAL.bits();
        }

        self.set_mode(set_tx_quad)?;
        let get_tx_quad = self.mode()?;
        if (get_tx_quad & LnxSpiMode::TX_QUAD.bits()) == LnxSpiMode::TX_QUAD.bits() {
            tx_nbits_mask |= ConfigNbits::QUAD.bits();
        }

        self.set_mode(set_tx_octal)?;
        let get_tx_octal = self.mode()?;
        if (get_tx_octal & LnxSpiMode::TX_OCTAL.bits()) == LnxSpiMode::TX_OCTAL.bits() {
            tx_nbits_mask |= ConfigNbits::OCTAL.bits();
        }

        self.set_mode(set_rx_dual)?;
        let get_rx_dual = self.mode()?;
        if (get_rx_dual & LnxSpiMode::RX_DUAL.bits()) == LnxSpiMode::RX_DUAL.bits() {
            rx_nbits_mask |= ConfigNbits::DUAL.bits();
        }

        self.set_mode(set_rx_quad)?;
        let get_rx_quad = self.mode()?;
        if (get_rx_quad & LnxSpiMode::RX_QUAD.bits()) == LnxSpiMode::RX_QUAD.bits() {
            rx_nbits_mask |= ConfigNbits::QUAD.bits();
        }

        self.set_mode(set_rx_octal)?;
        let get_rx_octal = self.mode()?;
        if (get_rx_octal & LnxSpiMode::RX_OCTAL.bits()) == LnxSpiMode::RX_OCTAL.bits() {
            rx_nbits_mask |= ConfigNbits::OCTAL.bits();
        }

        // detect supported CPHA setting
        let mut mode_function_mask: u32 = 0;

        let mut set_cpha_mode = origin_mode;
        let get_cpha_mode;

        if (origin_mode & LnxSpiMode::CPHA.bits()) == LnxSpiMode::CPHA.bits() {
            mode_function_mask |= ConfigMode::CPHA_1.bits();
            set_cpha_mode &= !LnxSpiMode::CPHA.bits();

            match self.set_mode(set_cpha_mode) {
                Err(_) => mode_function_mask &= !ConfigMode::CPHA_0.bits(),
                Ok(()) => {
                    get_cpha_mode = self.mode()?;
                    if (get_cpha_mode & LnxSpiMode::CPHA.bits()) == 0 {
                        mode_function_mask |= ConfigMode::CPHA_0.bits();
                    } else {
                        mode_function_mask &= !ConfigMode::CPHA_0.bits();
                    }
                }
            };
        } else {
            mode_function_mask |= ConfigMode::CPHA_0.bits();
            set_cpha_mode |= LnxSpiMode::CPHA.bits();

            match self.set_mode(set_cpha_mode) {
                Err(_) => mode_function_mask &= !ConfigMode::CPHA_1.bits(),
                Ok(()) => {
                    get_cpha_mode = self.mode()?;
                    if (get_cpha_mode & LnxSpiMode::CPHA.bits()) == LnxSpiMode::CPHA.bits() {
                        mode_function_mask |= ConfigMode::CPHA_1.bits();
                    } else {
                        mode_function_mask &= !ConfigMode::CPHA_1.bits();
                    }
                }
            };
        }

        // detect supported CPOL setting
        let mut set_cpol_mode = origin_mode;
        let get_cpol_mode;

        if (origin_mode & LnxSpiMode::CPOL.bits()) == LnxSpiMode::CPOL.bits() {
            mode_function_mask |= ConfigMode::CPOL_1.bits();

            set_cpol_mode &= !LnxSpiMode::CPOL.bits();

            match self.set_mode(set_cpol_mode) {
                Err(_) => mode_function_mask &= !ConfigMode::CPOL_0.bits(),
                Ok(()) => {
                    get_cpol_mode = self.mode()?;
                    if (get_cpol_mode & LnxSpiMode::CPOL.bits()) == 0 {
                        mode_function_mask |= ConfigMode::CPOL_0.bits();
                    } else {
                        mode_function_mask &= !ConfigMode::CPOL_0.bits();
                    }
                }
            };
        } else {
            mode_function_mask |= ConfigMode::CPOL_0.bits();

            set_cpol_mode |= LnxSpiMode::CPOL.bits();

            match self.set_mode(set_cpol_mode) {
                Err(_) => mode_function_mask &= !ConfigMode::CPOL_1.bits(),
                Ok(()) => {
                    get_cpol_mode = self.mode()?;
                    if (get_cpol_mode & LnxSpiMode::CPOL.bits()) == LnxSpiMode::CPOL.bits() {
                        mode_function_mask |= ConfigMode::CPOL_1.bits();
                    } else {
                        mode_function_mask &= !ConfigMode::CPOL_1.bits();
                    }
                }
            };
        }

        // detect supported CS_HIGH setting
        let mut set_cs_high_mode = origin_mode;
        let get_cs_high_mode;

        if (origin_mode & LnxSpiMode::CS_HIGH.bits()) == LnxSpiMode::CS_HIGH.bits() {
            mode_function_mask |= ConfigMode::CS_HIGH.bits();
        } else {
            set_cs_high_mode |= LnxSpiMode::CS_HIGH.bits();
            match self.set_mode(set_cs_high_mode) {
                Err(_) => mode_function_mask &= !ConfigMode::CS_HIGH.bits(),
                Ok(()) => {
                    get_cs_high_mode = self.mode()?;
                    if (get_cs_high_mode & LnxSpiMode::CS_HIGH.bits()) == LnxSpiMode::CS_HIGH.bits()
                    {
                        mode_function_mask |= ConfigMode::CS_HIGH.bits();
                    } else {
                        mode_function_mask &= !ConfigMode::CS_HIGH.bits();
                    }
                }
            };
        }

        // detect supported LSB setting
        let mut set_lsb_mode = origin_mode;
        let get_lsb_mode;

        if (origin_mode & LnxSpiMode::LSB_FIRST.bits()) == LnxSpiMode::LSB_FIRST.bits() {
            mode_function_mask |= ConfigMode::LSB.bits();
        } else {
            set_lsb_mode |= LnxSpiMode::LSB_FIRST.bits();
            match self.set_mode(set_lsb_mode) {
                Err(_) => mode_function_mask &= !ConfigMode::LSB.bits(),
                Ok(()) => {
                    get_lsb_mode = self.mode()?;
                    if (get_lsb_mode & LnxSpiMode::LSB_FIRST.bits()) == LnxSpiMode::LSB_FIRST.bits()
                    {
                        mode_function_mask |= ConfigMode::LSB.bits();
                    } else {
                        mode_function_mask &= !ConfigMode::LSB.bits();
                    }
                }
            };
        }

        // detect supported LOOP setting
        let mut set_loop_mode = origin_mode;
        let get_loop_mode;

        if (origin_mode & LnxSpiMode::LOOP.bits()) == LnxSpiMode::LOOP.bits() {
            mode_function_mask |= ConfigMode::LOOP.bits();
        } else {
            set_loop_mode |= LnxSpiMode::LOOP.bits();
            match self.set_mode(set_loop_mode) {
                Err(_) => mode_function_mask &= !ConfigMode::LOOP.bits(),
                Ok(()) => {
                    get_loop_mode = self.mode()?;
                    if (get_loop_mode & LnxSpiMode::LOOP.bits()) == LnxSpiMode::LOOP.bits() {
                        mode_function_mask |= ConfigMode::LOOP.bits();
                    } else {
                        mode_function_mask &= !ConfigMode::LOOP.bits();
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
            bits_per_word_mask: bits_per_word_mask.into(),
            mode_func_supported: mode_function_mask.into(),
            max_freq_hz: max_speed_hz.into(),
            max_word_delay_ns: 0.into(),
            max_cs_setup_ns: 0.into(),
            max_cs_hold_ns: 0.into(),
            max_cs_inactive_ns: 0.into(),
        })
    }
}

#[derive(Debug)]
pub struct SpiController<D: SpiDevice> {
    device: D,
    config: VirtioSpiConfig,
}

impl<D: SpiDevice> SpiController<D> {
    // Creates a new controller corresponding to `device`.
    pub(crate) fn new(device: D) -> Result<Self> {
        let config: VirtioSpiConfig = device.detect_supported_features()?;

        Ok(Self { device, config })
    }

    pub(crate) const fn config(&self) -> &VirtioSpiConfig {
        &self.config
    }

    pub(crate) fn transfer(&self, reqs: &mut [SpiTransReq]) -> Result<()> {
        let mut msgs: Vec<SpiIocTransfer> = Vec::with_capacity(reqs.len());
        let mut tx_buf_ptr: *mut u8;
        let mut rx_buf_ptr: *mut u8;

        let saved_mode: u32 = self.device.mode()?;
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
                _padding: 0,
            });

            if (req.mode & ReqMode::CPHA.bits()) == ReqMode::CPHA.bits() {
                trans_mode |= LnxSpiMode::CPHA.bits();
            } else {
                trans_mode &= !LnxSpiMode::CPHA.bits();
            }
            if (req.mode & ReqMode::CPOL.bits()) == ReqMode::CPOL.bits() {
                trans_mode |= LnxSpiMode::CPOL.bits();
            } else {
                trans_mode &= !LnxSpiMode::CPOL.bits();
            }
            if (req.mode & ReqMode::CS_HIGH.bits()) == ReqMode::CS_HIGH.bits() {
                trans_mode |= LnxSpiMode::CS_HIGH.bits();
            } else {
                trans_mode &= !LnxSpiMode::CS_HIGH.bits();
            }
            if (req.mode & ReqMode::LSB_FIRST.bits()) == ReqMode::LSB_FIRST.bits() {
                trans_mode |= LnxSpiMode::LSB_FIRST.bits();
            } else {
                trans_mode &= !LnxSpiMode::LSB_FIRST.bits();
            }
            if (req.mode & ReqMode::LOOP.bits()) == ReqMode::LOOP.bits() {
                trans_mode |= LnxSpiMode::LOOP.bits();
            } else {
                trans_mode &= !LnxSpiMode::LOOP.bits();
            }
        }

        self.device.set_mode(trans_mode)?;
        self.device.rdwr(&mut msgs)?;
        self.device.set_mode(saved_mode)?;

        Ok(())
    }

    pub(crate) fn check_trans_params(
        &self,
        reqs: &mut [SpiTransReq],
        param_stat: &mut Vec<bool>,
    ) -> bool {
        let mut reqs_valid: bool = true;
        let mut trans_params_valid: bool;

        for req in reqs {
            trans_params_valid = true;

            if self.config.cs_max_number < req.cs_id {
                trans_params_valid = false;
            }

            if (self.config.bits_per_word_mask != 0)
                && ((1 << (req.bits_per_word - 1)) & self.config.bits_per_word_mask.to_native())
                    == 0
            {
                println!(
                    "cuihaixu: self.config.bits_per_word_mask {}",
                    self.config.bits_per_word_mask.to_native()
                );
                trans_params_valid = false;
            }

            if ((self.config.tx_nbits_supported & ConfigNbits::DUAL.bits()) == 0
                && req.tx_nbits == 2)
                || ((self.config.tx_nbits_supported & ConfigNbits::QUAD.bits()) == 0
                    && req.tx_nbits == 4)
                || ((self.config.tx_nbits_supported & ConfigNbits::OCTAL.bits()) == 0
                    && req.tx_nbits == 8)
                || ((req.tx_nbits != 0)
                    && (req.tx_nbits != 1)
                    && (req.tx_nbits != 2)
                    && (req.tx_nbits != 4)
                    && (req.tx_nbits != 8))
            {
                trans_params_valid = false;
            }

            if ((self.config.rx_nbits_supported & ConfigNbits::DUAL.bits()) == 0
                && req.rx_nbits == 2)
                || ((self.config.rx_nbits_supported & ConfigNbits::QUAD.bits()) == 0
                    && req.rx_nbits == 4)
                || ((self.config.rx_nbits_supported & ConfigNbits::OCTAL.bits()) == 0
                    && req.rx_nbits == 8)
                || ((req.rx_nbits != 0)
                    && (req.rx_nbits != 1)
                    && (req.rx_nbits != 2)
                    && (req.rx_nbits != 4)
                    && (req.rx_nbits != 8))
            {
                trans_params_valid = false;
            }

            if (req.mode & ReqMode::CPHA.bits() == 0)
                && (self.config.mode_func_supported.to_native() & ConfigMode::CPHA_0.bits() == 0)
            {
                trans_params_valid = false;
            }

            if (req.mode & ReqMode::CPHA.bits() == ReqMode::CPHA.bits())
                && (self.config.mode_func_supported.to_native() & ConfigMode::CPHA_1.bits() == 0)
            {
                trans_params_valid = false;
            }

            if (req.mode & ReqMode::CPOL.bits() == 0)
                && (self.config.mode_func_supported.to_native() & ConfigMode::CPOL_0.bits() == 0)
            {
                trans_params_valid = false;
            }

            if (req.mode & ReqMode::CPOL.bits() == ReqMode::CPOL.bits())
                && (self.config.mode_func_supported.to_native() & ConfigMode::CPOL_1.bits() == 0)
            {
                trans_params_valid = false;
            }

            if (req.mode & ReqMode::CS_HIGH.bits() == ReqMode::CS_HIGH.bits())
                && (self.config.mode_func_supported.to_native() & ConfigMode::CS_HIGH.bits() == 0)
            {
                trans_params_valid = false;
            }

            if (req.mode & ReqMode::LSB_FIRST.bits() == ReqMode::LSB_FIRST.bits())
                && (self.config.mode_func_supported.to_native() & ConfigMode::LSB.bits() == 0)
            {
                trans_params_valid = false;
            }

            if (req.mode & ReqMode::LOOP.bits() == ReqMode::LOOP.bits())
                && (self.config.mode_func_supported.to_native() & ConfigMode::LOOP.bits() == 0)
            {
                println!("reach here???");
                println!(
                    "cuihaixu: self.config.mode_func_supported.to_native {}",
                    self.config.mode_func_supported.to_native()
                );
                println!("cuihaixu {}", ConfigMode::LOOP.bits());
                trans_params_valid = false;
            }

            if (self.config.max_freq_hz != 0)
                && (req.speed_hz > self.config.max_freq_hz.to_native())
            {
                trans_params_valid = false;
            }

            param_stat.push(trans_params_valid);
            if !trans_params_valid {
                reqs_valid = false;
            }
        }

        reqs_valid
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;
    use vmm_sys_util::tempfile::TempFile;

    // Update read-buffer of each write-buffer with index + 1 value.
    pub fn update_rdwr_buf(buf: u64, len: u32) {
        let buf_ptr = buf as *mut u8;

        // SAFETY: Safe as the buf is from the request tx/rx filed
        unsafe {
            for i in 0..len {
                ptr::write(buf_ptr.add(i as usize), i as u8);
            }
        }
    }

    // Verify the write-buffer passed to us
    pub fn verify_rdwr_buf(buf: u64, len: u32) {
        let buf_ptr = buf as *mut u8;

        // SAFETY: Safe as the buf is from the request tx/rx filed
        unsafe {
            for i in 0..len {
                assert_eq!(ptr::read(buf_ptr.add(i as usize)), i as u8);
            }
        }
    }

    #[derive(Debug)]
    pub struct DummyDevice {
        mode_result: Result<u32>,
        set_mode_result: Result<()>,
        max_speed_result: Result<u32>,
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
                bits_per_word_mask: 0.into(),
                mode_func_supported: 0xf.into(),
                max_freq_hz: 10000.into(),
                max_word_delay_ns: 0.into(),
                max_cs_setup_ns: 0.into(),
                max_cs_hold_ns: 0.into(),
                max_cs_inactive_ns: 0.into(),
            };

            Self {
                mode_result: Ok(0),
                set_mode_result: Ok(()),
                max_speed_result: Ok(0),
                set_max_speed_result: Ok(()),
                get_bpw_result: Ok(0),
                set_bpw_result: Ok(()),
                rdwr_result: Ok(()),
                detect_supported_features_result: Ok(default_config),
            }
        }
    }

    impl SpiDevice for DummyDevice {
        fn open(_spidev_name: &Path) -> Result<Self> {
            Ok(DummyDevice::default())
        }

        fn max_speed_hz(&self) -> Result<u32> {
            self.max_speed_result
        }

        fn set_max_speed_hz(&self, _max_speed_hz: u32) -> Result<()> {
            self.set_max_speed_result
        }

        fn bits_per_word(&self) -> Result<u8> {
            self.get_bpw_result
        }

        fn set_bits_per_word(&self, _bpw: u8) -> Result<()> {
            self.set_bpw_result
        }

        fn mode(&self) -> Result<u32> {
            self.mode_result
        }

        fn set_mode(&self, _mode: u32) -> Result<()> {
            self.set_mode_result
        }

        fn rdwr(&self, reqs: &mut [SpiIocTransfer]) -> Result<()> {
            for req in reqs {
                if req.tx_buf != 0 {
                    verify_rdwr_buf(req.tx_buf, req.len);
                }

                if req.rx_buf != 0 {
                    update_rdwr_buf(req.rx_buf, req.len);
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
                verify_rdwr_buf(req.rx_buf.as_ptr() as u64, req.trans_len);
            }
        }
    }

    impl<D: SpiDevice> SpiController<D> {
        pub(crate) fn update_bpw_mask_config(&mut self, bpw_mask: u32) {
            self.config.bits_per_word_mask = bpw_mask.into();
        }

        pub(crate) fn update_mode_config(&mut self, mode: u32) {
            self.config.mode_func_supported = mode.into();
        }
    }

    #[test]
    fn test_spi_transfer() {
        let dummy_device = PathBuf::from("spidev0.0");
        let spi_dummy_ctrl = SpiController::new(DummyDevice::open(&dummy_device).unwrap()).unwrap();

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
                update_rdwr_buf(req.tx_buf.as_ptr() as u64, req.trans_len);
            }
        }

        spi_dummy_ctrl.transfer(&mut reqs).unwrap();
        verify_rdwr_data(&reqs);
    }

    #[test]
    fn test_phys_device_failure() {
        // Open failure

        let invalid_spi_dev = PathBuf::from("/dev/spidev-invalid");
        assert_eq!(
            PhysDevice::open(&invalid_spi_dev).unwrap_err(),
            Error::DeviceOpenFailed
        );

        let file = TempFile::new().unwrap();
        //let dev = PhysDevice::open(file.as_path().to_str().unwrap()).unwrap();
        let dev = PhysDevice::open(file.as_path()).unwrap();

        assert_eq!(
            dev.mode().unwrap_err(),
            Error::IoctlFailure("mode", IoError::last())
        );

        assert_eq!(
            dev.set_mode(0).unwrap_err(),
            Error::IoctlFailure("set_mode", IoError::last())
        );

        assert_eq!(
            dev.max_speed_hz().unwrap_err(),
            Error::IoctlFailure("max_speed_hz", IoError::last())
        );

        assert_eq!(
            dev.set_max_speed_hz(0).unwrap_err(),
            Error::IoctlFailure("set_max_speed_hz", IoError::last())
        );

        assert_eq!(
            dev.bits_per_word().unwrap_err(),
            Error::IoctlFailure("bits_per_word", IoError::last())
        );

        assert_eq!(
            dev.set_bits_per_word(0).unwrap_err(),
            Error::IoctlFailure("set_bits_per_word", IoError::last())
        );

        assert_eq!(
            dev.detect_supported_features().unwrap_err(),
            Error::IoctlFailure("max_speed_hz", IoError::last())
        );

        // rdwr failure
        let mut reqs = [SpiIocTransfer {
            tx_buf: vec![7, 4].as_ptr() as u64,
            rx_buf: vec![7, 4].as_ptr() as u64,
            len: 2,
            speed_hz: 10000,
            delay_usecs: 0,
            bits_per_word: 8,
            cs_change: 1,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            _padding: 0,
        }];
        assert_eq!(
            dev.rdwr(&mut reqs).unwrap_err(),
            Error::IoctlFailure("rdwr", IoError::last())
        );
    }

    #[test]
    fn test_spi_ioctl_cmd() {
        assert_eq!(SPI_IOC_RD_BITS_PER_WORD(), 0x80016b03);
        assert_eq!(SPI_IOC_WR_BITS_PER_WORD(), 0x40016b03);
        assert_eq!(SPI_IOC_RD_MAX_SPEED_HZ(), 0x80046b04);
        assert_eq!(SPI_IOC_WR_MAX_SPEED_HZ(), 0x40046b04);
        assert_eq!(SPI_IOC_RD_MODE32(), 0x80046b05);
        assert_eq!(SPI_IOC_WR_MODE32(), 0x40046b05);
        assert_eq!(spi_ioc_message(1), 0x40206b00);
        assert_eq!(spi_ioc_message(2), 0x40406b00);
    }

    #[test]
    fn test_spi_ctrl_param_check() {
        let dummy_device = PathBuf::from("spidev0.0");
        let mut spi_dummy_ctrl =
            SpiController::new(DummyDevice::open(&dummy_device).unwrap()).unwrap();
        let mut reqs: Vec<SpiTransReq> = Vec::new();
        let mut param_stats: Vec<bool> = Vec::new();

        // valid transfer request
        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0,
            delay_usecs: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(false);

        assert!(spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(param_stats.pop().unwrap());

        reqs.pop();

        // transfer request with invalid cs_id
        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0,
            delay_usecs: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 3,
        };

        reqs.push(trans_header);
        param_stats.push(true);

        assert!(!spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(!param_stats.pop().unwrap());

        reqs.pop();

        // transfer request with invalid freq
        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 1000000,
            mode: 0,
            delay_usecs: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(true);

        assert!(!spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(!param_stats.pop().unwrap());

        reqs.pop();

        // transfer request with invalid mode
        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 10000,
            mode: 0x10,
            delay_usecs: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(true);

        assert!(!spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(!param_stats.pop().unwrap());

        reqs.pop();

        // transfer request with invalid tx_nbits
        let trans_header1 = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 10000,
            mode: 0x10,
            delay_usecs: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 2,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        let trans_header2 = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0,
            delay_usecs: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header1);
        param_stats.push(true);
        reqs.push(trans_header2);
        param_stats.push(false);

        assert!(!spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(param_stats.pop().unwrap());
        assert!(!param_stats.pop().unwrap());

        reqs.pop();
        reqs.pop();

        spi_dummy_ctrl.update_bpw_mask_config(0xf);
        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0,
            delay_usecs: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(false);

        assert!(!spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(!param_stats.pop().unwrap());

        reqs.pop();

        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0,
            delay_usecs: 0,
            bits_per_word: 1,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(false);

        assert!(spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(param_stats.pop().unwrap());

        reqs.pop();

        spi_dummy_ctrl.update_mode_config(0x4f);

        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0x10,
            delay_usecs: 0,
            bits_per_word: 1,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(true);

        assert!(spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(param_stats.pop().unwrap());

        reqs.pop();

        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0x14,
            delay_usecs: 0,
            bits_per_word: 1,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(true);

        assert!(!spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(!param_stats.pop().unwrap());

        reqs.pop();

        spi_dummy_ctrl.update_mode_config(0x5f);

        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0x14,
            delay_usecs: 0,
            bits_per_word: 1,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(true);

        assert!(spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(param_stats.pop().unwrap());

        reqs.pop();

        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0x8,
            delay_usecs: 0,
            bits_per_word: 1,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(true);

        assert!(!spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(!param_stats.pop().unwrap());

        reqs.pop();

        spi_dummy_ctrl.update_mode_config(0x2f);

        let trans_header = SpiTransReq {
            tx_buf: Vec::<u8>::new(),
            rx_buf: vec![0; 15],
            trans_len: 15,
            speed_hz: 0,
            mode: 0x8,
            delay_usecs: 0,
            bits_per_word: 1,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            word_delay_usecs: 0,
            cs_id: 0,
        };

        reqs.push(trans_header);
        param_stats.push(true);

        assert!(spi_dummy_ctrl.check_trans_params(&mut reqs, &mut param_stats));
        assert!(param_stats.pop().unwrap());

        reqs.pop();
    }
}

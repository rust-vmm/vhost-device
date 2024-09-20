// Low level I2C definitions
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::info;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use libc::{c_ulong, ioctl};
use thiserror::Error as ThisError;
use vmm_sys_util::errno::Error as IoError;

use super::AdapterConfig;
use crate::AdapterIdentifier;

// The type of the `req` parameter is different for the `musl` library. This will enable
// successful build for other non-musl libraries.
#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = c_ulong;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ThisError)]
/// Errors related to low level i2c helpers
pub enum Error {
    #[error("Incorrect message length for {0} operation: {1}")]
    MessageLengthInvalid(&'static str, usize),
    #[error("Invalid SMBUS command: {0}")]
    SMBusCommandInvalid(u32),
    #[error("Invalid SMBus transfer, request-count: {0}, req[0].len: {1}, req[1].len: {2}")]
    SMBusTransferInvalid(usize, u16, u16),
    #[error("Invalid I2C transfer, request with invalid count: {0}")]
    I2cTransferInvalid(usize),
    #[error("Failed to open adapter at /dev/i2c-{0}")]
    DeviceOpenFailed(u32),
    #[error("Ioctl command failed for {0} operation: {1}")]
    IoctlFailure(&'static str, IoError),
    #[error("Invalid Adapter function: {0:x}")]
    AdapterFunctionInvalid(u64),
    #[error("Invalid Client Address")]
    ClientAddressInvalid,
    #[error("Adapter not found")]
    AdapterNotFound,
    #[error("Multiple adapters share the same name")]
    AdapterShareSameName,
    #[error("Std IO Error")]
    StdIoErr,
    #[error("Failed while parsing to integer")]
    ParseFailure,
}

// Linux I2C/SMBUS definitions
// IOCTL commands, refer Linux's Documentation/i2c/dev-interface.rst for further details.

/// NOTE: Slave address is 7 or 10 bits, but 10-bit addresses are NOT supported!
/// (due to code brokenness)
const I2C_SLAVE: IoctlRequest = 0x0703; // Use this slave address
const I2C_FUNCS: IoctlRequest = 0x0705; // Get the adapter functionality mask
const I2C_RDWR: IoctlRequest = 0x0707; // Combined R/W transfer (one STOP only)
const I2C_SMBUS: IoctlRequest = 0x0720; // SMBus transfer

// Functions

const I2C_FUNC_I2C: u64 = 0x00000001;
const I2C_FUNC_SMBUS_READ_BYTE: u64 = 0x00020000;
const I2C_FUNC_SMBUS_WRITE_BYTE: u64 = 0x00040000;
const I2C_FUNC_SMBUS_READ_BYTE_DATA: u64 = 0x00080000;
const I2C_FUNC_SMBUS_WRITE_BYTE_DATA: u64 = 0x00100000;
const I2C_FUNC_SMBUS_READ_WORD_DATA: u64 = 0x00200000;
const I2C_FUNC_SMBUS_WRITE_WORD_DATA: u64 = 0x00400000;

const I2C_FUNC_SMBUS_BYTE: u64 = I2C_FUNC_SMBUS_READ_BYTE | I2C_FUNC_SMBUS_WRITE_BYTE;
const I2C_FUNC_SMBUS_BYTE_DATA: u64 =
    I2C_FUNC_SMBUS_READ_BYTE_DATA | I2C_FUNC_SMBUS_WRITE_BYTE_DATA;
const I2C_FUNC_SMBUS_WORD_DATA: u64 =
    I2C_FUNC_SMBUS_READ_WORD_DATA | I2C_FUNC_SMBUS_WRITE_WORD_DATA;
const I2C_FUNC_SMBUS_ALL: u64 =
    I2C_FUNC_SMBUS_BYTE | I2C_FUNC_SMBUS_BYTE_DATA | I2C_FUNC_SMBUS_WORD_DATA;

// I2C protocol definitions

/// read data, from slave to master
pub const I2C_M_RD: u16 = 0x0001;

/// `I2cMsg` - an I2C transaction segment beginning with `START`
///
/// Copied (partially) from Linux's include/uapi/linux/i2c.h
///
/// ```text
/// @addr: Slave address, only 7 bit supported by virtio specification.
///
/// @flags:
///   Supported by all adapters:
///   %I2C_M_RD: read data (from slave to master). Guaranteed to be 0x0001!
///
///   Optional:
///   These aren't supported by virtio specification yet.
///
/// @len: Number of data bytes in @buf being read from or written to the I2C
///   slave address.
///
/// @buf: The buffer into which data is read, or from which it's written.
///
/// An I2cMsg is the low level representation of one segment of an I2C
/// transaction.
///
/// Each transaction begins with a START. That is followed by the slave
/// address, and a bit encoding read versus write. Then follow all the
/// data bytes, possibly including a byte with SMBus PEC. The transfer
/// terminates with a NAK, or when all those bytes have been transferred
/// and ACKed. If this is the last message in a group, it is followed by
/// a STOP. Otherwise it is followed by the next @I2cMsg transaction
/// segment, beginning with a (repeated) START.
/// ```
#[repr(C)]
struct I2cMsg {
    addr: u16,
    flags: u16,
    len: u16,
    buf: *mut u8,
}

/// This is the structure as used in the I2C_RDWR ioctl call
#[repr(C)]
pub struct I2cRdwrIoctlData {
    msgs: *mut I2cMsg,
    nmsgs: u32,
}

// SMBUS protocol definitions
// SMBUS read or write markers

const I2C_SMBUS_WRITE: u8 = 0;
const I2C_SMBUS_READ: u8 = 1;

// SMBus transaction types (size parameter in the above functions)

const I2C_SMBUS_QUICK: u32 = 0;
const I2C_SMBUS_BYTE: u32 = 1;
const I2C_SMBUS_BYTE_DATA: u32 = 2;
const I2C_SMBUS_WORD_DATA: u32 = 3;

/// As specified in SMBus standard
const I2C_SMBUS_BLOCK_MAX: usize = 32;

#[repr(C)]
union I2cSmbusData {
    byte: u8,
    word: u16,

    /// block[0] is used for length, and one more for user-space compatibility
    block: [u8; I2C_SMBUS_BLOCK_MAX + 2],
}

impl I2cSmbusData {
    const fn read_byte(&self) -> u8 {
        // SAFETY: Safe as we will only read the relevant bytes.
        unsafe { self.byte }
    }

    const fn read_word(&self) -> u16 {
        // SAFETY: Safe as we will only read the relevant bytes.
        unsafe { self.word }
    }
}

/// This is the structure as used in the `I2C_SMBUS` ioctl call
#[repr(C)]
pub struct I2cSmbusIoctlData {
    read_write: u8,
    command: u8,
    size: u32,
    data: *mut I2cSmbusData,
}

pub struct SmbusMsg {
    read_write: u8,
    command: u8,
    size: u32,
    data: Option<I2cSmbusData>,
}

impl SmbusMsg {
    /// Based on Linux's drivers/i2c/i2c-core-smbus.c:i2c_smbus_xfer_emulated().
    ///
    /// These smbus related functions try to reverse what Linux does, only
    /// support basic modes (up to word transfer).
    fn new(reqs: &[I2cReq]) -> Result<Self> {
        let mut data = I2cSmbusData {
            block: [0; I2C_SMBUS_BLOCK_MAX + 2],
        };

        // Write messages have only one request message, while read messages
        // will have two (except for few special cases of I2C_SMBUS_QUICK and
        // I2C_SMBUS_BYTE, where only one request messages is sent).
        match reqs.len() {
            // Write requests (with some exceptions as mentioned above)
            1 => {
                let read_write = match reqs[0].flags & I2C_M_RD {
                    0 => I2C_SMBUS_WRITE,
                    _ => I2C_SMBUS_READ,
                };

                match reqs[0].len {
                    // Special Read requests
                    0 => Ok(Self {
                        read_write,
                        command: 0,
                        size: I2C_SMBUS_QUICK,
                        data: None,
                    }),

                    1 => Ok(Self {
                        read_write,
                        command: reqs[0].buf[0],
                        size: I2C_SMBUS_BYTE,
                        data: Some(data),
                    }),

                    // Write requests
                    2 => {
                        if read_write == I2C_SMBUS_READ {
                            // Special Read requests, reqs[0].len can be 0 or 1 only.
                            Err(Error::MessageLengthInvalid("read", 2))
                        } else {
                            data.byte = reqs[0].buf[1];
                            Ok(Self {
                                read_write,
                                command: reqs[0].buf[0],
                                size: I2C_SMBUS_BYTE_DATA,
                                data: Some(data),
                            })
                        }
                    }

                    3 => {
                        if read_write == I2C_SMBUS_READ {
                            // Special Read requests, reqs[0].len can be 0 or 1 only.
                            Err(Error::MessageLengthInvalid("read", 3))
                        } else {
                            data.word =
                                u16::from(reqs[0].buf[1]) | (u16::from(reqs[0].buf[2]) << 8);
                            Ok(Self {
                                read_write,
                                command: reqs[0].buf[0],
                                size: I2C_SMBUS_WORD_DATA,
                                data: Some(data),
                            })
                        }
                    }
                    _ => Err(Error::MessageLengthInvalid("write", reqs[0].len as usize)),
                }
            }

            // Read requests
            2 => {
                // The first request contains the command, so its length must be
                // set to 1 and shouldn't have I2C_M_RD set in flags.
                //
                // The second request contains the read buffer, so must have its
                // I2C_M_RD flag set. We don't support block transfers yet and
                // so its length shouldn't be greater than 2.
                if ((reqs[0].flags & I2C_M_RD) != 0)
                    || ((reqs[1].flags & I2C_M_RD) == 0)
                    || (reqs[0].len != 1)
                    || (reqs[1].len > 2)
                {
                    Err(Error::SMBusTransferInvalid(
                        reqs.len(),
                        reqs[0].len,
                        reqs[1].len,
                    ))
                } else {
                    Ok(Self {
                        read_write: I2C_SMBUS_READ,
                        command: reqs[0].buf[0],
                        size: if reqs[1].len == 1 {
                            I2C_SMBUS_BYTE_DATA
                        } else {
                            I2C_SMBUS_WORD_DATA
                        },
                        data: Some(data),
                    })
                }
            }

            _ => Err(Error::SMBusTransferInvalid(
                reqs.len(),
                reqs[0].len,
                reqs[1].len,
            )),
        }
    }
}

/// I2C definitions
pub struct I2cReq {
    pub addr: u16,
    pub flags: u16,
    pub len: u16,
    pub buf: Vec<u8>,
}

/// Trait that represents an I2C Device.
///
/// This trait is introduced for development purposes only, and should not
/// be used outside of this crate. The purpose of this trait is to provide a
/// mock implementation for the I2C driver so that we can test the I2C
/// functionality without the need of a physical device.
pub trait I2cDevice {
    // Open the device specified by the adapter identifier, number or name.
    fn open(adapter_identifier: &AdapterIdentifier) -> Result<Self>
    where
        Self: Sized;

    // Corresponds to the I2C_FUNCS ioctl call.
    fn funcs(&mut self) -> Result<u64>;

    // Corresponds to the I2C_RDWR ioctl call.
    fn rdwr(&self, reqs: &mut [I2cReq]) -> Result<()>;

    // Corresponds to the I2C_SMBUS ioctl call.
    fn smbus(&self, msg: &mut SmbusMsg) -> Result<()>;

    // Corresponds to the I2C_SLAVE ioctl call.
    fn slave(&self, addr: u64) -> Result<()>;

    // Returns the adapter number corresponding to this device.
    fn adapter_no(&self) -> u32;
}

/// A physical I2C device. This structure can only be initialized on hosts
/// where `/dev/i2c-XX` is available.
#[derive(Debug)]
pub struct PhysDevice {
    file: File,
    adapter_no: u32,
}

impl PhysDevice {
    fn open_with(device_path: &str, adapter_no: u32) -> Result<Self> {
        Ok(Self {
            file: OpenOptions::new()
                .read(true)
                .write(true)
                .open(device_path)
                .map_err(|_| Error::DeviceOpenFailed(adapter_no))?,
            adapter_no,
        })
    }

    fn find_adapter(name: &str) -> Result<u32> {
        let mut adapter_no = None;

        for entry in
            fs::read_dir(Path::new("/sys/bus/i2c/devices/")).map_err(|_| Error::StdIoErr)?
        {
            let entry = entry.map_err(|_| Error::StdIoErr)?;
            let mut path = entry.path();
            path.push("name");
            let adapter_name = fs::read_to_string(path).map_err(|_| Error::StdIoErr)?;

            if adapter_name.trim() == name {
                if adapter_no.is_some() {
                    return Err(Error::AdapterShareSameName);
                }
                let path = entry.path();
                let list: Vec<&str> = path.to_str().unwrap().split('-').collect();
                adapter_no = Some(list[1].parse::<u32>().map_err(|_| Error::ParseFailure)?);
            }
        }
        adapter_no.ok_or(Error::AdapterNotFound)
    }
}

impl I2cDevice for PhysDevice {
    fn open(adapter_identifier: &AdapterIdentifier) -> Result<Self> {
        let adapter_no = match adapter_identifier {
            AdapterIdentifier::Name(adapter_name) => Self::find_adapter(adapter_name)?,
            AdapterIdentifier::Number(no) => *no,
        };
        let device_path = format!("/dev/i2c-{}", adapter_no);

        Self::open_with(&device_path, adapter_no)
    }

    fn funcs(&mut self) -> Result<u64> {
        let mut func: u64 = 0;

        // SAFETY: Safe as the file is a valid I2C adapter, the kernel will only
        // update the correct amount of memory in func.
        let ret = unsafe { ioctl(self.file.as_raw_fd(), I2C_FUNCS, &mut func) };

        if ret == -1 {
            Err(Error::IoctlFailure("funcs", IoError::last()))
        } else {
            Ok(func)
        }
    }

    fn rdwr(&self, reqs: &mut [I2cReq]) -> Result<()> {
        let mut msgs: Vec<I2cMsg> = Vec::with_capacity(reqs.len());
        let len = reqs.len();

        for req in reqs {
            if req.len == 0 {
                return Err(Error::I2cTransferInvalid(0));
            }

            msgs.push(I2cMsg {
                addr: req.addr,
                flags: req.flags,
                len: req.len,
                buf: req.buf.as_mut_ptr(),
            });
        }

        let mut data = I2cRdwrIoctlData {
            msgs: msgs.as_mut_ptr(),
            nmsgs: len as u32,
        };

        // SAFETY: Safe as the file is a valid I2C adapter, the kernel will only
        // update the correct amount of memory in data.
        let ret = unsafe { ioctl(self.file.as_raw_fd(), I2C_RDWR, &mut data) };

        if ret == -1 {
            Err(Error::IoctlFailure("rdwr", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn smbus(&self, msg: &mut SmbusMsg) -> Result<()> {
        let mut smbus_data = I2cSmbusIoctlData {
            read_write: msg.read_write,
            command: msg.command,
            size: msg.size,
            data: msg.data.as_mut().map_or(std::ptr::null_mut(), |data| data),
        };

        // SAFETY: Safe as the file is a valid I2C adapter, the kernel will only
        // update the correct amount of memory in data.
        let ret = unsafe { ioctl(self.file.as_raw_fd(), I2C_SMBUS, &mut smbus_data) };

        if ret == -1 {
            Err(Error::IoctlFailure("smbus", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn slave(&self, addr: u64) -> Result<()> {
        // SAFETY: Safe as the file is a valid I2C adapter.
        let ret = unsafe { ioctl(self.file.as_raw_fd(), I2C_SLAVE, addr as c_ulong) };

        if ret == -1 {
            Err(Error::IoctlFailure("slave", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn adapter_no(&self) -> u32 {
        self.adapter_no
    }
}

#[derive(Debug)]
pub struct I2cAdapter<D: I2cDevice> {
    device: D,
    adapter_no: u32,
    smbus: bool,
}

impl<D: I2cDevice> I2cAdapter<D> {
    // Creates a new adapter corresponding to `device`.
    fn new(mut device: D) -> Result<Self> {
        let smbus;

        let func = device.funcs()?;
        if (func & I2C_FUNC_I2C) != 0 {
            smbus = false;
        } else if (func & I2C_FUNC_SMBUS_ALL) != 0 {
            smbus = true;
        } else {
            return Err(Error::AdapterFunctionInvalid(func));
        }

        Ok(Self {
            adapter_no: device.adapter_no(),
            device,
            smbus,
        })
    }

    /// Perform I2C_RDWR transfer
    fn i2c_transfer(&self, reqs: &mut [I2cReq]) -> Result<()> {
        self.device.rdwr(reqs)
    }

    /// Perform I2C_SMBUS transfer
    fn smbus_transfer(&self, reqs: &mut [I2cReq]) -> Result<()> {
        let mut msg = SmbusMsg::new(reqs)?;
        self.device.smbus(&mut msg)?;

        if msg.read_write == I2C_SMBUS_READ {
            match msg.size {
                I2C_SMBUS_QUICK => {}
                I2C_SMBUS_BYTE => reqs[0].buf[0] = msg.data.unwrap().read_byte(),
                I2C_SMBUS_BYTE_DATA => reqs[1].buf[0] = msg.data.unwrap().read_byte(),
                I2C_SMBUS_WORD_DATA => {
                    let word = msg.data.unwrap().read_word();

                    reqs[1].buf[0] = (word & 0xff) as u8;
                    reqs[1].buf[1] = (word >> 8) as u8;
                }

                _ => {
                    return Err(Error::SMBusCommandInvalid(msg.size));
                }
            }
        }
        Ok(())
    }

    const fn adapter_no(&self) -> u32 {
        self.adapter_no
    }

    const fn is_smbus(&self) -> bool {
        self.smbus
    }

    /// Sets device's address for an I2C adapter.
    fn set_device_addr(&self, addr: usize) -> Result<()> {
        self.device.slave(addr as u64)
    }

    fn transfer(&self, reqs: &mut [I2cReq]) -> Result<()> {
        if self.is_smbus() {
            self.smbus_transfer(reqs)
        } else {
            self.i2c_transfer(reqs)
        }
    }
}

/// I2C map and helpers
pub const MAX_I2C_VDEV: usize = 1 << 7;

pub struct I2cMap<D: I2cDevice> {
    adapters: Vec<I2cAdapter<D>>,
    device_map: HashMap<u16, usize>,
}

impl<D: I2cDevice> I2cMap<D> {
    pub(crate) fn new(device_config: &AdapterConfig) -> Result<Self>
    where
        Self: Sized,
    {
        let mut device_map = HashMap::new();
        let mut adapters: Vec<I2cAdapter<D>> = Vec::new();

        for (i, device_cfg) in device_config.inner.iter().enumerate() {
            let device = D::open(&device_cfg.adapter)?;
            let adapter = I2cAdapter::new(device)?;

            // Check that all addresses corresponding to the adapter are valid.
            for addr in &device_cfg.addr {
                adapter.set_device_addr(*addr as usize)?;
                device_map.insert(*addr, i);
            }

            info!(
                "Added I2C master with bus id: {:x} for devices",
                adapter.adapter_no(),
            );

            adapters.push(adapter);
        }

        Ok(Self {
            adapters,
            device_map,
        })
    }

    pub fn transfer(&self, reqs: &mut [I2cReq]) -> Result<()> {
        let device = reqs[0].addr;

        // identify the device in the device_map
        let index = match self.device_map.get(&device) {
            Some(&index) => index,

            // This can happen a lot while scanning the bus, don't print any errors.
            None => return Err(Error::ClientAddressInvalid),
        };

        // get the corresponding adapter based on the device config.
        let adapter = &self.adapters[index];

        // Set device's address
        adapter.set_device_addr(device as usize)?;
        adapter.transfer(reqs)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::DeviceConfig;
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
        funcs_result: Result<u64>,
        rdwr_result: Result<()>,
        smbus_result: Result<()>,
        slave_result: Result<()>,
        adapter_no: u32,
    }

    impl DummyDevice {
        const fn find_adapter(_name: &str) -> Result<u32> {
            Ok(11)
        }
    }

    impl Default for DummyDevice {
        fn default() -> Self {
            Self {
                funcs_result: Ok(I2C_FUNC_I2C),
                rdwr_result: Ok(()),
                smbus_result: Ok(()),
                slave_result: Ok(()),
                adapter_no: 0,
            }
        }
    }

    impl I2cDevice for DummyDevice {
        fn open(adapter_identifier: &AdapterIdentifier) -> Result<Self>
        where
            Self: Sized,
        {
            match adapter_identifier {
                AdapterIdentifier::Name(adapter_name) => Ok(Self {
                    adapter_no: Self::find_adapter(adapter_name)?,
                    ..Default::default()
                }),
                AdapterIdentifier::Number(adapter_no) => Ok(Self {
                    adapter_no: *adapter_no,
                    ..Default::default()
                }),
            }
        }

        fn funcs(&mut self) -> Result<u64> {
            self.funcs_result
        }

        fn rdwr(&self, reqs: &mut [I2cReq]) -> Result<()> {
            for req in reqs {
                if req.len == 0 {
                    return Err(Error::I2cTransferInvalid(0));
                }

                if (req.flags & I2C_M_RD) != 0 {
                    update_rdwr_buf(&mut req.buf);
                } else {
                    verify_rdwr_buf(&req.buf);
                }
            }

            self.rdwr_result
        }

        fn smbus(&self, msg: &mut SmbusMsg) -> Result<()> {
            // Update data unconditionally to 1 and 2.
            if let Some(data) = &mut msg.data {
                data.word = 0x0201;
            }
            self.smbus_result
        }

        fn slave(&self, _addr: u64) -> Result<()> {
            self.slave_result
        }

        fn adapter_no(&self) -> u32 {
            self.adapter_no
        }
    }

    fn verify_rdwr_data(reqs: &[I2cReq]) {
        // Match what's done by DummyDevice::rdwr()
        for req in reqs {
            if (req.flags & I2C_M_RD) != 0 {
                verify_rdwr_buf(&req.buf);
            }
        }
    }

    #[test]
    fn test_funcs() {
        let i2c_device = DummyDevice {
            funcs_result: Ok(I2C_FUNC_SMBUS_ALL),
            ..Default::default()
        };
        let adapter = I2cAdapter::new(i2c_device).unwrap();
        assert!(adapter.smbus);

        let i2c_device = DummyDevice {
            funcs_result: Ok(I2C_FUNC_I2C),
            ..Default::default()
        };
        let adapter = I2cAdapter::new(i2c_device).unwrap();
        assert!(!adapter.smbus);

        let i2c_device = DummyDevice {
            funcs_result: Ok(0),
            ..Default::default()
        };
        assert_eq!(
            I2cAdapter::new(i2c_device).unwrap_err(),
            Error::AdapterFunctionInvalid(0)
        );
    }

    #[test]
    fn test_i2c_map() {
        let adapter_config = AdapterConfig::new_with(vec![
            DeviceConfig::new_with(AdapterIdentifier::Number(1), vec![4]),
            DeviceConfig::new_with(AdapterIdentifier::Number(2), vec![32, 21]),
            DeviceConfig::new_with(AdapterIdentifier::Number(5), vec![10, 23]),
        ]);
        let i2c_map: I2cMap<DummyDevice> = I2cMap::new(&adapter_config).unwrap();

        assert_eq!(i2c_map.adapters.len(), 3);
        assert_eq!(i2c_map.adapters[0].adapter_no(), 1);
        assert_eq!(i2c_map.adapters[1].adapter_no(), 2);
        assert_eq!(i2c_map.adapters[2].adapter_no(), 5);

        assert_eq!(i2c_map.device_map.get(&4), Some(&0));
        assert_eq!(i2c_map.device_map.get(&32), Some(&1));
        assert_eq!(i2c_map.device_map.get(&21), Some(&1));
        assert_eq!(i2c_map.device_map.get(&10), Some(&2));
        assert_eq!(i2c_map.device_map.get(&23), Some(&2));
    }

    #[test]
    fn test_i2c_transfer() {
        let adapter_config = AdapterConfig::new_with(vec![DeviceConfig::new_with(
            AdapterIdentifier::Number(1),
            vec![3],
        )]);
        let mut i2c_map: I2cMap<DummyDevice> = I2cMap::new(&adapter_config).unwrap();

        i2c_map.adapters[0].smbus = false;

        // Read-Write-Read-Write-Read block
        let mut reqs: Vec<I2cReq> = vec![
            I2cReq {
                addr: 0x3,
                flags: I2C_M_RD,
                len: 20,
                buf: vec![0; 20],
            },
            I2cReq {
                addr: 0x3,
                flags: 0,
                len: 10,
                buf: vec![0; 10],
            },
            I2cReq {
                addr: 0x3,
                flags: I2C_M_RD,
                len: 25,
                buf: vec![0; 25],
            },
            I2cReq {
                addr: 0x3,
                flags: 0,
                len: 11,
                buf: vec![0; 11],
            },
            I2cReq {
                addr: 0x3,
                flags: I2C_M_RD,
                len: 30,
                buf: vec![0; 30],
            },
        ];

        for req in &mut reqs {
            if (req.flags & I2C_M_RD) == 0 {
                update_rdwr_buf(&mut req.buf);
            }
        }

        i2c_map.transfer(&mut reqs).unwrap();
        verify_rdwr_data(&reqs);
    }

    #[test]
    fn test_verify_smbus_data() {
        let data = I2cSmbusData { word: 0x050A };

        assert_eq!(data.read_byte(), 0x0A);
        assert_eq!(data.read_word(), 0x050A);
    }

    #[test]
    fn test_smbus_transfer() {
        let adapter_config = AdapterConfig::new_with(vec![DeviceConfig::new_with(
            AdapterIdentifier::Number(1),
            vec![3],
        )]);
        let mut i2c_map: I2cMap<DummyDevice> = I2cMap::new(&adapter_config).unwrap();

        i2c_map.adapters[0].smbus = true;

        // I2C_SMBUS_WRITE (I2C_SMBUS_QUICK) operation
        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: 0,
            len: 0,
            buf: Vec::<u8>::new(),
        }];

        i2c_map.transfer(&mut reqs).unwrap();

        // I2C_SMBUS_READ (I2C_SMBUS_QUICK) operation
        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: I2C_M_RD,
            len: 0,
            buf: vec![0],
        }];

        i2c_map.transfer(&mut reqs).unwrap();

        // I2C_SMBUS_WRITE (I2C_SMBUS_BYTE) operation
        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: 0,
            len: 1,
            buf: vec![0],
        }];

        i2c_map.transfer(&mut reqs).unwrap();

        // I2C_SMBUS_READ (I2C_SMBUS_BYTE) operation
        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: I2C_M_RD,
            len: 1,
            buf: vec![0],
        }];

        i2c_map.transfer(&mut reqs).unwrap();
        assert_eq!(reqs[0].buf[0], 1);

        // I2C_SMBUS_WRITE (I2C_SMBUS_BYTE_DATA) operation
        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: 0,
            len: 2,
            buf: [7, 4].to_vec(),
        }];

        i2c_map.transfer(&mut reqs).unwrap();

        // I2C_SMBUS_READ (I2C_SMBUS_BYTE_DATA) operation
        let mut reqs = vec![
            I2cReq {
                addr: 0x3,
                flags: 0,
                len: 1,
                buf: vec![0],
            },
            I2cReq {
                addr: 0x3,
                flags: I2C_M_RD,
                len: 1,
                buf: vec![0],
            },
        ];
        i2c_map.transfer(&mut reqs).unwrap();
        assert_eq!(reqs[1].buf[0], 1);

        // I2C_SMBUS_WRITE (I2C_SMBUS_WORD_DATA) operation
        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: 0,
            len: 3,
            buf: [7, 4, 3].to_vec(),
        }];

        i2c_map.transfer(&mut reqs).unwrap();

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) operation
        let mut reqs = vec![
            I2cReq {
                addr: 0x3,
                flags: 0,
                len: 1,
                buf: vec![0],
            },
            I2cReq {
                addr: 0x3,
                flags: I2C_M_RD,
                len: 2,
                buf: vec![0; 2],
            },
        ];
        i2c_map.transfer(&mut reqs).unwrap();
        assert_eq!(reqs[1].buf[0], 1);
        assert_eq!(reqs[1].buf[1], 2);
    }

    #[test]
    fn test_transfer_failure() {
        let adapter_config = AdapterConfig::new_with(vec![DeviceConfig::new_with(
            AdapterIdentifier::Number(1),
            vec![3],
        )]);
        let mut i2c_map: I2cMap<DummyDevice> = I2cMap::new(&adapter_config).unwrap();

        i2c_map.adapters[0].smbus = false;

        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            // Will cause failure
            addr: 0x4,
            flags: 0,
            len: 2,
            buf: vec![7, 4],
        }];

        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::ClientAddressInvalid
        );
    }

    #[test]
    fn test_smbus_transfer_failure() {
        let adapter_config = AdapterConfig::new_with(vec![DeviceConfig::new_with(
            AdapterIdentifier::Number(1),
            vec![3],
        )]);
        let mut i2c_map: I2cMap<DummyDevice> = I2cMap::new(&adapter_config).unwrap();
        i2c_map.adapters[0].smbus = true;

        // I2C_SMBUS_READ (Invalid size) failure operation
        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: I2C_M_RD,
            // Will cause failure
            len: 2,
            buf: [34].to_vec(),
        }];
        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::MessageLengthInvalid("read", 2)
        );

        // I2C_SMBUS_WRITE (Invalid size) failure operation
        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: 0,
            // Will cause failure
            len: 4,
            buf: [34].to_vec(),
        }];
        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::MessageLengthInvalid("write", 4)
        );

        // I2C_SMBUS_WRITE (I2C_SMBUS_WORD_DATA) failure operation
        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            // Will cause failure
            flags: I2C_M_RD,
            len: 3,
            buf: [7, 4, 3].to_vec(),
        }];
        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::MessageLengthInvalid("read", 3)
        );

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) failure operation
        let mut reqs: Vec<I2cReq> = vec![
            I2cReq {
                addr: 0x3,
                // Will cause failure
                flags: I2C_M_RD,
                len: 1,
                buf: [34].to_vec(),
            },
            I2cReq {
                addr: 0x3,
                flags: I2C_M_RD,
                len: 2,
                buf: [3, 4].to_vec(),
            },
        ];
        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::SMBusTransferInvalid(2, 1, 2)
        );

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) failure operation
        let mut reqs = vec![
            I2cReq {
                addr: 0x3,
                flags: 0,
                len: 1,
                buf: [34].to_vec(),
            },
            I2cReq {
                addr: 0x3,
                // Will cause failure
                flags: 0,
                len: 2,
                buf: [3, 4].to_vec(),
            },
        ];
        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::SMBusTransferInvalid(2, 1, 2)
        );

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) failure operation
        let mut reqs = vec![
            I2cReq {
                addr: 0x3,
                flags: 0,
                // Will cause failure
                len: 2,
                buf: [3, 4].to_vec(),
            },
            I2cReq {
                addr: 0x3,
                flags: I2C_M_RD,
                len: 2,
                buf: [3, 4].to_vec(),
            },
        ];
        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::SMBusTransferInvalid(2, 2, 2)
        );

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) failure operation
        let mut reqs = vec![
            I2cReq {
                addr: 0x3,
                flags: 0,
                len: 1,
                buf: [34].to_vec(),
            },
            I2cReq {
                addr: 0x3,
                flags: I2C_M_RD,
                // Will cause failure
                len: 3,
                buf: [3, 4, 5].to_vec(),
            },
        ];
        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::SMBusTransferInvalid(2, 1, 3)
        );

        // I2C_SMBUS_READ (Invalid request count) failure operation
        let mut reqs = vec![
            I2cReq {
                addr: 0x3,
                flags: 0,
                len: 1,
                buf: [34].to_vec(),
            },
            I2cReq {
                addr: 0x3,
                flags: I2C_M_RD,
                len: 2,
                buf: [3, 4].to_vec(),
            },
            // Will cause failure
            I2cReq {
                addr: 0,
                flags: 0,
                len: 0,
                buf: [0].to_vec(),
            },
        ];
        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::SMBusTransferInvalid(3, 1, 2)
        );
    }

    #[test]
    fn test_phys_device_failure() {
        // Open failure
        assert_eq!(
            PhysDevice::open(&AdapterIdentifier::Name("555555".to_string())).unwrap_err(),
            Error::AdapterNotFound
        );

        assert_eq!(
            PhysDevice::open(&AdapterIdentifier::Number(55555)).unwrap_err(),
            Error::DeviceOpenFailed(55555)
        );

        assert_eq!(
            PhysDevice::open_with("/dev/i2c-invalid-path", 0).unwrap_err(),
            Error::DeviceOpenFailed(0)
        );

        let file = TempFile::new().unwrap();
        let mut dev = PhysDevice::open_with(file.as_path().to_str().unwrap(), 1).unwrap();

        // Match adapter number
        assert_eq!(dev.adapter_no(), 1);

        // funcs failure
        assert_eq!(
            dev.funcs().unwrap_err(),
            Error::IoctlFailure("funcs", IoError::last())
        );

        // rdwr failure
        let mut reqs = [I2cReq {
            addr: 0x4,
            flags: 0,
            len: 2,
            buf: vec![7, 4],
        }];
        assert_eq!(
            dev.rdwr(&mut reqs).unwrap_err(),
            Error::IoctlFailure("rdwr", IoError::last())
        );

        // rdwr failure - missing buffer
        let mut reqs = [I2cReq {
            addr: 0x4,
            flags: 0,
            len: 0,
            buf: Vec::<u8>::new(),
        }];
        assert_eq!(
            dev.rdwr(&mut reqs).unwrap_err(),
            Error::I2cTransferInvalid(0)
        );

        // smbus failure
        let mut data = SmbusMsg {
            read_write: 0,
            command: 0,
            size: 0,
            data: None,
        };
        assert_eq!(
            dev.smbus(&mut data).unwrap_err(),
            Error::IoctlFailure("smbus", IoError::last())
        );

        // slave failure
        assert_eq!(
            dev.slave(0).unwrap_err(),
            Error::IoctlFailure("slave", IoError::last())
        );
    }
}

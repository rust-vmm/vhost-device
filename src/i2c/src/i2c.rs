// Low level I2C definitions
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use log::info;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

use libc::{c_ulong, ioctl};
use thiserror::Error as ThisError;
use vmm_sys_util::errno::Error as IoError;

use super::AdapterConfig;

// The type of the `req` parameter is different for the `musl` library. This will enable
// successful build for other non-musl libraries.
#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = c_ulong;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, ThisError)]
/// Errors related to low level i2c helpers
pub enum Error {
    #[error("Incorrect message length for {0} operation: {1}")]
    MessageLengthInvalid(&'static str, usize),
    #[error("Invalid SMBUS command: {0}")]
    SMBusCommandInvalid(u32),
    #[error("Invalid SMBus transfer, request-count: {0}, req[0].len: {1}, req[1].len: {2}")]
    SMBusTransferInvalid(usize, u16, u16),
    #[error("Failed to open adapter at /dev/i2c-{0}")]
    DeviceOpenFailed(u32),
    #[error("Ioctl command failed for {0} operation: {1}")]
    IoctlFailure(&'static str, IoError),
    #[error("Invalid Adapter function: {0:x}")]
    AdapterFunctionInvalid(u64),
    #[error("Invalid Client Address")]
    ClientAddressInvalid,
}

/// Linux I2C/SMBUS definitions
/// IOCTL commands

/// NOTE: Slave address is 7 or 10 bits, but 10-bit addresses are NOT supported!
/// (due to code brokenness)
const I2C_SLAVE: IoctlRequest = 0x0703; // Use this slave address
const I2C_FUNCS: IoctlRequest = 0x0705; // Get the adapter functionality mask
const I2C_RDWR: IoctlRequest = 0x0707; // Combined R/W transfer (one STOP only)
const I2C_SMBUS: IoctlRequest = 0x0720; // SMBus transfer

/// Functions
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

/// I2C protocol definitions
pub const I2C_M_RD: u16 = 0x0001; // read data, from slave to master

/// Copied (partially) from Linux's include/uapi/linux/i2c.h
///
/// I2cMsg - an I2C transaction segment beginning with START
///
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
/// Each transaction begins with a START.  That is followed by the slave
/// address, and a bit encoding read versus write.  Then follow all the
/// data bytes, possibly including a byte with SMBus PEC.  The transfer
/// terminates with a NAK, or when all those bytes have been transferred
/// and ACKed.  If this is the last message in a group, it is followed by
/// a STOP.  Otherwise it is followed by the next @I2cMsg transaction
/// segment, beginning with a (repeated) START.

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

/// SMBUS protocol definitions
/// SMBUS read or write markers
const I2C_SMBUS_WRITE: u8 = 0;
const I2C_SMBUS_READ: u8 = 1;

/// SMBus transaction types (size parameter in the above functions)
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

/// This is the structure as used in the I2C_SMBUS ioctl call
#[repr(C)]
pub struct I2cSmbusIoctlData {
    read_write: u8,
    command: u8,
    size: u32,
    data: *mut I2cSmbusData,
}

impl I2cSmbusIoctlData {
    /// Based on Linux's drivers/i2c/i2c-core-smbus.c:i2c_smbus_xfer_emulated().
    ///
    /// These smbus related functions try to reverse what Linux does, only
    /// support basic modes (up to word transfer).
    fn new(reqs: &mut [I2cReq]) -> Result<I2cSmbusIoctlData> {
        let mut data = I2cSmbusData {
            block: [0; I2C_SMBUS_BLOCK_MAX + 2],
        };
        let read_write: u8;
        let size: u32;

        // Write messages have only one request message, while read messages
        // will have two (except for few special cases of I2C_SMBUS_QUICK and
        // I2C_SMBUS_BYTE, where only one request messages is sent).
        match reqs.len() {
            // Write requests (with some exceptions as mentioned above)
            1 => {
                if (reqs[0].flags & I2C_M_RD) != 0 {
                    // Special Read requests, reqs[0].len can be 0 or 1 only.
                    if reqs[0].len > 1 {
                        return Err(Error::MessageLengthInvalid("read", reqs[0].len as usize));
                    }
                    read_write = I2C_SMBUS_READ;
                } else {
                    read_write = I2C_SMBUS_WRITE;
                }

                size = match reqs[0].len {
                    // Special Read requests
                    0 => I2C_SMBUS_QUICK,
                    1 => I2C_SMBUS_BYTE,

                    // Write requests
                    2 => {
                        data.byte = reqs[0].buf[1];
                        I2C_SMBUS_BYTE_DATA
                    }
                    3 => {
                        data.word = reqs[0].buf[1] as u16 | ((reqs[0].buf[2] as u16) << 8);
                        I2C_SMBUS_WORD_DATA
                    }
                    _ => {
                        return Err(Error::MessageLengthInvalid("write", reqs[0].len as usize));
                    }
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
                    return Err(Error::SMBusTransferInvalid(
                        reqs.len(),
                        reqs[0].len,
                        reqs[1].len,
                    ));
                }
                read_write = I2C_SMBUS_READ;

                if reqs[1].len == 1 {
                    size = I2C_SMBUS_BYTE_DATA;
                } else {
                    size = I2C_SMBUS_WORD_DATA;
                }
            }

            _ => {
                return Err(Error::SMBusTransferInvalid(
                    reqs.len(),
                    reqs[0].len,
                    reqs[1].len,
                ));
            }
        }

        Ok(I2cSmbusIoctlData {
            read_write,
            command: reqs[0].buf[0],
            size,
            data: &mut data,
        })
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
    // Open the device specified by the adapter number.
    fn open(adapter_no: u32) -> Result<Self>
    where
        Self: Sized;

    // Corresponds to the I2C_FUNCS ioctl call.
    fn funcs(&mut self, func: u64) -> Result<()>;

    // Corresponds to the I2C_RDWR ioctl call.
    fn rdwr(&self, data: &I2cRdwrIoctlData) -> Result<()>;

    // Corresponds to the I2C_SMBUS ioctl call.
    fn smbus(&self, data: &I2cSmbusIoctlData) -> Result<()>;

    // Corresponds to the I2C_SLAVE ioctl call.
    fn slave(&self, addr: u64) -> Result<()>;

    // Returns the adapter number corresponding to this device.
    fn adapter_no(&self) -> u32;
}

/// A physical I2C device. This structure can only be initialized on hosts
/// where `/dev/i2c-XX` is available.
pub struct PhysDevice {
    file: File,
    adapter_no: u32,
}

impl I2cDevice for PhysDevice {
    fn open(adapter_no: u32) -> Result<Self> {
        let device_path = format!("/dev/i2c-{}", adapter_no);
        Ok(PhysDevice {
            file: OpenOptions::new()
                .read(true)
                .write(true)
                .open(device_path)
                .map_err(|_| Error::DeviceOpenFailed(adapter_no))?,
            adapter_no,
        })
    }

    fn funcs(&mut self, func: u64) -> Result<()> {
        let ret = unsafe { ioctl(self.file.as_raw_fd(), I2C_FUNCS, &func) };

        if ret == -1 {
            Err(Error::IoctlFailure("funcs", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn rdwr(&self, data: &I2cRdwrIoctlData) -> Result<()> {
        let ret = unsafe { ioctl(self.file.as_raw_fd(), I2C_RDWR, data) };

        if ret == -1 {
            Err(Error::IoctlFailure("rdwr", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn smbus(&self, data: &I2cSmbusIoctlData) -> Result<()> {
        let ret = unsafe { ioctl(self.file.as_raw_fd(), I2C_SMBUS, data) };

        if ret == -1 {
            Err(Error::IoctlFailure("smbus", IoError::last()))
        } else {
            Ok(())
        }
    }

    fn slave(&self, addr: u64) -> Result<()> {
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

pub struct I2cAdapter<D: I2cDevice> {
    device: D,
    adapter_no: u32,
    smbus: bool,
}

impl<D: I2cDevice> I2cAdapter<D> {
    // Creates a new adapter corresponding to `device`.
    fn new(mut device: D) -> Result<I2cAdapter<D>> {
        let func: u64 = I2C_FUNC_SMBUS_ALL;

        device.funcs(func)?;

        let smbus;
        if (func & I2C_FUNC_I2C) != 0 {
            smbus = false;
        } else if (func & I2C_FUNC_SMBUS_ALL) != 0 {
            smbus = true;
        } else {
            return Err(Error::AdapterFunctionInvalid(func));
        }

        Ok(I2cAdapter {
            adapter_no: device.adapter_no(),
            device,
            smbus,
        })
    }

    /// Perform I2C_RDWR transfer
    fn i2c_transfer(&self, reqs: &mut [I2cReq]) -> Result<()> {
        let mut msgs: Vec<I2cMsg> = Vec::with_capacity(reqs.len());
        let len = reqs.len();

        for req in reqs {
            msgs.push(I2cMsg {
                addr: req.addr,
                flags: req.flags,
                len: req.len,
                buf: req.buf.as_mut_ptr(),
            });
        }

        let data = I2cRdwrIoctlData {
            msgs: msgs.as_mut_ptr(),
            nmsgs: len as u32,
        };

        self.device.rdwr(&data)
    }

    /// Perform I2C_SMBUS transfer
    fn smbus_transfer(&self, reqs: &mut [I2cReq]) -> Result<()> {
        let smbus_data = I2cSmbusIoctlData::new(reqs)?;

        self.device.smbus(&smbus_data)?;

        if smbus_data.read_write == I2C_SMBUS_READ {
            unsafe {
                match smbus_data.size {
                    I2C_SMBUS_BYTE => reqs[0].buf[0] = (*smbus_data.data).byte,
                    I2C_SMBUS_BYTE_DATA => reqs[1].buf[0] = (*smbus_data.data).byte,
                    I2C_SMBUS_WORD_DATA => {
                        reqs[1].buf[0] = ((*smbus_data.data).word & 0xff) as u8;
                        reqs[1].buf[1] = ((*smbus_data.data).word >> 8) as u8;
                    }

                    _ => {
                        return Err(Error::SMBusCommandInvalid(smbus_data.size));
                    }
                }
            }
        }
        Ok(())
    }

    fn adapter_no(&self) -> u32 {
        self.adapter_no
    }

    fn is_smbus(&self) -> bool {
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
pub(crate) const MAX_I2C_VDEV: usize = 1 << 7;
const I2C_INVALID_ADAPTER: u32 = 0xFFFFFFFF;

pub struct I2cMap<D: I2cDevice> {
    adapters: Vec<I2cAdapter<D>>,
    device_map: [u32; MAX_I2C_VDEV],
}

impl<D: I2cDevice> I2cMap<D> {
    pub(crate) fn new(device_config: &AdapterConfig) -> Result<Self>
    where
        Self: Sized,
    {
        let mut device_map: [u32; MAX_I2C_VDEV] = [I2C_INVALID_ADAPTER; MAX_I2C_VDEV];
        let mut adapters: Vec<I2cAdapter<D>> = Vec::new();

        for (i, device_cfg) in device_config.inner.iter().enumerate() {
            let device = D::open(device_cfg.adapter_no)?;
            let adapter = I2cAdapter::new(device)?;

            // Check that all addresses corresponding to the adapter are valid.
            for addr in &device_cfg.addr {
                adapter.set_device_addr(*addr as usize)?;
                device_map[*addr as usize] = i as u32;
            }

            info!(
                "Added I2C master with bus id: {:x} for devices",
                adapter.adapter_no(),
            );

            adapters.push(adapter);
        }

        Ok(I2cMap {
            adapters,
            device_map,
        })
    }

    pub fn transfer(&self, reqs: &mut [I2cReq]) -> Result<()> {
        let device = reqs[0].addr as usize;

        // identify the device in the device_map
        let index = self.device_map[device];

        // This can happen a lot while scanning the bus, don't print any errors.
        if index == I2C_INVALID_ADAPTER {
            return Err(Error::ClientAddressInvalid);
        }

        // get the corresponding adapter based on the device config.
        let adapter = &self.adapters[index as usize];

        // Set device's address
        adapter.set_device_addr(device)?;
        adapter.transfer(reqs)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[derive(Debug)]
    pub struct DummyDevice {
        funcs_result: Result<()>,
        rdwr_result: Result<()>,
        smbus_result: Result<()>,
        slave_result: Result<()>,
        adapter_no: u32,
    }

    impl I2cDevice for DummyDevice {
        fn open(adapter_no: u32) -> Result<Self>
        where
            Self: Sized,
        {
            Ok(DummyDevice {
                adapter_no,
                funcs_result: Ok(()),
                rdwr_result: Ok(()),
                smbus_result: Ok(()),
                slave_result: Ok(()),
            })
        }

        fn funcs(&mut self, _func: u64) -> Result<()> {
            self.funcs_result
        }

        fn rdwr(&self, _data: &I2cRdwrIoctlData) -> Result<()> {
            self.rdwr_result
        }

        fn smbus(&self, _data: &I2cSmbusIoctlData) -> Result<()> {
            self.smbus_result
        }

        fn slave(&self, _addr: u64) -> Result<()> {
            self.slave_result
        }

        fn adapter_no(&self) -> u32 {
            self.adapter_no
        }
    }

    #[test]
    fn test_funcs() {
        let i2c_device = DummyDevice {
            funcs_result: I2C_FUNC_SMBUS_ALL as i32,
            ..Default::default()
        };
        let adapter = I2cAdapter::new(i2c_device).unwrap();
        assert_eq!(adapter.smbus, true);

        let i2c_device = DummyDevice {
            funcs_result: I2C_FUNC_I2C as i32,
            ..Default::default()
        };
        let adapter = I2cAdapter::new(i2c_device).unwrap();
        assert_eq!(adapter.smbus, false);
    }

    #[test]
    fn test_i2c_map() {
        let adapter_config = AdapterConfig::try_from("1:4,2:32:21,5:10:23").unwrap();
        let i2c_map: I2cMap<DummyDevice> = I2cMap::new(&adapter_config).unwrap();

        assert_eq!(i2c_map.adapters.len(), 3);
        assert_eq!(i2c_map.adapters[0].adapter_no(), 1);
        assert_eq!(i2c_map.adapters[1].adapter_no(), 2);
        assert_eq!(i2c_map.adapters[2].adapter_no(), 5);

        assert_eq!(i2c_map.device_map[4], 0);
        assert_eq!(i2c_map.device_map[32], 1);
        assert_eq!(i2c_map.device_map[21], 1);
        assert_eq!(i2c_map.device_map[10], 2);
        assert_eq!(i2c_map.device_map[23], 2);
    }

    #[test]
    fn test_i2c_transfer() {
        let adapter_config = AdapterConfig::try_from("1:3").unwrap();
        let mut i2c_map: I2cMap<DummyDevice> = I2cMap::new(&adapter_config).unwrap();

        i2c_map.adapters[0].smbus = false;

        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: 0,
            len: 2,
            buf: vec![7, 4],
        }];

        i2c_map.transfer(&mut *reqs).unwrap();
    }

    #[test]
    fn test_smbus_transfer() {
        let adapter_config = AdapterConfig::try_from("1:3").unwrap();
        let mut i2c_map: I2cMap<DummyDevice> = I2cMap::new(&adapter_config).unwrap();

        i2c_map.adapters[0].smbus = true;

        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: 0,
            len: 2,
            buf: [7, 4].to_vec(),
        }];

        // I2C_SMBUS_WRITE (I2C_SMBUS_BYTE_DATA) operation
        i2c_map.transfer(&mut reqs).unwrap();

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) operation
        let mut reqs = vec![
            I2cReq {
                addr: 0x3,
                flags: 0,
                len: 1,
                buf: [34].to_vec(),
            },
            I2cReq {
                addr: 0x3,
                flags: 1,
                len: 2,
                buf: [3, 4].to_vec(),
            },
        ];
        i2c_map.transfer(&mut reqs).unwrap();
    }

    #[test]
    fn test_smbus_transfer_failure() {
        let adapter_config = AdapterConfig::try_from("1:3").unwrap();
        let mut i2c_map: I2cMap<DummyDevice> = I2cMap::new(&adapter_config).unwrap();
        i2c_map.adapters[0].smbus = true;

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) failure operation
        let mut reqs: Vec<I2cReq> = vec![
            I2cReq {
                addr: 0x3,
                // Will cause failure
                flags: 0x1,
                len: 1,
                buf: [34].to_vec(),
            },
            I2cReq {
                addr: 0x3,
                flags: 1,
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
                flags: 1,
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
                flags: 1,
                // Will cause failure
                len: 3,
                buf: [3, 4, 5].to_vec(),
            },
        ];
        assert_eq!(
            i2c_map.transfer(&mut reqs).unwrap_err(),
            Error::SMBusTransferInvalid(2, 1, 3)
        );
    }
}

// Low level I2C definitions
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use libc::{c_ulong, ioctl, EADDRINUSE, EADDRNOTAVAIL, EINVAL};
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use vmm_sys_util::errno::{errno_result, Error, Result};

// The type of the `req` parameter is different for the `musl` library. This will enable
// successful build for other non-musl libraries.
#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = c_ulong;

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
                        println!(
                            "Incorrect message length for read operation: {}",
                            reqs[0].len
                        );
                        return Err(Error::new(EINVAL));
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
                        println!(
                            "Message length not supported for write operation: {}",
                            reqs[0].len
                        );
                        return Err(Error::new(EINVAL));
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
                    println!(
                        "Expecting a valid read smbus transfer: {:?}",
                        (reqs.len(), reqs[0].len, reqs[1].len)
                    );
                    return Err(Error::new(EINVAL));
                }
                read_write = I2C_SMBUS_READ;

                if reqs[1].len == 1 {
                    size = I2C_SMBUS_BYTE_DATA;
                } else {
                    size = I2C_SMBUS_WORD_DATA;
                }
            }

            _ => {
                println!("Invalid number of messages for smbus xfer: {}", reqs.len());
                return Err(Error::new(EINVAL));
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

/// I2C adapter and helpers
pub trait I2cAdapterTrait: Send + Sync + 'static {
    fn new(adapter_no: u32) -> Result<Self>
    where
        Self: Sized;

    fn adapter_no(&self) -> u32;
    fn is_smbus(&self) -> bool;

    /// Sets device's address for an I2C adapter.
    fn set_device_addr(&self, addr: usize) -> Result<()>;

    /// Gets adapter's functionality
    //TODO: this needs to be called as part of new because otherwise is_smbus is invalid.
    fn get_func(&mut self) -> Result<()>;

    /// Transfer data
    fn do_i2c_transfer(&self, data: &I2cRdwrIoctlData, addr: u16) -> Result<()>;

    fn do_smbus_transfer(&self, data: &I2cSmbusIoctlData, addr: u16) -> Result<()>;

    /// Perform I2C_RDWR transfer
    fn i2c_transfer(&self, reqs: &mut [I2cReq]) -> Result<()> {
        let mut msgs: Vec<I2cMsg> = Vec::with_capacity(reqs.len());
        let len = reqs.len();
        let addr = reqs[0].addr;

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

        self.do_i2c_transfer(&data, addr)
    }

    /// Perform I2C_SMBUS transfer
    fn smbus_transfer(&self, reqs: &mut [I2cReq]) -> Result<()> {
        let smbus_data = I2cSmbusIoctlData::new(reqs)?;

        self.do_smbus_transfer(&smbus_data, reqs[0].addr)?;

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
                        println!("Invalid SMBUS command: {}", smbus_data.size);
                        return Err(Error::new(EINVAL));
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct I2cAdapter {
    fd: File,
    adapter_no: u32,
    smbus: bool,
}

impl I2cAdapterTrait for I2cAdapter {
    fn new(adapter_no: u32) -> Result<I2cAdapter> {
        let i2cdev = format!("/dev/i2c-{}", adapter_no);

        Ok(I2cAdapter {
            adapter_no,
            smbus: false,
            fd: OpenOptions::new().read(true).write(true).open(i2cdev)?,
        })
    }

    fn adapter_no(&self) -> u32 {
        self.adapter_no
    }

    fn is_smbus(&self) -> bool {
        self.smbus
    }

    /// Sets device's address for an I2C adapter.
    fn set_device_addr(&self, addr: usize) -> Result<()> {
        let ret = unsafe { ioctl(self.fd.as_raw_fd(), I2C_SLAVE, addr as c_ulong) };

        if ret == -1 {
            println!("Failed to set device addr to {:x}", addr);
            errno_result()
        } else {
            Ok(())
        }
    }

    /// Gets adapter's functionality
    fn get_func(&mut self) -> Result<()> {
        let func: u64 = I2C_FUNC_SMBUS_ALL;

        let ret = unsafe { ioctl(self.fd.as_raw_fd(), I2C_FUNCS, &func) };

        if ret == -1 {
            println!("Failed to get I2C function");
            return errno_result();
        }

        if (func & I2C_FUNC_I2C) != 0 {
            self.smbus = false;
        } else if (func & I2C_FUNC_SMBUS_ALL) != 0 {
            self.smbus = true;
        } else {
            println!("Invalid functionality {:x}", func);
            return Err(Error::new(EINVAL));
        }

        Ok(())
    }

    /// Transfer data
    fn do_i2c_transfer(&self, data: &I2cRdwrIoctlData, addr: u16) -> Result<()> {
        let ret = unsafe { ioctl(self.fd.as_raw_fd(), I2C_RDWR, data) };

        if ret == -1 {
            println!("Failed to transfer i2c data to device addr to {:x}", addr);
            errno_result()
        } else {
            Ok(())
        }
    }

    fn do_smbus_transfer(&self, data: &I2cSmbusIoctlData, addr: u16) -> Result<()> {
        let ret = unsafe { ioctl(self.fd.as_raw_fd(), I2C_SMBUS, data) };

        if ret == -1 {
            println!("Failed to transfer smbus data to device addr to {:x}", addr);
            return errno_result();
        }

        Ok(())
    }
}

/// I2C map and helpers
const MAX_I2C_VDEV: usize = 1 << 7;
const I2C_INVALID_ADAPTER: u32 = 0xFFFFFFFF;

pub struct I2cMap<A: I2cAdapterTrait> {
    adapters: Vec<A>,
    device_map: [u32; MAX_I2C_VDEV],
}

impl<A: I2cAdapterTrait> I2cMap<A> {
    pub fn new(list: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let mut device_map: [u32; MAX_I2C_VDEV] = [I2C_INVALID_ADAPTER; MAX_I2C_VDEV];
        let mut adapters: Vec<A> = Vec::new();
        let busses: Vec<&str> = list.split(',').collect();

        for (i, businfo) in busses.iter().enumerate() {
            let list: Vec<&str> = businfo.split(':').collect();
            let adapter_no = list[0].parse::<u32>().map_err(|_| Error::new(EINVAL))?;
            let mut adapter = A::new(adapter_no)?;
            let devices = &list[1..];

            adapter.get_func()?;

            for device in devices {
                let device = device.parse::<usize>().map_err(|_| Error::new(EINVAL))?;

                if device > MAX_I2C_VDEV {
                    println!("Invalid device address {}", device);
                    return Err(Error::new(EADDRNOTAVAIL));
                }

                if device_map[device] != I2C_INVALID_ADAPTER {
                    println!(
                        "Client address {} is already used by {}",
                        device,
                        adapters[device_map[device] as usize].adapter_no()
                    );
                    return Err(Error::new(EADDRINUSE));
                }

                adapter.set_device_addr(device)?;
                device_map[device] = i as u32;
            }

            println!(
                "Added I2C master with bus id: {:x} for devices: {:?}",
                adapter.adapter_no(),
                devices
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
        let index = self.device_map[device];

        // This can happen a lot while scanning the bus, don't print any errors.
        if index == I2C_INVALID_ADAPTER {
            return Err(Error::new(EINVAL));
        }

        let adapter = &self.adapters[index as usize];

        // Set device's address
        adapter.set_device_addr(device)?;

        if adapter.is_smbus() {
            adapter.smbus_transfer(reqs)
        } else {
            adapter.i2c_transfer(reqs)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub struct I2cMockAdapter {
        bus: u32,
        smbus: bool,
        result: Result<()>,
    }

    impl I2cAdapterTrait for I2cMockAdapter {
        fn new(bus: u32) -> Result<I2cMockAdapter> {
            Ok(I2cMockAdapter {
                bus,
                smbus: false,
                result: Ok(()),
            })
        }

        fn adapter_no(&self) -> u32 {
            self.bus
        }

        fn is_smbus(&self) -> bool {
            self.smbus
        }

        fn set_device_addr(&self, _addr: usize) -> Result<()> {
            Ok(())
        }

        fn get_func(&mut self) -> Result<()> {
            Ok(())
        }

        fn do_i2c_transfer(&self, _data: &I2cRdwrIoctlData, _addr: u16) -> Result<()> {
            println!("In i2c-transfer");
            self.result
        }

        fn do_smbus_transfer(&self, _data: &I2cSmbusIoctlData, _addr: u16) -> Result<()> {
            println!("In smbus-transfer");
            self.result
        }
    }

    fn assert_results(
        i2c_map: &mut I2cMap<I2cMockAdapter>,
        reqs: &mut Vec<I2cReq>,
        before: bool,
        after: bool,
    ) {
        i2c_map.adapters[0].result = Ok(());
        assert_eq!(i2c_map.transfer(reqs).is_err(), before);
        i2c_map.adapters[0].result = Err(Error::new(EINVAL));
        assert_eq!(i2c_map.transfer(reqs).is_err(), after);

        reqs.clear();
    }

    #[test]
    fn test_i2c_map_duplicate_device4() {
        assert!(I2cMap::<I2cMockAdapter>::new("1:4,2:32:21,5:4:23").is_err());
    }

    #[test]
    fn test_i2c_map() {
        let i2c_map: I2cMap<I2cMockAdapter> = I2cMap::new("1:4,2:32:21,5:10:23").unwrap();

        assert_eq!(i2c_map.adapters.len(), 3);
        assert_eq!(i2c_map.adapters[0].bus, 1);
        assert_eq!(i2c_map.adapters[1].bus, 2);
        assert_eq!(i2c_map.adapters[2].bus, 5);

        assert_eq!(i2c_map.device_map[4], 0);
        assert_eq!(i2c_map.device_map[32], 1);
        assert_eq!(i2c_map.device_map[21], 1);
        assert_eq!(i2c_map.device_map[10], 2);
        assert_eq!(i2c_map.device_map[23], 2);
    }

    #[test]
    fn test_i2c_transfer() {
        let mut i2c_map: I2cMap<I2cMockAdapter> = I2cMap::new("1:3").unwrap();
        i2c_map.adapters[0].smbus = false;

        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: 0,
            len: 2,
            buf: [7, 4].to_vec(),
        }];

        assert_results(&mut i2c_map, &mut reqs, false, true);
    }

    #[test]
    fn test_smbus_transfer() {
        let mut i2c_map: I2cMap<I2cMockAdapter> = I2cMap::new("1:3").unwrap();
        i2c_map.adapters[0].smbus = true;

        let mut reqs: Vec<I2cReq> = vec![I2cReq {
            addr: 0x3,
            flags: 0,
            len: 2,
            buf: [7, 4].to_vec(),
        }];

        // I2C_SMBUS_WRITE (I2C_SMBUS_BYTE_DATA) operation
        assert_results(&mut i2c_map, &mut reqs, false, true);

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) operation
        reqs.push(I2cReq {
            addr: 0x3,
            flags: 0,
            len: 1,
            buf: [34].to_vec(),
        });
        reqs.push(I2cReq {
            addr: 0x3,
            flags: 1,
            len: 2,
            buf: [3, 4].to_vec(),
        });

        assert_results(&mut i2c_map, &mut reqs, false, true);
    }

    #[test]
    fn test_smbus_transfer_failure() {
        let mut i2c_map: I2cMap<I2cMockAdapter> = I2cMap::new("1:3").unwrap();
        i2c_map.adapters[0].smbus = true;

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

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) failure operation
        assert_results(&mut i2c_map, &mut reqs, true, true);

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) failure operation
        reqs.push(I2cReq {
            addr: 0x3,
            flags: 0,
            len: 1,
            buf: [34].to_vec(),
        });
        reqs.push(I2cReq {
            addr: 0x3,
            // Will cause failure
            flags: 0,
            len: 2,
            buf: [3, 4].to_vec(),
        });

        assert_results(&mut i2c_map, &mut reqs, true, true);

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) failure operation
        reqs.push(I2cReq {
            addr: 0x3,
            flags: 0,
            // Will cause failure
            len: 2,
            buf: [3, 4].to_vec(),
        });
        reqs.push(I2cReq {
            addr: 0x3,
            flags: 1,
            len: 2,
            buf: [3, 4].to_vec(),
        });

        assert_results(&mut i2c_map, &mut reqs, true, true);

        // I2C_SMBUS_READ (I2C_SMBUS_WORD_DATA) failure operation
        reqs.push(I2cReq {
            addr: 0x3,
            flags: 0,
            len: 1,
            buf: [34].to_vec(),
        });
        reqs.push(I2cReq {
            addr: 0x3,
            flags: 1,
            // Will cause failure
            len: 3,
            buf: [3, 4, 5].to_vec(),
        });

        assert_results(&mut i2c_map, &mut reqs, true, true);
    }
}

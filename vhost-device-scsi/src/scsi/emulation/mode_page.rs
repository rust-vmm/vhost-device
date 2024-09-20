// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::io::{self, Write};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ModePage {
    Caching,
}

impl ModePage {
    pub(crate) const ALL_ZERO: &'static [Self] = &[Self::Caching];

    pub(crate) const fn page_code(self) -> (u8, u8) {
        match self {
            Self::Caching => (0x8, 0),
        }
    }

    pub(crate) const fn page_length(self) -> u8 {
        match self {
            Self::Caching => 0x12,
        }
    }

    pub(crate) fn write(self, data_in: &mut impl Write) -> io::Result<()> {
        assert_eq!(self.page_code().1, 0, "Subpages aren't supported yet.");

        data_in.write_all(&[
            self.page_code().0, // top 2 bits: no subpage, saving not supported
            self.page_length(), // page length
        ])?;

        match self {
            Self::Caching => {
                data_in.write_all(&[
                    // Writeback Cache Enable, lots of bits zero
                    // n.b. kernel logs will show WCE off; it always says
                    // that for read-only devices, which we are rn
                    0b0000_0100,
                ])?;
                // various cache fine-tuning stuff we can't really control
                data_in.write_all(&[0; 0x11])?;
            }
        }

        Ok(())
    }
}

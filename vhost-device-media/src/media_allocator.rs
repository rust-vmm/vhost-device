// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    cmp,
    collections::{BTreeSet, HashMap},
    ops::Bound,
};

pub(crate) type Result<T> = std::result::Result<T, i32>;

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    pub const fn from_range(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Returns an empty range.
    pub const fn empty() -> Self {
        AddressRange { start: 1, end: 0 }
    }

    /// Returns `true` if this range is empty (contains no addresses).
    pub fn is_empty(&self) -> bool {
        self.end < self.start
    }

    pub fn non_overlapping_ranges(&self, other: AddressRange) -> (AddressRange, AddressRange) {
        let before = if self.start >= other.start {
            Self::empty()
        } else {
            let start = cmp::min(self.start, other.start);

            // We know that self.start != other.start, so the maximum of the two cannot be
            // 0, so it is safe to subtract 1.
            let end = cmp::max(self.start, other.start) - 1;

            // For non-overlapping ranges, don't allow end to extend past self.end.
            let end = cmp::min(end, self.end);

            AddressRange { start, end }
        };

        let after = if self.end <= other.end {
            Self::empty()
        } else {
            // We know that self.end != other.end, so the minimum of the two cannot be
            // `u64::MAX`, so it is safe to add 1.
            let start = cmp::min(self.end, other.end) + 1;

            // For non-overlapping ranges, don't allow start to extend before self.start.
            let start = cmp::max(start, self.start);

            let end = cmp::max(self.end, other.end);

            AddressRange { start, end }
        };

        (before, after)
    }

    pub fn overlaps(&self, other: AddressRange) -> bool {
        !self.intersect(other).is_empty()
    }

    pub fn intersect(&self, other: AddressRange) -> AddressRange {
        let start = cmp::max(self.start, other.start);
        let end = cmp::min(self.end, other.end);
        AddressRange { start, end }
    }

    pub fn len(&self) -> Option<u64> {
        // Treat any range we consider "empty" (end < start) as having 0 length.
        if self.is_empty() {
            Some(0)
        } else {
            (self.end - self.start).checked_add(1)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MediaAllocator {
    pools: Vec<AddressRange>,
    min_align: u64,
    /// The region that is allocated.
    allocs: HashMap<u64, AddressRange>,
    /// The region that is not allocated yet.
    regions: BTreeSet<AddressRange>,
}

impl MediaAllocator {
    pub fn new(pool: AddressRange, min_align: Option<u64>) -> Result<MediaAllocator> {
        Self::new_from_list(vec![pool], min_align)
    }

    pub fn new_from_list<T>(pools: T, min_align: Option<u64>) -> Result<MediaAllocator>
    where
        T: IntoIterator<Item = AddressRange>,
    {
        let pools: Vec<AddressRange> = pools.into_iter().filter(|p| !p.is_empty()).collect();

        let min_align = min_align.unwrap_or(4);
        if !min_align.is_power_of_two() || min_align == 0 {
            return Err(libc::EBADR);
        }

        let mut regions = BTreeSet::new();
        for r in pools.iter() {
            regions.insert(r.clone());
        }
        Ok(MediaAllocator {
            pools,
            min_align,
            allocs: HashMap::new(),
            regions,
        })
    }

    fn internal_allocate_from_slot(
        &mut self,
        slot: AddressRange,
        range: AddressRange,
        id: u64,
    ) -> Result<u64> {
        let slot_was_present = self.regions.remove(&slot);
        assert!(slot_was_present);

        let (before, after) = slot.non_overlapping_ranges(range);

        if !before.is_empty() {
            self.regions.insert(before);
        }
        if !after.is_empty() {
            self.regions.insert(after);
        }

        self.allocs.insert(id, range);
        Ok(range.start)
    }

    pub fn allocate(&mut self, size: u64, id: u64) -> Result<u64> {
        if self.allocs.contains_key(&id) {
            return Err(libc::EADDRINUSE);
        }
        if size == 0 {
            return Err(libc::EINVAL);
        }
        // finds first region matching alignment and size.
        let region = self
            .regions
            .iter()
            .find(|range| {
                match range.start % self.min_align {
                    0 => range.start.checked_add(size - 1),
                    r => range.start.checked_add(size - 1 + self.min_align - r),
                }
                .map_or(false, |end| end <= range.end)
            })
            .cloned();

        match region {
            Some(slot) => {
                let start = match slot.start % self.min_align {
                    0 => slot.start,
                    r => slot.start + self.min_align - r,
                };
                let end = start + size - 1;
                let range = AddressRange { start, end };

                self.internal_allocate_from_slot(slot, range, id)
            }
            None => Err(libc::EFAULT),
        }
    }

    fn insert_at(&mut self, mut slot: AddressRange) -> Result<()> {
        if slot.is_empty() {
            return Err(libc::EINVAL);
        }

        // Find the region with the highest starting address that is at most
        // |slot.start|. Check if it overlaps with |slot|, or if it is adjacent to
        // (and thus can be coalesced with) |slot|.
        let mut smaller_merge = None;
        if let Some(smaller) = self
            .regions
            .range((Bound::Unbounded, Bound::Included(slot)))
            .max()
        {
            // If there is overflow, then |smaller| covers up through u64::MAX
            let next_addr = smaller.end.checked_add(1).ok_or(libc::EBADR)?;
            match next_addr.cmp(&slot.start) {
                cmp::Ordering::Less => (),
                cmp::Ordering::Equal => smaller_merge = Some(*smaller),
                cmp::Ordering::Greater => return Err(libc::EBADR),
            }
        }

        let mut larger_merge = None;
        if let Some(larger) = self
            .regions
            .range((Bound::Excluded(slot), Bound::Unbounded))
            .min()
        {
            // If there is underflow, then |larger| covers down through 0
            let prev_addr = larger.start.checked_sub(1).ok_or(libc::EBADR)?;
            match slot.end.cmp(&prev_addr) {
                cmp::Ordering::Less => (),
                cmp::Ordering::Equal => larger_merge = Some(*larger),
                cmp::Ordering::Greater => return Err(libc::EBADR),
            }
        }

        if let Some(smaller) = smaller_merge {
            self.regions.remove(&smaller);
            slot.start = smaller.start;
        }
        if let Some(larger) = larger_merge {
            self.regions.remove(&larger);
            slot.end = larger.end;
        }
        self.regions.insert(slot);

        Ok(())
    }

    pub fn release(&mut self, id: u64) -> Result<AddressRange> {
        if let Some(range) = self.allocs.remove(&id) {
            self.insert_at(range)?;
            Ok(range)
        } else {
            Err(libc::EINVAL)
        }
    }

    pub fn release_containing(&mut self, value: u64) -> Result<AddressRange> {
        if let Some(id) = self.find_overlapping(AddressRange {
            start: value,
            end: value,
        }) {
            self.release(id)
        } else {
            Err(libc::EFAULT)
        }
    }

    fn find_overlapping(&self, range: AddressRange) -> Option<u64> {
        if range.is_empty() {
            return None;
        }

        self.allocs
            .iter()
            .find(|(_, &alloc_range)| alloc_range.overlaps(range))
            .map(|(&alloc, _)| alloc)
    }
}

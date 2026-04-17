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

#[cfg(test)]
mod tests {
    use rstest::*;

    use super::*;

    #[rstest]
    #[case(0, 1023, None, 4)]
    #[case(0, 2047, Some(8), 8)]
    #[case(100, 999, Some(16), 16)]
    #[case(0, 4095, Some(4096), 4096)]
    fn test_allocator_new(
        #[case] start: u64,
        #[case] end: u64,
        #[case] min_align: Option<u64>,
        #[case] expected_align: u64,
    ) {
        let pool = AddressRange::from_range(start, end);
        let allocator = MediaAllocator::new(pool, min_align).unwrap();
        assert_eq!(allocator.pools, vec![pool]);
        assert_eq!(allocator.min_align, expected_align);
        assert_eq!(allocator.allocs, HashMap::new());
        let mut regions = BTreeSet::new();
        regions.insert(pool);
        assert_eq!(allocator.regions, regions);
    }

    #[rstest]
    #[case(
        256,
        1,
        0,
        AddressRange::from_range(0, 255),
        AddressRange::from_range(256, 1023)
    )]
    #[case(
        128,
        2,
        0,
        AddressRange::from_range(0, 127),
        AddressRange::from_range(128, 1023)
    )]
    #[case(
        512,
        3,
        0,
        AddressRange::from_range(0, 511),
        AddressRange::from_range(512, 1023)
    )]
    #[case(
        64,
        4,
        0,
        AddressRange::from_range(0, 63),
        AddressRange::from_range(64, 1023)
    )]
    fn test_allocator_allocate_and_release(
        #[case] size: u64,
        #[case] id: u64,
        #[case] expected_offset: u64,
        #[case] expected_alloc_range: AddressRange,
        #[case] expected_free_range: AddressRange,
    ) {
        let pool = AddressRange::from_range(0, 1023);
        let mut allocator = MediaAllocator::new(pool, Some(4)).unwrap();

        // Allocate a region
        let offset = allocator.allocate(size, id).unwrap();
        assert_eq!(offset, expected_offset);
        assert_eq!(allocator.allocs.get(&id), Some(&expected_alloc_range));
        assert_eq!(allocator.regions.iter().next(), Some(&expected_free_range));

        // Release the region
        let released_range = allocator.release(id).unwrap();
        assert_eq!(released_range, expected_alloc_range);
        assert!(allocator.allocs.is_empty());
        assert_eq!(allocator.regions.iter().next(), Some(&pool));
    }

    #[rstest]
    #[case(2048, 1, libc::EFAULT)]
    #[case(4096, 2, libc::EFAULT)]
    #[case(1025, 3, libc::EFAULT)] // One byte larger than the pool
    fn test_allocator_allocate_too_large(
        #[case] size: u64,
        #[case] id: u64,
        #[case] expected_error: i32,
    ) {
        let pool = AddressRange::from_range(0, 1023);
        let mut allocator = MediaAllocator::new(pool, Some(4)).unwrap();
        assert_eq!(allocator.allocate(size, id), Err(expected_error));
    }

    #[rstest]
    #[case(128, 1, 64, 2)]
    #[case(256, 5, 128, 6)]
    #[case(512, 10, 256, 11)]
    fn test_allocator_duplicate_id(
        #[case] first_size: u64,
        #[case] id: u64,
        #[case] second_size: u64,
        #[case] _second_id: u64,
    ) {
        let pool = AddressRange::from_range(0, 1023);
        let mut allocator = MediaAllocator::new(pool, Some(4)).unwrap();

        // Allocate with an ID
        allocator.allocate(first_size, id).unwrap();
        // Try to allocate again with the same ID
        assert_eq!(allocator.allocate(second_size, id), Err(libc::EADDRINUSE));
    }

    #[test]
    fn test_allocator_release_nonexistent() {
        let pool = AddressRange::from_range(0, 1023);
        let mut allocator = MediaAllocator::new(pool, Some(4)).unwrap();
        assert_eq!(allocator.release(99), Err(libc::EINVAL));
    }

    #[test]
    fn test_address_range_empty_and_is_empty() {
        let empty = AddressRange::empty();
        assert!(empty.is_empty());

        let non_empty = AddressRange::from_range(0, 0);
        assert!(!non_empty.is_empty());

        let also_empty = AddressRange::from_range(5, 3);
        assert!(also_empty.is_empty());
    }

    #[test]
    fn test_address_range_len() {
        assert_eq!(AddressRange::empty().len(), Some(0));
        assert_eq!(AddressRange::from_range(0, 0).len(), Some(1));
        assert_eq!(AddressRange::from_range(0, 9).len(), Some(10));
        assert_eq!(AddressRange::from_range(100, 199).len(), Some(100));
        assert_eq!(AddressRange::from_range(0, u64::MAX).len(), None);
    }

    #[test]
    fn test_address_range_intersect() {
        let a = AddressRange::from_range(0, 100);
        let b = AddressRange::from_range(50, 200);
        let c = AddressRange::from_range(101, 200);

        assert_eq!(a.intersect(b), AddressRange::from_range(50, 100));
        assert!(a.overlaps(b));

        assert!(a.intersect(c).is_empty());
        assert!(!a.overlaps(c));

        let d = AddressRange::from_range(0, 100);
        assert_eq!(a.intersect(d), a);
    }

    #[test]
    fn test_address_range_non_overlapping_ranges() {
        let a = AddressRange::from_range(10, 90);
        let b = AddressRange::from_range(30, 60);
        let (before, after) = a.non_overlapping_ranges(b);
        assert_eq!(before, AddressRange::from_range(10, 29));
        assert_eq!(after, AddressRange::from_range(61, 90));

        let (before, after) = a.non_overlapping_ranges(a);
        assert!(before.is_empty());
        assert!(after.is_empty());
    }

    #[test]
    fn test_allocator_new_from_list() {
        let pools = vec![
            AddressRange::from_range(0, 99),
            AddressRange::from_range(200, 299),
        ];
        let alloc = MediaAllocator::new_from_list(pools.clone(), None).unwrap();
        assert_eq!(alloc.pools, pools);
        assert_eq!(alloc.regions.len(), 2);
    }

    #[test]
    fn test_allocator_new_from_list_filters_empty() {
        let pools = vec![
            AddressRange::from_range(0, 99),
            AddressRange::empty(),
            AddressRange::from_range(200, 299),
        ];
        let alloc = MediaAllocator::new_from_list(pools, None).unwrap();
        assert_eq!(alloc.pools.len(), 2);
        assert_eq!(alloc.regions.len(), 2);
    }

    #[test]
    fn test_allocator_bad_min_align() {
        let pool = AddressRange::from_range(0, 1023);
        assert_eq!(MediaAllocator::new(pool, Some(3)), Err(libc::EBADR));
        assert_eq!(MediaAllocator::new(pool, Some(6)), Err(libc::EBADR));
    }

    #[test]
    fn test_allocator_allocate_zero_size() {
        let pool = AddressRange::from_range(0, 1023);
        let mut allocator = MediaAllocator::new(pool, Some(4)).unwrap();
        assert_eq!(allocator.allocate(0, 1), Err(libc::EINVAL));
    }

    #[test]
    fn test_allocator_release_containing() {
        let pool = AddressRange::from_range(0, 1023);
        let mut allocator = MediaAllocator::new(pool, Some(4)).unwrap();

        let offset = allocator.allocate(100, 42).unwrap();
        let released = allocator.release_containing(offset + 50).unwrap();
        assert_eq!(released, AddressRange::from_range(0, 99));
        assert!(allocator.allocs.is_empty());
    }

    #[test]
    fn test_allocator_release_containing_not_found() {
        let pool = AddressRange::from_range(0, 1023);
        let mut allocator = MediaAllocator::new(pool, Some(4)).unwrap();
        assert_eq!(allocator.release_containing(500), Err(libc::EFAULT));
    }

    #[rstest]
    #[case(
        256,
        1,
        256,
        2,
        AddressRange::from_range(0, 255),
        AddressRange::from_range(512, 1023)
    )]
    #[case(
        128,
        1,
        128,
        2,
        AddressRange::from_range(0, 127),
        AddressRange::from_range(256, 1023)
    )]
    #[case(
        512,
        1,
        256,
        2,
        AddressRange::from_range(0, 511),
        AddressRange::from_range(768, 1023)
    )]
    fn test_allocator_coalescing(
        #[case] first_size: u64,
        #[case] first_id: u64,
        #[case] second_size: u64,
        #[case] second_id: u64,
        #[case] expected_first_free: AddressRange,
        #[case] expected_second_free: AddressRange,
    ) {
        let pool = AddressRange::from_range(0, 1023);
        let mut allocator = MediaAllocator::new(pool, Some(4)).unwrap();

        // Allocate two regions
        allocator.allocate(first_size, first_id).unwrap();
        allocator.allocate(second_size, second_id).unwrap();

        // Release the first region
        allocator.release(first_id).unwrap();
        assert_eq!(
            allocator.regions.iter().collect::<Vec<_>>(),
            vec![&expected_first_free, &expected_second_free]
        );

        // Release the second region, which should coalesce the free regions
        allocator.release(second_id).unwrap();
        assert_eq!(allocator.regions.iter().next(), Some(&pool));
    }
}

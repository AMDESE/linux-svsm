/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 SUSE LLC.
 * Authors: Jörg Rödel (jroedel at suse.de)
 *
 */

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

pub struct LockGuard<'a, T> {
    holder: &'a AtomicU64,
    data: &'a mut T,
}

impl<'a, T> Deref for LockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T> DerefMut for LockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

impl<'a, T> Drop for LockGuard<'a, T> {
    fn drop(&mut self) {
        self.holder.fetch_add(1, Ordering::Release);
    }
}

pub struct SpinLock<T> {
    current: AtomicU64,
    holder: AtomicU64,
    data: UnsafeCell<T>,
    testmode: AtomicU64,
}

unsafe impl<T> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        SpinLock {
            current: AtomicU64::new(1),
            holder: AtomicU64::new(1),
            data: UnsafeCell::new(data),
            testmode: AtomicU64::new(0),
        }
    }

    pub fn test_mode(&self) {
        self.testmode.swap(1, Ordering::Relaxed);
    }

    pub fn lock(&self) -> LockGuard<T> {
        let ticket: u64 = self.current.fetch_add(1, Ordering::Relaxed);

        loop {
            let h: u64 = self.holder.load(Ordering::Acquire);
            if h == ticket {
                break;
            }
        }

        let res: LockGuard<T> = LockGuard {
            holder: &self.holder,
            data: unsafe { &mut *self.data.get() },
        };

        if self.testmode.fetch_add(0, Ordering::SeqCst) == 1 {
            unsafe {
                asm!("2: jmp 2b", in("rsi") 0xdead256);
            }
        }

        return res;
    }

    pub fn unlock(&mut self) {
        self.holder.fetch_add(1, Ordering::Release);
    }
}

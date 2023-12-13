// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex, Once,
    },
};

use tempfile::{tempdir, TempDir};

static mut TEST_HARNESS: Option<AlsaTestHarness> = None;
static INIT_ALSA_CONF: Once = Once::new();

#[must_use]
pub fn setup_alsa_conf() -> AlsaTestHarnessRef<'static> {
    INIT_ALSA_CONF.call_once(||
        // SAFETY:
        // This is only called once, because of.. `Once`, so it's safe to
        // access the static value mutably.
        unsafe {
            TEST_HARNESS = Some(AlsaTestHarness::new());
        });
    let retval = AlsaTestHarnessRef(
        // SAFETY:
        // The unsafe { } block is needed because TEST_HARNESS is a mutable static. The inner
        // operations are protected by atomics.
        unsafe { TEST_HARNESS.as_ref().unwrap() },
    );
    retval.0.inc_ref();
    retval
}

/// The alsa test harness. It must only be constructed via
/// `AlsaTestHarness::new()`.
#[non_exhaustive]
pub struct AlsaTestHarness {
    pub tempdir: Arc<Mutex<Option<TempDir>>>,
    pub conf_path: PathBuf,
    pub ref_count: AtomicU8,
}

/// Ref counted alsa test harness ref.
#[repr(transparent)]
#[non_exhaustive]
pub struct AlsaTestHarnessRef<'a>(&'a AlsaTestHarness);

impl<'a> Drop for AlsaTestHarnessRef<'a> {
    fn drop(&mut self) {
        self.0.dec_ref();
    }
}

impl AlsaTestHarness {
    pub fn new() -> Self {
        let tempdir = tempdir().unwrap();
        let conf_path = tempdir.path().join("alsa.conf");

        std::fs::write(
            &conf_path,
            b"pcm.!default {\n type null \n }\n\nctl.!default {\n type null\n }\n\npcm.null {\n type null \n }\n\nctl.null {\n type null\n }\n",
        ).unwrap();

        std::env::set_var("ALSA_CONFIG_PATH", &conf_path);
        println!(
            "INFO: setting ALSA_CONFIG_PATH={} in PID {} and TID {:?}",
            conf_path.display(),
            std::process::id(),
            std::thread::current().id()
        );

        Self {
            tempdir: Arc::new(Mutex::new(Some(tempdir))),
            conf_path,
            ref_count: 0.into(),
        }
    }

    #[inline]
    pub fn inc_ref(&self) {
        let old_val = self.ref_count.fetch_add(1, Ordering::SeqCst);
        assert!(
            old_val != u8::MAX,
            "ref_count overflowed on 8bits when increasing by 1"
        );
    }

    #[inline]
    pub fn dec_ref(&self) {
        let old_val = self.ref_count.fetch_sub(1, Ordering::SeqCst);
        if old_val == 1 {
            let mut lck = self.tempdir.lock().unwrap();
            println!(
                "INFO: unsetting ALSA_CONFIG_PATH={} in PID {} and TID {:?}",
                self.conf_path.display(),
                std::process::id(),
                std::thread::current().id()
            );
            std::env::remove_var("ALSA_CONFIG_PATH");
            _ = lck.take();
        }
    }
}

impl Drop for AlsaTestHarness {
    fn drop(&mut self) {
        let ref_count = self.ref_count.load(Ordering::SeqCst);
        if ref_count != 0 {
            println!(
                "ERROR: ref_count is {ref_count} when dropping {}",
                stringify!(AlsaTestHarness)
            );
        }
        if self
            .tempdir
            .lock()
            .map(|mut l| l.take().is_some())
            .unwrap_or(false)
        {
            println!(
                "ERROR: tempdir held a value when dropping {}",
                stringify!(AlsaTestHarness)
            );
        }
    }
}

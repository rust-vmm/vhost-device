// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex},
};

use tempfile::{tempdir, TempDir};

static TEST_HARNESS: LazyLock<AlsaTestHarness> = LazyLock::new(AlsaTestHarness::new);

#[must_use]
pub fn setup_alsa_conf() -> &'static AlsaTestHarness {
    // Dereferencing is necessary to perform the LazyLock init fn
    &TEST_HARNESS
}

/// The alsa test harness.
///
/// It sets up the `ALSA_CONFIG_PATH` variable pointing to a configuration file
/// inside a temporary directory. This way the tests won't mess with the host
/// machine's devices.
pub struct AlsaTestHarness {
    tempdir: Arc<Mutex<Option<TempDir>>>,
    conf_path: PathBuf,
}

impl AlsaTestHarness {
    fn new() -> Self {
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
        }
    }
}

impl Drop for AlsaTestHarness {
    fn drop(&mut self) {
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

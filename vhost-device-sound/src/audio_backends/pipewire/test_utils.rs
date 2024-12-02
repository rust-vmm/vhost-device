// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    convert::TryFrom,
    io::Read,
    path::Path,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use rand::distributions::Uniform;
use tempfile::{tempdir, TempDir};

/// Temporary Dbus session which is killed in drop().
pub struct DbusSession {
    pub child: Child,
    pub address: String,
}

impl DbusSession {
    pub fn new(working_dir: &Path) -> Self {
        let address_prefix = format!("unix:path={}", working_dir.join("dbus").display());
        let child = Command::new("/usr/bin/dbus-daemon")
            .args(["--session", "--address", &address_prefix, "--print-address"])
            .env("DBUS_VERBOSE", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .current_dir(working_dir)
            .spawn()
            .expect("ERROR: dbus-daemon binary not found");

        Self {
            child,
            address: address_prefix,
        }
    }
}

impl Drop for DbusSession {
    fn drop(&mut self) {
        println!("INFO: Killing Dbus session {}", self.child.id());
        if let Err(err) = self.child.kill() {
            println!(
                "ERROR: could not kill dbus process {}: {err}",
                self.child.id()
            );
        }
        // We mustn't panic in drop(), so use a wrapper function for convenience
        print_output(&mut self.child, "dbus");
    }
}

/// The pipewire test harness. It must only be constructed via
/// `PipewireTestHarness::new()`.
#[non_exhaustive]
pub struct PipewireTestHarness {
    pub _dbus: DbusSession,
    pub pipewire_child: Child,
    pub _tempdir: TempDir,
}

pub fn launch_pipewire(
    tempdir: &Path,
    dbus_session_bus_address: &Path,
) -> Result<Child, std::io::Error> {
    Command::new("pipewire")
        .env("DBUS_SESSION_BUS_ADDRESS", dbus_session_bus_address)
        .env("XDG_RUNTIME_DIR", tempdir)
        .current_dir(tempdir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
}

impl PipewireTestHarness {
    pub fn new() -> Self {
        let tempdir = tempdir().unwrap();

        let dbus_session = DbusSession::new(tempdir.path());
        println!("INFO: dbus_session_bus_address={}", dbus_session.address);

        println!("INFO: Wait for dbus to setup...");
        sleep(Duration::from_secs(1));

        println!("INFO: Launch pipewire.");
        let pipewire_child = launch_pipewire(tempdir.path(), Path::new(&dbus_session.address))
            .expect("ERROR: Could not launch pipewire");
        println!("INFO: Wait for pipewire to setup...");
        sleep(Duration::from_secs(1));

        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &dbus_session.address);
        std::env::set_var("XDG_RUNTIME_DIR", tempdir.path());

        Self {
            _dbus: dbus_session,
            pipewire_child,
            _tempdir: tempdir,
        }
    }
}

impl Drop for PipewireTestHarness {
    fn drop(&mut self) {
        println!("INFO: Killing pipewire pid {}", self.pipewire_child.id());
        if let Err(err) = self.pipewire_child.kill() {
            println!(
                "ERROR: could not kill Pipewire process {}: {err}",
                self.pipewire_child.id()
            );
        }
        // We mustn't panic in drop(), so use a wrapper function for convenience
        print_output(&mut self.pipewire_child, "pipewire");
    }
}

fn print_output(child: &mut Child, id: &'static str) -> Option<()> {
    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;

    let mut buf = String::new();
    stdout.read_to_string(&mut buf).ok()?;
    if !buf.trim().is_empty() {
        println!("INFO: {id} stdout {buf}");
    }

    buf.clear();

    stderr.read_to_string(&mut buf).ok()?;
    if !buf.trim().is_empty() {
        println!("ERROR: {id} stderr {buf}");
    }

    None
}

pub fn truncated_wait_delay<D: rand::distributions::Distribution<f32>, R: rand::Rng>(
    slot_time: &Duration,
    attempts_so_far: u32,
    exponent_max: u32,
    rng: &mut R,
    distribution: &D,
) -> Duration {
    let attempts_so_far =
        i32::try_from(attempts_so_far.clamp(0_u32, exponent_max)).unwrap_or(i32::MAX);
    let position = distribution.sample(rng);
    let max = 2_f32.powi(attempts_so_far) - 1.0_f32;
    slot_time.mul_f32(position * max)
}

pub fn try_backoff<T, E: std::fmt::Display>(
    closure: impl Fn() -> Result<T, E>,
    max_retries: Option<std::num::NonZeroU32>,
) -> Result<T, ()> {
    const NO_DELAY: Duration = Duration::new(0, 0);

    let max_retries: Option<u32> = max_retries.map(Into::into);
    let mut iterations: u32 = 0;
    let mut dur: Option<Duration> = None;
    let mut rng = rand::thread_rng();

    let distribution = Uniform::new(0.0_f32, 1.0_f32);

    loop {
        if max_retries.map_or(false, |max| iterations >= max) {
            return Err(());
        }

        let start: Instant = Instant::now();
        let result: Result<T, E> = closure();
        let elapsed: Duration = start.elapsed();

        iterations += 1;

        match result {
            Ok(v) => return Ok(v),
            Err(err) => {
                log::debug!("try_backoff: closured failed with {err}, will retry");
            }
        }

        if let Some(dur_val) = &dur {
            dur = Some((*dur_val * (iterations - 1) + elapsed) / iterations);
        } else {
            dur = Some(elapsed);
        }

        let delay: Duration = truncated_wait_delay(
            dur.as_ref().unwrap_or(&NO_DELAY),
            iterations,
            10_u32,
            &mut rng,
            &distribution,
        );

        log::debug!("Sleeping for {}s", delay.as_secs_f64());

        sleep(delay);
    }
}

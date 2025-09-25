use std::env;

use tempfile::TempDir;

/// A test harness that sets up an isolated environment for GStreamer tests.
/// Unlike PipeWire, GStreamer is a library and doesn't need a daemon.
/// We only need to isolate runtime dirs and registry files.
pub struct GStreamerTestHarness {
    _runtime_dir: TempDir,
    old_runtime_dir: Option<String>,
    old_gst_registry: Option<String>,
    old_gst_debug: Option<String>,
}

impl GStreamerTestHarness {
    /// Create a new isolated GStreamer test environment.
    pub fn new() -> Self {
        let tmpdir = tempfile::tempdir().expect("Failed to create temp dir for GStreamer");

        let old_runtime_dir = env::var("XDG_RUNTIME_DIR").ok();
        let old_gst_registry = env::var("GST_REGISTRY").ok();
        let old_gst_debug = env::var("GST_DEBUG").ok();

        log::debug!("old_runtime_dir: {:?}", old_runtime_dir);
        log::debug!("old_gst_registry: {:?}", old_gst_registry);
        log::debug!("old_gst_debug: {:?}", old_gst_debug);

        env::set_var("XDG_RUNTIME_DIR", tmpdir.path());
        env::set_var("GST_REGISTRY", tmpdir.path().join("gst-registry.bin"));
        env::set_var("GST_DEBUG", "ERROR");

        log::debug!(
            "Started isolated GStreamer test environment at {:?}",
            tmpdir.path()
        );

        Self {
            _runtime_dir: tmpdir,
            old_runtime_dir,
            old_gst_registry,
            old_gst_debug,
        }
    }
}

impl Drop for GStreamerTestHarness {
    fn drop(&mut self) {
        if let Some(val) = &self.old_runtime_dir {
            env::set_var("XDG_RUNTIME_DIR", val);
        } else {
            env::remove_var("XDG_RUNTIME_DIR");
        }

        if let Some(val) = &self.old_gst_registry {
            env::set_var("GST_REGISTRY", val);
        } else {
            env::remove_var("GST_REGISTRY");
        }

        if let Some(val) = &self.old_gst_debug {
            env::set_var("GST_DEBUG", val);
        } else {
            env::remove_var("GST_DEBUG");
        }

        log::debug!("Isolated GStreamer environment cleaned up");
    }
}

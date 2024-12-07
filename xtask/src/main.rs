// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later
// Copyright (c) 2024 Linaro Ltd.

// the `explicit_builtin_cfgs_in_flags` lint must be allowed because we might
// emit `target_env = "gnu"` in build.rs in order to get some cfg checks to
// compile; it does no harm because we're not using anything target_env specific
// here. If we find out that it affects the xtask's crate dependencies (e.g.
// when using this xtask under musl), we should figure out some other solution.
#![allow(unknown_lints, explicit_builtin_cfgs_in_flags)]

use std::error::Error;

#[cfg(feature = "mangen")]
use clap::CommandFactory;
#[cfg(feature = "mangen")]
use clap_mangen::Man;
#[cfg(feature = "mangen")]
use toml::value::Table;

// Use vhost-device-sound's args module as our own using the #[path] attribute

#[cfg(any(
    feature = "vhost-device-sound-pipewire",
    feature = "vhost-device-sound-alsa"
))]
#[path = "../../vhost-device-sound/src/args.rs"]
mod vhost_device_sound;

fn main() {
    if let Err(err) = run_app() {
        eprintln!("{}", err);
        std::process::exit(-1);
    }
}

fn run_app() -> Result<(), Box<dyn Error>> {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        #[cfg(feature = "mangen")]
        Some("mangen") => mangen()?,
        _ => print_help(),
    }
    Ok(())
}

fn print_help() {
    eprintln!(
        "Tasks:

{mangen}",
        mangen = if cfg!(feature = "mangen") {
            "mangen            builds man pages using clap_mangen under target/dist/man"
        } else {
            ""
        },
    )
}

#[cfg(feature = "mangen")]
fn mangen() -> Result<(), Box<dyn Error>> {
    let workspace_dir = std::path::Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf();
    let dist_dir = workspace_dir.join("target/dist/man");
    let _ = std::fs::remove_dir_all(&dist_dir);
    std::fs::create_dir_all(&dist_dir)?;

    let mut generated_artifacts = vec![];

    #[cfg(any(
        feature = "vhost-device-sound-pipewire",
        feature = "vhost-device-sound-alsa"
    ))]
    {
        use vhost_device_sound::SoundArgs;

        let manifest =
            std::fs::read_to_string(workspace_dir.join("vhost-device-sound/Cargo.toml"))?;
        let manifest = manifest.as_str().parse::<Table>()?;

        let name: &'static str = manifest["package"]["name"]
            .as_str()
            .unwrap()
            .to_string()
            .leak();
        let version: &'static str = manifest["package"]["version"]
            .as_str()
            .unwrap()
            .to_string()
            .leak();
        let repository: &'static str = manifest["package"]["repository"]
            .as_str()
            .unwrap()
            .to_string()
            .leak();
        let description: &'static str = manifest["package"]["description"]
            .as_str()
            .unwrap()
            .to_string()
            .leak();
        let cmd = <SoundArgs as CommandFactory>::command()
            .name(name)
            .display_name(name)
            .bin_name(name)
            .version(version)
            .about(description);
        let man = Man::new(cmd);
        let mut buffer: Vec<u8> = Default::default();
        man.render(&mut buffer)?;
        clap_mangen::roff::Roff::new()
            .control("SH", ["REPORTING BUGS"])
            .text(vec![format!(
                "Report bugs to the project's issue tracker: {repository}"
            )
            .into()])
            .to_writer(&mut buffer)?;

        let man_path = dist_dir.join("vhost-device-sound.1");
        std::fs::write(&man_path, buffer)?;
        generated_artifacts.push(man_path);
    }
    if generated_artifacts.is_empty() {
        println!("No manpages were generated! Try using the correct xtask cargo features.");
    } else {
        println!("Generated the following manual pages:");
        for art in generated_artifacts {
            println!("{}", art.display());
        }
    }

    Ok(())
}

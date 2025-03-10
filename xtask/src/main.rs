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
use markdown::{to_mdast, ParseOptions};
#[cfg(feature = "mangen")]
use toml::value::Table;

// Use vhost-device-sound's args module as our own using the #[path] attribute

#[cfg(any(
    feature = "vhost-device-sound-pipewire",
    feature = "vhost-device-sound-alsa"
))]
#[path = "../../vhost-device-sound/src/args.rs"]
mod vhost_device_sound;

// Use vhost-device-scmi's args module as our own using the #[path] attribute

#[cfg(feature = "vhost-device-scmi")]
#[path = "../../vhost-device-scmi/src/args.rs"]
mod vhost_device_scmi;

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
fn mangen_for_crate<T: CommandFactory>(
    crate_dir: std::path::PathBuf,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let readme_md = std::fs::read_to_string(crate_dir.join("README.md"))?;
    let example_text = parse_examples_from_readme(readme_md).unwrap_or_default();
    let examples = if example_text.is_empty() {
        None
    } else {
        Some(example_text.trim())
    };
    let manifest = std::fs::read_to_string(crate_dir.join("Cargo.toml"))?;
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
    let cmd = <T as CommandFactory>::command()
        .name(name)
        .display_name(name)
        .author(None)
        .bin_name(name)
        .version(version)
        .about(description);
    let man = Man::new(cmd);
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)?;
    if let Some(examples) = examples {
        let mut examples_section = clap_mangen::roff::Roff::new();
        examples_section.control("SH", ["EXAMPLES"]);
        for line in examples.lines() {
            examples_section.text(vec![line.into()]);
        }
        examples_section.to_writer(&mut buffer)?;
    }
    clap_mangen::roff::Roff::new()
        .control("SH", ["REPORTING BUGS"])
        .text(vec![format!(
            "Report bugs to the project's issue tracker: {repository}"
        )
        .into()])
        .to_writer(&mut buffer)?;

    Ok(buffer)
}

#[cfg(feature = "mangen")]
fn parse_examples_from_readme(readme_md: String) -> Result<String, Box<dyn Error>> {
    use markdown::mdast;

    let mdast = to_mdast(&readme_md, &ParseOptions::gfm()).map_err(|err| err.to_string())?;
    let mut example_text = String::new();
    if let mdast::Node::Root(root) = mdast {
        if let Some(examples_index) = root.children.iter().position(|r| matches!(r, mdast::Node::Heading(mdast::Heading { ref children, .. }) if matches!(children.first(), Some(mdast::Node::Text(mdast::Text { ref value, .. })) if value.trim() == "Examples"))){
            let mdast::Node::Heading(examples_heading) =
                &root.children[examples_index]
                else {
                    // SAFETY: Unreachable because we found the exact position earlier.
                    unreachable!();
                };
                let depth = examples_heading.depth;
                let mut i = examples_index + 1;
                while i < root.children.len() && !matches!(root.children[i], mdast::Node::Heading(ref h) if h.depth >= depth) {
                    match &root.children[i] {
                        mdast::Node::Paragraph(p) => {
                            example_text.push_str(&p.children.iter().map(|t| t.to_string()).collect::<Vec<String>>().join(" "));
                            example_text.push_str("\n\n");
                        },
                        mdast::Node::Code(c) => {
                            example_text.push_str(&c.value);
                            example_text.push_str("\n\n");
                        },
                        _ => {},
                    }
                    i += 1;
                }
        }
    }
    Ok(example_text)
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

    let mut buffers = vec![];
    #[cfg(any(
        feature = "vhost-device-sound-pipewire",
        feature = "vhost-device-sound-alsa"
    ))]
    {
        use vhost_device_sound::SoundArgs;

        let buffer = mangen_for_crate::<SoundArgs>(workspace_dir.join("vhost-device-sound"))?;
        let man_path = dist_dir.join("vhost-device-sound.1");
        buffers.push((man_path, buffer));
    }
    #[cfg(feature = "vhost-device-scmi")]
    {
        use vhost_device_scmi::ScmiArgs;

        let buffer = mangen_for_crate::<ScmiArgs>(workspace_dir.join("vhost-device-scmi"))?;
        let man_path = dist_dir.join("vhost-device-scmi.1");
        buffers.push((man_path, buffer));
    }

    if buffers.is_empty() {
        println!("No manpages were generated! Try using the correct xtask cargo features.");
        return Ok(());
    }

    let mut generated_artifacts = Vec::with_capacity(buffers.len());

    for (man_path, buffer) in buffers {
        std::fs::write(&man_path, buffer)?;
        generated_artifacts.push(man_path);
    }

    assert!(!generated_artifacts.is_empty());
    println!("Generated the following manual pages:");
    for art in generated_artifacts {
        println!("{}", art.display());
    }

    Ok(())
}

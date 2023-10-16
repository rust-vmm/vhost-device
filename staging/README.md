# vhost-device `staging` workspace

This directory includes a separate Cargo workspace to include working vhost-user backend implementations that concern devices that have partial functionality and devices (and/or functionality) not yet ratified in the [VIRTIO specification](https://github.com/oasis-tcs/virtio-spec).
For more details about vhost-device you can refer to the repository [README](../README.md).

To add a new member crate:

1. Place it under this directory, [`./staging`](../staging).
2. Append its name in the `workspace.members` array field of [the workspace manifest file](./Cargo.toml).
3. Update the crate list in the repository [README](../README.md).

## Testing and Continuous Integration

ℹ️  **Notice** ℹ️ : The CI runs on the root workspace only.
This means that `staging` crates can have failing tests and bring down code coverage without automatic checks.
Tests can still be run locally as part of the development process.
To add a crate to the CI, add it to the root `Cargo.toml` `workspace.members` array as well as the `staging` manifest.

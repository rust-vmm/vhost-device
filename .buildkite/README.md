# buildkite custom pipelines

This folder contains the custom pipelines for this repository.

If we add a new pipeline we need to enable it in
https://buildkite.com/rust-vmm/vhost-device-ci/steps

Custom pipelines currently defined are:
- `main-tests.json`
  This is based on `rust-vmm-ci/.buildkite/test_description.json`.
  We have an internal version, because we have several applications that have
  dependencies that don't work very well on musl, so it's easier to manage CI
  by having our own internal pipeline.

- `staging-tests.json`
  This is based on `main-tests.json`.
  We should keep `staging-tests.json` aligned with it as much as possible to
  make sure we don't notice any difference in CI when we move a crate from the
  staging to the main workspace.


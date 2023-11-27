# buildkite custom pipelines

This folder contains the custom pipelines for this repository.

If we add a new pipeline we need to enable it in
https://buildkite.com/rust-vmm/vhost-device-ci/steps

Custom pipelines currently defined are:
- `staging-tests.json`
  This is based on `rust-vmm-ci/.buildkite/test_description.json`.
  We should keep `staging-tests.json` aligned with it as much as possible to
  make sure we don't notice any difference in CI when we move a crate from the
  staging to the main workspace.


# vhost-user-scsi architecture

Rough outline of the different pieces and how they fit together:

## `scsi/mod.rs`

This defines the `Target` trait, which represents a SCSI target. The code in
this file is independent from:

- A particular SCSI implementation: Currently, we have one implementation of
  `Target`, which emulates the SCSI commands itself; but future implementations
  could provide pass-through to an iSCSI target or SCSI devices attached to the
  host.
- A particular SCSI transport: Nothing in `src/scsi/*` knows anything about
  virtio; this is helpful for maintainability, and also allows our SCSI
  emulation code to be reusable as, for example, an iSCSI target. To this end,
  the `Target` trait is generic over a `Read` and `Write` that it uses for SCSI
  data transfer. This makes testing easy: we can just provide a `Vec<u8>` to
  write into.

## `scsi/emulation/*.rs`

This is the SCSI emulation code, which forms the bulk of the crate. It provides
`EmulatedTarget`, an implementation of `Target`. `EmulatedTarget`, in turn,
looks at the LUN and delegates commands to an implementation of `LogicalUnit`.
In most cases, this will be `BlockDevice`; there's also `MissingLun`, which is
used for responding to commands to invalid LUNs.

Currently, there is no separation between commands defined in the SPC standard
(commands shared by all device types) and the SBC standard (block-device
specific commands). If we ever implemented another device type (CD/DVD seems
most likely), we'd want to separate those out.

As noted above, the emulation code knows nothing about virtio.

## `src/{main,virtio}.rs`

This code handles vhost-user, virtio, and virtio-scsi; it's the only part of
the crate that knows about these protocols.

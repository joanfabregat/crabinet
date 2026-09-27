# Writable share staging cutover

This runbook moves each deployed writable share's existing `.index-staging` directory to `.crabinet/staging`. The deployment operator supplies the actual share roots and service control commands. Keep the application stopped throughout the filesystem work; only one Crabinet process may own a writable share.

## Before starting

1. Record the deployed image digest, configuration, share roots, and database location. Take a restorable snapshot of each writable share and the SQLite database. Confirm that the snapshots completed before changing files. A snapshot is a recovery option, not the routine rollback procedure: restoring it later would discard writes made after it was taken.
2. Stop the current Crabinet process and verify it has exited. Prevent a second replica from starting against the same writable share.
3. For each writable share, inspect `.index-staging` without following links. Confirm it is a directory on the same filesystem as the share root. List its direct children, including hidden names. Treat every `.index-del-<32 hex>` entry as potentially recoverable user data from an interrupted delete or replacement; leave it in staging for operator review. Other entries, including incomplete `.index-tmp-<32 hex>` uploads, are also preserved by the rename. Investigate unexpected files or links before proceeding.

## Rename and start

1. For each share root, create `.crabinet` with mode `0700`, or verify that an existing `.crabinet` is a real directory with mode `0700`. Preserve any existing `.crabinet/trash` content. Confirm that `.crabinet/staging` does not exist; stop if it does, since the rename must never overwrite it.
2. Atomically rename that share's `.index-staging` directory to `.crabinet/staging` on the same filesystem, with no overwrite. Verify that the old path is absent, the new path is a real mode-`0700` directory, and its contents are still present. Do not copy, empty, or delete the staging directory.
3. Deploy the new image and start exactly one writer for each writable share. Confirm readiness, then verify a test upload and download on an authorized writable share. Confirm `.crabinet` and `.index-staging` are absent from browser listings, including when hidden files are shown. Review any retained `.index-del-` entries without deleting them automatically.

## Rollback

1. Stop the new process and verify it has exited. Inspect each `.crabinet/staging` directory and preserve its contents, especially `.index-del-` entries. Confirm that `.index-staging` does not exist; stop if it does, since the reverse rename must never overwrite it.
2. Atomically rename `.crabinet/staging` back to `.index-staging` on the same filesystem, with no overwrite. Verify the new path is absent and the old path contains the preserved entries. Move the remaining `.crabinet` directory to a protected location outside the share and record its new path before starting the older binary. The older binary does not reserve `.crabinet` from its file API, so it must not remain in the served share. Preserve any `trash` or other contents for future recovery.
3. Deploy the recorded previous image digest and compatible configuration. If the new version changed the SQLite schema, first determine whether the older binary can open it. Restoring the pre-cutover database snapshot is an explicit data-loss decision because it discards newer database state; do so only with a separate plan to preserve or reconcile intervening changes. Start exactly one old writer per writable share and verify readiness and a read.

If new-version startup fails because `.index-staging` still exists, leave the service stopped and verify the rename. Do not bypass the check by changing a share to read-only while users expect writes.

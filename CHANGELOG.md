# Changelog

## Unreleased

### Added

- Web Push notifications (RFC 8030 / 8291 / 8292, VAPID). When `GATE_VAPID_PRIVATE_KEY` is set,
  approvers can enable notifications on a device after a passkey ceremony, and each new approval
  request is pushed to every subscribed device of the organisation's active approvers. Off by
  default; with the variable unset the server behaves as before. Delivery is best effort and the
  approve link remains the fallback. See "Notifications" in the README.
- `perathos-gate vapid-keygen` prints a VAPID key pair.
- New table `push_subscriptions`, created at startup by the existing `create_all` call. No
  existing table or column changes.
- Home page `/`, `/sw.js` and `/manifest.webmanifest` (only when push is configured), so the Gate
  can be added to an iPhone or iPad Home Screen, which iOS requires for Web Push.
- New dependency: `pywebpush` (MPL-2.0).

### Changed

- The page CSP gains `worker-src 'self'` and `manifest-src 'self'`.
- Approver rate limiting also covers `POST /push/*`.

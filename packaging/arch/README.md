# oo8 Arch updates from GitHub Releases

The package source, GitHub Releases, and pacman repository live in this
**single GitHub repository**. No AUR submission, extra GitHub repository, custom
updater binary, or per-release manual download is required.

## Release path

1. A version tag such as `v0.7.0.oo8.1` triggers GitHub Actions.
2. CI builds the Arch `.pkg.tar.zst`, inspects its installed file manifest,
   and tests the packaged daemon on disposable keyrings in a private D-Bus
   session. A failure stops publication.
3. `repo-add` builds the `oo8.db` and `oo8.files` pacman indexes.
4. The package and repository databases are uploaded to a **draft** GitHub
   Release. Only after all assets are present is it published and marked latest.
5. Pacman can request the stable asset names through GitHub's
   `/releases/latest/download/oo8.db` endpoint, while package filenames are
   derived from the database. Thus the same GitHub Release acts as a pacman
   repository.

## One-time pacman configuration

**Do not enable this until the first validated oo8 release is published,
packaging compatibility has been verified, and the signing policy has been
finalized.**

After that, a repository section in `/etc/pacman.conf` is sufficient:

```ini
[oo8]
Server = https://github.com/sguzman/oo8/releases/latest/download
```

If packages are unsigned, pacman's normal `SigLevel = Required` rejects
them. A repository-specific `SigLevel = Optional` permits unsigned
packages, but weakens authenticity verification and **is not an acceptable
long-term default for a credential manager**. Prefer signing released
packages with a trusted GPG key and keeping normal signature verification
enabled. Never change the global signature policy just for oo8.

Install `oo8` **once** from this repository after validation. From then on,
normal `pacman -Syu` / `yay -Syu` finds newer oo8 releases through the
standard package database. Pacman does not silently update itself.

GitHub Releases are retained as downloadable, versioned packages for rollback.
Packages and indexes on the latest release must be published together; the
staged release workflow avoids switching to a partially populated release.

## Scope and safeguards

- Existing `oo7` binary, PAM, portal, credential, and D-Bus names are kept for
  interface and storage compatibility.
- The `oo8` package declares `provides` and `conflicts` for the upstream
  package. A rollback plan and encrypted-keyring backup are required before
  switching a production desktop.
- No GitHub workflow performs installations on the user's computer.
- No special `yay` development-package flag is needed: releases carry
  explicit package versions and are indexed by `oo8.db`.
- This is not a separate GitHub repository, despite pacman calling it a
  repository. That term means a served package database and its packages.

# Git-Flow Branching Model

This repository follows the **git-flow** branching model for firmware releases.

## Branch Types

| Branch | Purpose | Created from | Merges to |
|--------|---------|-------------|-----------|
| `master` | Production releases only. Every commit is tagged. | — | — |
| `develop` | Integration branch. All features merge here first. | — | — |
| `feature/*` | New features and improvements | `develop` | `develop` |
| `release/*` | Release preparation (version bump, final fixes) | `develop` | `master` + `develop` |
| `hotfix/*` | Critical production fixes | `master` | `master` + `develop` |
| `fix/*` | Non-critical bug fixes | `develop` | `develop` |

## Workflows

### Feature Development

```bash
# Start feature
git checkout develop
git pull origin develop
git checkout -b feature/solana-support

# Work, commit, push
git push -u origin feature/solana-support

# Create PR → develop (CI runs automatically)
gh pr create --repo BitHighlander/keepkey-firmware --base develop
```

### Cutting a Release

```bash
# 1. Branch from develop
git checkout develop
git pull origin develop
git checkout -b release/v7.11.0

# 2. Bump version in CMakeLists.txt
#    VERSION 7.11.0

# 3. Final fixes only (no new features!)
git commit -m "chore: bump version to v7.11.0"
git push -u origin release/v7.11.0

# 4. CI runs on release/* branch — must pass

# 5. When ready: merge to master
gh pr create --repo BitHighlander/keepkey-firmware --base master \
  --title "Release v7.11.0"

# 6. After merge to master: tag it
git checkout master
git pull origin master
git tag v7.11.0
git push origin v7.11.0
# → Release workflow triggers → builds firmware → creates draft GitHub Release

# 7. Merge release branch back to develop
git checkout develop
git merge release/v7.11.0
git push origin develop

# 8. Delete release branch
git branch -d release/v7.11.0
git push origin --delete release/v7.11.0
```

### Hotfix (Critical Production Fix)

```bash
# 1. Branch from master
git checkout master
git pull origin master
git checkout -b hotfix/v7.11.1

# 2. Fix + bump patch version
git commit -m "fix: critical signing bug"
git commit -m "chore: bump version to v7.11.1"

# 3. PR to master
gh pr create --repo BitHighlander/keepkey-firmware --base master \
  --title "Hotfix v7.11.1"

# 4. After merge: tag + merge to develop
git checkout master && git pull origin master
git tag v7.11.1
git push origin v7.11.1

git checkout develop
git merge hotfix/v7.11.1
git push origin develop
```

## CI/CD Pipeline

### On Every Push (ci.yml)
- **Gate**: lint, secret scan, submodule check
- **Build**: emulator + ARM firmware (full + BTC-only)
- **Test**: unit tests + python integration

### On Tag Push `v*` (release.yml)
- **Validate**: tag matches CMakeLists.txt version
- **Build**: full + BTC-only firmware with hash manifests
- **Test**: emulator unit tests
- **Release**: draft GitHub Release with all artifacts

### After Draft Release
1. Build on multiple machines, compare hashes
2. Sign on air-gapped machine (3/5 signers)
3. Upload signed `.bin` replacing unsigned
4. Publish release (remove draft status)

## Version Numbering

```
v7.MINOR.PATCH

MINOR = feature releases (new chain support, protocol changes)
PATCH = bug fixes, security patches
```

- `release/*` bumps MINOR (e.g., v7.10.0 → v7.11.0)
- `hotfix/*` bumps PATCH (e.g., v7.11.0 → v7.11.1)

## Branch Protection (Recommended)

### `master`
- Require PR reviews (1+)
- Require CI status checks to pass
- No direct pushes (except tags)

### `develop`
- Require CI status checks to pass
- Allow direct pushes for maintainers (merge commits)

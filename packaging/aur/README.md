# Arch User Repository (AUR) Packaging for Vetto

This directory contains the `PKGBUILD` recipe and `.SRCINFO` manifest for Arch Linux and derivative distributions.

---

## Files
- `PKGBUILD`: Build recipe compiling from source with reproducible paths.
- `.SRCINFO`: Machine-readable package metadata.

---

## Publishing to AUR (Arch Linux)

1. **Clone AUR repository**:
   ```bash
   git clone ssh://aur@aur.archlinux.org/vetto-git.git /tmp/aur-vetto
   ```

2. **Copy updated files**:
   ```bash
   cp packaging/aur/PKGBUILD /tmp/aur-vetto/
   cd /tmp/aur-vetto
   makepkg --printsrcinfo > .SRCINFO
   ```

3. **Verify build locally (Arch host / container)**:
   ```bash
   makepkg -si
   ```

4. **Commit and push**:
   ```bash
   git add PKGBUILD .SRCINFO
   git commit -m "feat: update vetto v0.2.5"
   git push origin master
   ```

5. **User installation**:
   ```bash
   yay -S vetto-git
   # or
   paru -S vetto-git
   ```

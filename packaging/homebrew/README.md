# Homebrew Packaging for Vetto

This directory contains the formula and tap setup instructions for macOS and Linux users using Homebrew.

---

## Formula Location
- **Formula**: [`vetto.rb`](vetto.rb)

---

## Publishing to Homebrew Tap

1. **Bootstrap Tap Directory**:
   ```bash
   bash packaging/homebrew/create-tap.sh
   ```

2. **Push to GitHub**:
   ```bash
   cd ~/homebrew-vetto
   git init && git add . && git commit -m "feat: release v0.2.5"
   git remote add origin git@github.com:shleder/homebrew-vetto.git
   git branch -M main
   git push -u origin main
   ```

3. **User Installation**:
   ```bash
   brew tap shleder/vetto
   brew install vetto
   ```

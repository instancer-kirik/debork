# debork Installation Guide

**For broken systems, use the one-liner rescue method below!**

## 🚨 Emergency Rescue (Your CachyOS situation)

When your system won't boot, use this one-liner from any rescue USB:

```bash
curl -sSL https://get.debork.dev | sudo bash
```

Then run:
```bash
sudo debork
```

That's it! No compilation needed.

## Package Installation (Normal systems)

### Arch Linux / CachyOS / Manjaro
```bash
# Install from AUR
yay -S debork

# Or shorter name
yay debork

# Then use
sudo debork
# or
sudo debork
```

### Ubuntu / Debian
```bash
# Download .deb package
wget https://github.com/debork/debork/releases/latest/download/debork_1.0.0_amd64.deb
sudo dpkg -i debork_1.0.0_amd64.deb

# Use
sudo debork
```

### Fedora / RHEL
```bash
# Download .rpm package
wget https://github.com/debork/debork/releases/latest/download/debork-1.0.0.x86_64.rpm
sudo rpm -i debork-1.0.0.x86_64.rpm

# Use
sudo debork
```

### Any Linux (Manual)
```bash
# Download portable version
wget https://github.com/debork/debork/releases/latest/download/debork-linux-x86_64
chmod +x debork-linux-x86_64
sudo ./debork-linux-x86_64
```

## Quick URLs for Rescue

**Easy to type in rescue scenarios:**

- `get.debork.dev` - One-liner installer
- `dl.debork.dev` - Direct binary download
- `git.io/debork` - GitHub shortlink

## What Gets Installed

- `/usr/local/bin/debork` - Main binary
- `/usr/local/bin/debork` - Symlink (easier to type)
- `/usr/share/doc/debork/` - Documentation

## Uninstall

```bash
sudo rm /usr/local/bin/debork /usr/local/bin/debork
sudo rm -rf /usr/share/doc/debork
```

## For Your Current Issue (CachyOS + rEFInd)

1. Boot any Linux rescue USB
2. Connect to internet
3. Run: `curl -sSL get.debork.dev | sudo bash`
4. Run: `sudo debork`
5. Enter your root partition (e.g., `/dev/sda2`)
6. Select "Fix Boot Configuration"
7. Choose your kernel
8. Reboot

**That's it - no compiling, no dependencies, just works.**

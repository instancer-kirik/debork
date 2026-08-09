# Maintainer: debork Team <debork@example.com>
pkgname=debork
pkgver=1.0.0
pkgrel=1
pkgdesc="Cross-platform Linux boot rescue tool with TUI interface"
arch=('x86_64' 'i686' 'aarch64')
url="https://github.com/debork/debork"
license=('MIT')
depends=('glibc')
makedepends=('dmd')
optdepends=(
    'grub: for GRUB bootloader support'
    'refind: for rEFInd bootloader support'
    'systemd: for systemd-boot support'
    'mkinitcpio: for initramfs regeneration on Arch-based systems'
)
source=("$pkgname-$pkgver.tar.gz::https://github.com/debork/debork/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')  # Update with actual checksum

build() {
    cd "$pkgname-$pkgver"
    dmd -O -release -inline -of=debork fixer.d
}

check() {
    cd "$pkgname-$pkgver"
    # Basic functionality test
    ./debork --help >/dev/null
}

package() {
    cd "$pkgname-$pkgver"

    # Install binary
    install -Dm755 debork "$pkgdir/usr/bin/debork"

    # Install documentation
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"

    # Install man page (if created)
    # install -Dm644 debork.1 "$pkgdir/usr/share/man/man1/debork.1"

    # Create symlink for easy access
    mkdir -p "$pkgdir/usr/bin"
    ln -s debork "$pkgdir/usr/bin/debork"
}

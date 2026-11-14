# Maintainer: ermat <ermats488@gmail.com>
pkgname=blackbox-git
pkgver=r0
pkgrel=1
pkgdesc="Cyber Investigation & Attack Reconstruction Platform (isolated lab)"
arch=('any')
url="https://github.com/ermat175-droid/BLACKBOX"
license=('MIT')
depends=('python' 'docker')
makedepends=('git')
provides=('blackbox')
conflicts=('blackbox')
source=("git+https://github.com/ermat175-droid/BLACKBOX.git")
sha256sums=('SKIP')

pkgver() {
  cd "$srcdir/BLACKBOX"
  printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

package() {
  cd "$srcdir/BLACKBOX"
  local dest="$pkgdir/usr/share/blackbox"
  install -dm755 "$dest"
  cp -r backend scripts deploy fixtures scenarios bin requirements.txt README.md "$dest/"

  # A self-contained virtualenv shipped with the package. The `blackbox`
  # launcher calls .venv/bin/python directly (a symlink to the system
  # interpreter), so the env works from its install location; case data is
  # written to the user's ~/.local/share/blackbox (this tree stays read-only).
  python -m venv "$dest/.venv"
  "$dest/.venv/bin/pip" install --quiet --no-cache-dir -r requirements.txt

  install -dm755 "$pkgdir/usr/bin"
  ln -s /usr/share/blackbox/bin/blackbox "$pkgdir/usr/bin/blackbox"
}

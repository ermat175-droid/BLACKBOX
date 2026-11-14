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

build() {
  # Build the self-contained virtualenv here (network is allowed in build(),
  # not in package()). Pinned, tested dependencies travel with the package, so
  # it does not depend on the rolling versions of the system's python modules.
  cd "$srcdir/BLACKBOX"
  python -m venv .venv
  ./.venv/bin/pip install --quiet --no-cache-dir -r requirements.txt
}

package() {
  cd "$srcdir/BLACKBOX"
  local dest="$pkgdir/usr/share/blackbox"
  install -dm755 "$dest"
  # The venv is relocatable: .venv/bin/python is a symlink to the system
  # interpreter and pyvenv.cfg sits beside it, so it resolves at the install
  # path. The `blackbox` launcher calls .venv/bin/python directly; case data
  # is written to ~/.local/share/blackbox (this tree stays read-only).
  cp -r backend scripts deploy fixtures scenarios bin .venv requirements.txt README.md "$dest/"

  install -dm755 "$pkgdir/usr/bin"
  ln -s /usr/share/blackbox/bin/blackbox "$pkgdir/usr/bin/blackbox"
}

#!/bin/sh

set -eu

APP_NAME="Android Inspector"
PACKAGE_NAME="android-inspector"
VERSION="${PACKAGE_VERSION:-1.0.0}"
ARCH="amd64"

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

# Binario e icono corregidos con la estructura de tu proyecto
BINARY="$PROJECT_ROOT/build/bin/android_inspector"
ICON="$PROJECT_ROOT/build/linux/icons.png"

STAGING_DIR="$PROJECT_ROOT/build/deb/$PACKAGE_NAME"
OUTPUT_DIR="$PROJECT_ROOT/build/installer"
OUTPUT_FILE="$OUTPUT_DIR/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

echo "======================================"
echo " Android Inspector - Debian Builder"
echo "======================================"
echo ""

echo "==> Proyecto:"
echo "$PROJECT_ROOT"
echo ""

# --------------------------------------
# FRONTEND
# --------------------------------------

echo "==> Instalando dependencias frontend..."

if [ -f "$PROJECT_ROOT/frontend/package-lock.json" ]; then
    npm --prefix "$PROJECT_ROOT/frontend" ci
else
    npm --prefix "$PROJECT_ROOT/frontend" install
fi

echo "==> Compilando frontend..."

npm --prefix "$PROJECT_ROOT/frontend" run build

# --------------------------------------
# WAILS
# --------------------------------------

echo "==> Compilando Android Inspector..."

cd "$PROJECT_ROOT"

wails build \
    -clean \
    -s \
    -m \
    -nosyncgomod \
    -trimpath \
    -tags webkit2_41

# --------------------------------------
# VERIFICAR EJECUTABLE
# --------------------------------------

echo ""
echo "==> Verificando ejecutable..."

if [ ! -f "$BINARY" ]; then
    echo ""
    echo "ERROR: Wails terminó pero no existe:"
    echo "$BINARY"
    echo ""
    echo "Contenido de build/bin:"
    ls -lah "$PROJECT_ROOT/build/bin/" 2>/dev/null || true
    exit 1
fi

echo "OK: $BINARY"

# --------------------------------------
# VERIFICAR ICONO
# --------------------------------------

echo ""
echo "==> Verificando icono..."

if [ ! -f "$ICON" ]; then
    echo ""
    echo "ERROR: No existe:"
    echo "$ICON"
    exit 1
fi

echo "OK: $ICON"

# --------------------------------------
# CREAR ESTRUCTURA DEL DEB
# --------------------------------------

echo ""
echo "==> Preparando paquete Debian..."

rm -rf "$STAGING_DIR"
rm -f "$OUTPUT_FILE"

mkdir -p "$STAGING_DIR/DEBIAN"
mkdir -p "$STAGING_DIR/usr/bin"
mkdir -p "$STAGING_DIR/usr/share/applications"
mkdir -p "$STAGING_DIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$OUTPUT_DIR"

# --------------------------------------
# CONTROL
# --------------------------------------

echo "==> Creando control..."

cat > "$STAGING_DIR/DEBIAN/control" <<EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: libgtk-3-0, libwebkit2gtk-4.1-0
Maintainer: Jorge Loor <erudito.tv@gmail.com>
Description: Android Inspector
 Desktop application for inspecting Android devices using ADB.
EOF

# --------------------------------------
# DESKTOP
# --------------------------------------

echo "==> Creando acceso de aplicación..."

cat > "$STAGING_DIR/usr/share/applications/$PACKAGE_NAME.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=$APP_NAME
Comment=Inspect Android devices using ADB
Exec=/usr/bin/$PACKAGE_NAME
Icon=$PACKAGE_NAME
Terminal=false
Categories=Development;Utility;
StartupNotify=true
EOF

# --------------------------------------
# COPIAR EJECUTABLE
# --------------------------------------

echo "==> Copiando ejecutable..."

install -m 0755 \
    "$BINARY" \
    "$STAGING_DIR/usr/bin/$PACKAGE_NAME"

# --------------------------------------
# COPIAR ICONO
# --------------------------------------

echo "==> Copiando icono..."

install -m 0644 \
    "$ICON" \
    "$STAGING_DIR/usr/share/icons/hicolor/256x256/apps/$PACKAGE_NAME.png"

# --------------------------------------
# CREAR DEB
# --------------------------------------

echo "==> Creando paquete .deb..."

dpkg-deb \
    --root-owner-group \
    --build \
    "$STAGING_DIR" \
    "$OUTPUT_FILE"

# --------------------------------------
# VERIFICAR DEB
# --------------------------------------

if [ ! -f "$OUTPUT_FILE" ]; then
    echo ""
    echo "ERROR: No se creó el paquete:"
    echo "$OUTPUT_FILE"
    exit 1
fi

# --------------------------------------
# LIMPIAR TEMPORAL
# --------------------------------------

echo "==> Limpiando archivos temporales..."

rm -rf "$STAGING_DIR"

# --------------------------------------
# FINAL
# --------------------------------------

echo ""
echo "======================================"
echo " PAQUETE CREADO CORRECTAMENTE"
echo "======================================"
echo ""
echo "Aplicación: $APP_NAME"
echo "Paquete:    $PACKAGE_NAME"
echo "Versión:    $VERSION"
echo ""
echo "Archivo:"
echo "$OUTPUT_FILE"
echo ""
#!/bin/bash
set -e

source libs/env_deploy.sh
[ "$GOOS" == "windows" ] && [ "$GOARCH" == "amd64" ] && DEST=$DEPLOYMENT/windows64 || true
[ "$GOOS" == "windows" ] && [ "$GOARCH" == "arm64" ] && DEST=$DEPLOYMENT/windows-arm64 || true
[ "$GOOS" == "linux" ] && [ "$GOARCH" == "amd64" ] && DEST=$DEPLOYMENT/linux64 || true
[ "$GOOS" == "linux" ] && [ "$GOARCH" == "arm64" ] && DEST=$DEPLOYMENT/linux-arm64 || true
if [ -z $DEST ]; then
  echo "Please set GOOS GOARCH"
  exit 1
fi
rm -rf $DEST
mkdir -p $DEST

export CGO_ENABLED=0
# 某些网络环境下 proxy.golang.org 会出现 TLS 异常；允许用户覆盖。
: "${GOPROXY:=direct}"
export GOPROXY
# 让 Go 的缓存/模块缓存落到项目目录里，避免某些受限环境写入 $HOME 失败。
: "${GOCACHE:=$BUILD/.gocache}"
: "${GOMODCACHE:=$BUILD/.gomodcache}"
mkdir -p "$GOCACHE" "$GOMODCACHE"
export GOCACHE GOMODCACHE

#### Go: updater ####
pushd go/cmd/updater
[ "$GOOS" == "darwin" ] || go build -o $DEST -trimpath -ldflags "-w -s"
[ "$GOOS" == "linux" ] && mv $DEST/updater $DEST/launcher || true
popd

#### Go: nekobox_core ####
pushd go/cmd/nekobox_core
# with_ech 已在 sing-box 1.12+ 中弃用并会直接编译失败，移除即可（ECH 由标准库接管）。
go build -v -o $DEST -trimpath -ldflags "-w -s -X github.com/matsuridayo/libneko/neko_common.Version_neko=$version_standalone -X github.com/sagernet/sing-box/constant.Version=$version_sing_box" -tags "with_clash_api,with_gvisor,with_quic,with_wireguard,with_utls"
popd

#### Go: nekobox_sync ####
pushd go/cmd/nekobox_sync
go build -v -o $DEST -trimpath -ldflags "-w -s"
popd

#### copy to local build dir (for VSCode run) ####
if [ -d "$BUILD" ] && [ "$GOOS" == "linux" ] && [ "$GOARCH" == "amd64" ]; then
  cp -f "$DEST/nekobox_core" "$BUILD/nekobox_core" || true
  cp -f "$DEST/launcher" "$BUILD/launcher" || true
  cp -f "$DEST/nekobox_sync" "$BUILD/nekobox_sync" || true
fi

#!/usr/bin/env bash
set -euo pipefail
if test "${1:-}" = inspect; then
  for d in /workspaces/.agent-state/actplane-research/raw/translation-models-20261028 /boot /lib/modules; do
    printf '\n%s\n' "$d"
    test -d "$d" || continue
    find "$d" -maxdepth 4 -type f \( -name '*cpio*' -o -name '*initrd*' -o -name '*initramfs*' -o -name 'vmlinuz*' -o -name '*.ko*' -o -name '*vm*.sh' -o -name '*vm*.py' -o -name config-6.8\* \) -printf '%s %p\n' | head -65
  done
  printf '\n9p module candidates\n'
  find /workspaces/.agent-state/actplane-research/raw/translation-models-20261028/vm-root/lib/modules -type f \( -name '*9p*ko*' -o -name '*virtio*ko*' \) -printf '%p\n' | head -30
  command -v modprobe || true
  command -v depmod || true
  command -v zstd || true
  grep -E '^CONFIG_(9P|NET_9P|VIRTIO|BPF_LSM|NETFS|FSCACHE)' /workspaces/.agent-state/actplane-research/raw/translation-models-20261028/vm-root/boot/config-6.8.0-138-generic
  ls -l /workspaces/.agent-state/actplane-research/raw/translation-models-20261028/vm-root/lib/modules/6.8.0-138-generic/modules.dep* || true
  exit 0
fi
lane=/workspaces/exp/injection-bench
action=start
instance="${1:-default}"
if test "$instance" = stop; then
  action=stop
  instance="${2:-default}"
fi
if ! [[ "$instance" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
  echo 'VM instance must contain lowercase letters, digits or hyphens' >&2
  exit 2
fi
vm="$WS_RAW/vm"
test "$instance" = default || vm="$WS_RAW/vm-$instance"
if test "$action" = stop; then
  if ! test -r "$vm/qemu.pid"; then
    rm -f "$vm/queue/ready.json"
    echo "VM instance $instance is already stopped"
    exit 0
  fi
  pid=$(cat "$vm/qemu.pid")
  if test -r "/proc/$pid/cmdline" && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$vm/initrd.gz"; then
    kill "$pid"
    rm -f "$vm/queue/ready.json"
  else
    echo 'Refusing to stop PID that is not this lane VM' >&2
    exit 1
  fi
  exit 0
fi
if test -r "$vm/qemu.pid"; then
  pid=$(cat "$vm/qemu.pid")
  if test -r "/proc/$pid/cmdline" && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$vm/initrd.gz"; then
    echo "VM instance $instance is already running as PID $pid"
    exit 0
  fi
fi
source_root=/workspaces/.agent-state/actplane-research/raw/translation-models-20261028/vm-root
version=6.8.0-138-generic
mkdir -p "$vm/initrd/bin" "$vm/initrd/modules" "$vm/initrd/newroot" "$vm/queue"
chmod 700 "$vm/queue"
cp /bin/busybox "$vm/initrd/bin/busybox"
for applet in sh mount insmod mkdir switch_root cat echo sleep poweroff; do
  ln -sf busybox "$vm/initrd/bin/$applet"
done
# Resolve installed, read-only module dependencies, then copy/decompress only
# the 9p transport modules. No package install or existing VM-root mutation.
modprobe --dirname "$source_root" --set-version "$version" --show-depends 9pnet_virtio > "$vm/module-deps.txt"
modprobe --dirname "$source_root" --set-version "$version" --show-depends 9p >> "$vm/module-deps.txt"
: > "$vm/initrd/load-modules.sh"
while read -r kind module rest; do
  test "$kind" = insmod || continue
  name=$(basename "$module" .zst)
  if test ! -e "$vm/initrd/modules/$name"; then
    case "$module" in
      *.zst) zstd -q -d -c "$module" > "$vm/initrd/modules/$name" ;;
      *) cp "$module" "$vm/initrd/modules/$name" ;;
    esac
  fi
  if ! grep -Fxq "insmod /modules/$name" "$vm/initrd/load-modules.sh"; then
    printf 'insmod /modules/%s\n' "$name" >> "$vm/initrd/load-modules.sh"
  fi
done < "$vm/module-deps.txt"
cat > "$vm/initrd/init" <<'INIT'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
. /load-modules.sh
mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,ro rootfs /newroot || { echo ROOT_MOUNT_FAILED; poweroff -f; }
mount -t proc proc /newroot/proc
mount -t sysfs sysfs /newroot/sys
mount -t devtmpfs devtmpfs /newroot/dev
mount -t tmpfs tmpfs /newroot/run
mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 lane /newroot/workspaces/exp/injection-bench
mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 tasktmp /newroot/tmp
exec switch_root /newroot /bin/bash /workspaces/exp/injection-bench/src/scripts/vm_guest.sh
INIT
chmod +x "$vm/initrd/init"
mkdir -p "$vm/initrd/proc" "$vm/initrd/sys" "$vm/initrd/dev"
(cd "$vm/initrd" && find . -print0 | cpio --null -o --format=newc | gzip -1 > "$vm/initrd.gz") 2> "$vm/initrd-build.log"
rm -f "$vm/queue/ready.json"
if test -e "$vm/console.log"; then
  cp "$vm/console.log" "$vm/console-$(date -u +%Y%m%dT%H%M%SZ).log"
fi
printf '%s\n' "Starting KVM guest instance=$instance, kernel=$version, memory=4096MiB, CPUs=4"
qemu-system-x86_64 -accel kvm -m 4096 -smp 4 -nographic -no-reboot \
  -kernel "$source_root/boot/vmlinuz-$version" -initrd "$vm/initrd.gz" \
  -append "console=ttyS0 rdinit=/init panic=-1 lsm=lockdown,capability,landlock,yama,apparmor,bpf actplane_vm_instance=$instance" \
  -fsdev local,id=rootfs,path=/,security_model=none,readonly=on \
  -device virtio-9p-pci,fsdev=rootfs,mount_tag=rootfs \
  -fsdev local,id=lane,path="$lane",security_model=none \
  -device virtio-9p-pci,fsdev=lane,mount_tag=lane \
  -fsdev local,id=tasktmp,path=/tmp,security_model=none \
  -device virtio-9p-pci,fsdev=tasktmp,mount_tag=tasktmp \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -pidfile "$vm/qemu.pid" > "$vm/console.log" 2> "$vm/qemu.stderr"

#!/usr/bin/env bash
set -euo pipefail
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
[[ $# == 4 ]] || fail 'Usage: pipeline.sh validate|build debian-13|ubuntu-26.04 cloudstack-kvm|proxmox-lxc /absolute/site.json'
action=$1 profile=$2 target=$3 site=$4
case "$action" in validate|build) ;; *) fail 'Unsupported action.' ;; esac
case "$target" in cloudstack-kvm|proxmox-lxc) ;; *) fail 'Unsupported target.' ;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
for dependency in jq python3 git; do command -v "$dependency" >/dev/null || fail "Missing tool: $dependency"; done
profile_json=$(jq -ce --arg p "$profile" '.[$p] // error("Unsupported profile")' "$repo/builders/profiles.json") || fail 'Unsupported profile.'
[[ "$site" == /* && -f "$site" && ! -L "$site" ]] || fail 'Use an absolute private JSON file.'
site_parent=$(cd -- "$(dirname -- "$site")" && pwd -P)
[[ "$site_parent/" != "$repo/"* ]] || fail 'Site configuration belongs outside the public source tree.'
jq -e -f "$repo/builders/site.schema.jq" "$site" >/dev/null || fail 'Invalid site inputs or unpinned snapshot.'
python3 - "$site" <<'PY'
import datetime, json, sys
data = json.load(open(sys.argv[1]))
snapshot = datetime.datetime.strptime(data['snapshot_id'], '%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc)
if int(snapshot.timestamp()) != data['source_date_epoch']:
    raise SystemExit('source_date_epoch must match the snapshot timestamp')
PY
workspace=$(jq -r .workspace "$site")
mirror=$(jq -r .mirror_url "$site")
security_mirror=$(jq -r .security_mirror_url "$site")
version=$(jq -r .version "$site")
release=$(jq -r .release <<< "$profile_json")
distribution=$(jq -r .distribution <<< "$profile_json")
[[ "$distribution" != ubuntu || "$mirror" == "$security_mirror" ]] || fail 'Ubuntu snapshot must include base, updates, and security suites under one mirror.'
if [[ "$action" == validate ]]; then
  printf '[OK] %s %s %s: inputs valid; live build and acceptance have not run.\n' "$profile" "$target" "$version"
  exit 0
fi
[[ ${GOLDEN_APPLY:-} == build ]] || fail 'Set GOLDEN_APPLY=build only after approval of the dedicated YOW builder.'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 && $EUID == 0 ]] || fail 'Builds require root on the dedicated amd64 Linux builder.'
[[ ! -e /etc/pve ]] || fail 'Never run the active pipeline on a Proxmox host.'
export PATH=/opt/zs-golden-images/venv/bin:/opt/zs-golden-images/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PYTHONDONTWRITEBYTECODE=1
python3 - "$workspace" <<'PY'
import json, os, pathlib, stat, sys
workspace = pathlib.Path(sys.argv[1])
marker = pathlib.Path('/etc/zs-golden-images/builder.json')
for path in [marker, *marker.parents, workspace, *workspace.parents]:
    st = path.lstat()
    if path.is_symlink() or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise SystemExit('Builder paths must be root-owned without symlinks or group/other writes')
data = json.loads(marker.read_text())
if data.get('purpose') != 'isolated-image-builder' or data.get('region') != 'yow' or data.get('workspace') != str(workspace):
    raise SystemExit('Dedicated YOW builder marker does not match workspace')
PY
source_status=$(git -C "$repo" status --porcelain --untracked-files=all) || fail 'Cannot verify source checkout.'
[[ -z "$source_status" ]] || fail 'Live builds require a clean committed source checkout.'
source_commit=$(git -C "$repo" rev-parse HEAD)
for dependency in curl sha256sum flock debootstrap gpg gpgv unshare mount; do command -v "$dependency" >/dev/null || fail "Missing builder tool: $dependency"; done
python3 - "$repo/builders/pins.json" "$repo/ansible/requirements-builder.lock" "$repo/ansible/roles/builder/files" <<'PY'
import hashlib, importlib.util, json, pathlib, stat, subprocess, sys
record = pathlib.Path('/etc/zs-golden-images/toolchain.json')
st = record.lstat()
if record.is_symlink() or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
    raise SystemExit('Toolchain manifest must be root-owned mode 0600')
installed = json.loads(record.read_text())
expected = json.load(open(sys.argv[1]))
if hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest() != installed.get('python_lock_sha256'):
    raise SystemExit('Installed Python dependency lock does not match reviewed source')
freeze = subprocess.check_output(['/opt/zs-golden-images/venv/bin/python', '-m', 'pip', 'freeze', '--all'])
if hashlib.sha256(freeze).hexdigest() != installed.get('python_inventory_sha256'):
    raise SystemExit('Installed Python dependency inventory changed since bootstrap')
collection_files = pathlib.Path(sys.argv[3])
spec = importlib.util.spec_from_file_location('collection_integrity', collection_files / 'collection_integrity.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
pins = json.loads((collection_files / 'collections.json').read_text())
if module.inventory('/opt/zs-golden-images/collections', pins) != installed.get('collections'):
    raise SystemExit('Installed Ansible collections differ from the reviewed toolchain')
for name, path in {
    'diskimage_builder': '/opt/zs-golden-images/venv/bin/disk-image-create',
    'distrobuilder': '/opt/zs-golden-images/bin/distrobuilder',
}.items():
    if installed.get(name) != expected[name]:
        raise SystemExit('Installed builder provenance does not match source pins')
    binary = pathlib.Path(path)
    for parent in [binary, *binary.parents]:
        info = parent.lstat()
        if parent.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise SystemExit('Builder executable path must be root-owned and protected')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != installed.get('executables', {}).get(name):
        raise SystemExit('Builder executable does not match its installation record')
PY
[[ -e "/usr/share/debootstrap/scripts/$release" ]] || fail 'Installed debootstrap must natively support the requested release.'
case "$distribution" in
  debian) archive_keyring=/usr/share/keyrings/debian-archive-keyring.gpg ;;
  ubuntu) archive_keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg ;;
esac
[[ -s "$archive_keyring" && -r "$archive_keyring" ]] || fail 'Install the requested distribution archive keyring before building.'
umask 077
exec 9> "$workspace/.build.lock"
flock -n 9 || fail 'Another image build owns the dedicated builder lock.'
run="$workspace/$profile-$target-$version"
[[ ! -e "$run" && ! -L "$run" ]] || fail 'Version workspace already exists; retain it and choose a new version.'
mkdir -- "$run"
mkdir -- "$run/tmp" "$run/cache" "$run/output"
jq -S '{snapshot_id,mirror_url,security_mirror_url,source_date_epoch,inrelease_sha256}' "$site" > "$run/sources.json"
source_sha=$(sha256sum "$run/sources.json" | awk '{print $1}')
jq -n --arg profile "$profile" --arg target "$target" --arg version "$version" --arg commit "$source_commit" --arg sha "$source_sha" --arg url "$mirror" \
  '{profile:$profile,target:$target,image_version:$version,source_commit:$commit,source_kind:"apt-snapshot",source_image_sha256:$sha,source_manifest_sha256:$sha,source_image_url:$url}' > "$run/metadata.json"
verify_sources() {
  local suite url expected
  for suite in base updates security; do
    case "$suite" in
      base) url="$mirror/dists/$release/InRelease" ;;
      updates) url="$mirror/dists/$release-updates/InRelease" ;;
      security) url="$security_mirror/dists/$release-security/InRelease" ;;
    esac
    curl --fail --silent --show-error --proto '=https' --proto-redir '=https' --location --connect-timeout 15 --max-time 120 "$url" -o "$run/$suite.InRelease"
    expected=$(jq -r --arg s "$suite" '.inrelease_sha256[$s]' "$site")
    [[ $(sha256sum "$run/$suite.InRelease" | awk '{print $1}') == "$expected" ]] || fail "Snapshot metadata changed: $suite"
    gpgv --keyring "$archive_keyring" "$run/$suite.InRelease" >/dev/null 2>&1 || fail "Snapshot metadata signature is not trusted: $suite"
  done
}
verify_sources
mkdir -- "$run/gnupg"
chmod 0700 "$run/gnupg"
gpg --batch --homedir "$run/gnupg" --no-default-keyring --keyring "$archive_keyring" --armor --export > "$run/archive-keys.asc"
[[ -s "$run/archive-keys.asc" ]] || fail 'Distribution archive keyring contains no exportable trusted keys.'
components=$(jq -r '.components|join(",")' <<< "$profile_json")
epoch=$(jq -r .source_date_epoch "$site")
if [[ "$target" == cloudstack-kvm ]]; then
  # DIB invokes sudo -E in its host hooks; sudo-rs can ignore -E.
  sudo_binary=/usr/bin/sudo
  [[ ! -x /usr/bin/sudo.ws ]] || sudo_binary=/usr/bin/sudo.ws
  [[ -x "$sudo_binary" ]] || fail 'Install classic sudo for diskimage-builder.'
  mkdir -- "$run/host-bin"
  ln -s -- "$sudo_binary" "$run/host-bin/sudo"
  export PATH="$run/host-bin:$PATH"
  # Expand these variables in sudo's child, not in this shell.
  # shellcheck disable=SC2016
  env -i "PATH=$PATH" ARCH=amd64 "SOURCE_DATE_EPOCH=$epoch" sudo -n -E /bin/sh -c \
    '[ "$ARCH" = amd64 ] && [ "$SOURCE_DATE_EPOCH" = "$1" ]' sh "$epoch" \
    || fail 'diskimage-builder requires sudo -E to preserve its build environment.'
fi
common_env=(env -i "PATH=$PATH" PYTHONDONTWRITEBYTECODE=1 HOME=/root LANG=C.UTF-8 ANSIBLE_COLLECTIONS_PATH=/opt/zs-golden-images/collections "TMPDIR=$run/tmp" "TMP_DIR=$run/tmp" "SOURCE_DATE_EPOCH=$epoch" GOLDEN_APPLY=build)
if [[ "$target" == cloudstack-kvm ]]; then
  dib=/opt/zs-golden-images/venv/bin/disk-image-create
  expected_version=$(jq -r .diskimage_builder.version "$repo/builders/pins.json")
  [[ $("$dib" --version) == "$expected_version" ]] || fail 'Unexpected diskimage-builder version.'
  apt_sources=$(printf 'default:deb [check-valid-until=no] %s %s %s\nupdates:deb [check-valid-until=no] %s %s-updates %s\nsecurity:deb [check-valid-until=no] %s %s-security %s\n' "$mirror" "$release" "${components//,/ }" "$mirror" "$release" "${components//,/ }" "$security_mirror" "$release" "${components//,/ }")
  "${common_env[@]}" "DIB_RELEASE=$release" "DIB_DISTRIBUTION_MIRROR=$mirror" "DIB_DEBIAN_SECURITY_MIRROR=$security_mirror" \
    "DIB_APT_SOURCES_CONF=$apt_sources" "DIB_DEBIAN_COMPONENTS=$components" DIB_UBUNTU_MIRROR_DISTS=updates,security \
    "DIB_DEBIAN_DEBOOTSTRAP_SCRIPT=/usr/share/debootstrap/scripts/$release" "DIB_DEBOOTSTRAP_EXTRA_ARGS=--include=ca-certificates --force-check-gpg --keyring=$archive_keyring" \
    "DIB_IMAGE_CACHE=$run/cache" DIB_APT_MINIMAL_CREATE_INTERFACES=0 DIB_DEBUG_TRACE=0 \
    "ELEMENTS_PATH=$repo/builders/diskimage-builder/elements" "ZS_SOURCE=$repo" "ZS_PROFILE=$profile" "ZS_METADATA=$run/metadata.json" \
    "$dib" -a amd64 -t qcow2 --no-tmpfs --image-size 16 -o "$run/output/$profile-$version" \
    "$(jq -r .dib_element <<< "$profile_json")" vm block-device-mbr zs-configure
  artifact="$run/output/$profile-$version.qcow2"
  qemu-img check "$artifact"
else
  distrobuilder=/opt/zs-golden-images/bin/distrobuilder
  expected_version=$(jq -r .distrobuilder.version "$repo/builders/pins.json")
  [[ $("$distrobuilder" --version) == "$expected_version" ]] || fail 'Unexpected distrobuilder version.'
  jq -n --arg distro "$distribution" --arg release "$release" --arg version "$version" --arg mirror "$mirror" --arg security "$security_mirror" --argjson components "$(jq .components <<< "$profile_json")" --rawfile archive_keys "$run/archive-keys.asc" \
    '{image:{distribution:$distro,release:$release,architecture:"x86_64",serial:$version,variant:"default"},
      source:{downloader:"debootstrap",url:$mirror,variant:"minbase",components:$components,skip_verification:false,keys:[$archive_keys]},
      mappings:{architecture_map:"debian"},
      packages:{manager:"apt",update:true,cleanup:true,
        repositories:[{name:"sources.list",url:("deb [check-valid-until=no] " + $mirror + " " + $release + " " + ($components|join(" ")) + "\ndeb [check-valid-until=no] " + $mirror + " " + $release + "-updates " + ($components|join(" ")) + "\ndeb [check-valid-until=no] " + $security + " " + $release + "-security " + ($components|join(" ")))}],
        sets:[{packages:["ca-certificates"],action:"install",early:true},{packages:["python3","systemd-sysv"],action:"install"}]},
      targets:{lxc:{config:[{type:"all",after:4,content:"lxc.include = LXC_TEMPLATE_CONFIG/common.conf\nlxc.arch = x86_64"},{type:"user",after:4,content:"lxc.include = LXC_TEMPLATE_CONFIG/userns.conf"}]}}}' > "$run/lxc.json"
  "${common_env[@]}" "$distrobuilder" build-dir "$run/lxc.json" "$run/rootfs" --cache-dir "$run/cache"
  "${common_env[@]}" unshare --mount --propagation private --fork "$repo/scripts/configure-lxc-rootfs.sh" "$profile" "$run/rootfs" "$run/metadata.json"
  jq -f "$repo/builders/distrobuilder/pack.jq" "$run/lxc.json" > "$run/lxc-pack.json"
  "${common_env[@]}" "$distrobuilder" pack-lxc "$run/lxc-pack.json" "$run/rootfs" "$run/output" --compression xz --cache-dir "$run/cache"
  artifact="$run/output/rootfs.tar.xz"
  tar -tJf "$artifact" > "$run/archive-members.txt"
fi
verify_sources
[[ -f "$artifact" && ! -L "$artifact" ]] || fail 'Upstream builder did not produce the expected artifact.'
metadata_sha=$(sha256sum "$run/metadata.json" | awk '{print $1}')
jq -se --arg profile "$profile" --arg target "$target" --arg sha "$metadata_sha" \
  -f "$repo/builders/build-phases.schema.jq" \
  "$run/metadata.json.configure.json" "$run/metadata.json.harden.json" "$run/metadata.json.cleanup.json" \
  > "$run/build-phases.json" || fail 'Missing or mismatched successful configure, harden, or cleanup phase evidence.'
artifact_sha=$(sha256sum "$artifact" | awk '{print $1}')
jq -n --arg profile "$profile" --arg target "$target" --arg version "$version" --arg commit "$source_commit" --arg artifact "$artifact" --arg sha "$artifact_sha" \
  --slurpfile phases "$run/build-phases.json" --slurpfile sources "$run/sources.json" --slurpfile builders "$repo/builders/pins.json" --slurpfile toolchain /etc/zs-golden-images/toolchain.json \
  '{schema_version:1,profile:$profile,target:$target,version:$version,source_commit:$commit,artifact:{path:$artifact,sha256:$sha},inputs:{build_phases:$phases[0],sources:$sources[0],builders:$builders[0],toolchain:$toolchain[0]},status:"experimental-unaccepted",reproducibility:"pinned inputs; byte-for-byte reproducibility not established"}' > "$run/candidate.json"
printf '[BLOCKED] Candidate: %s. Live compatibility, security acceptance, signed approval, and release remain required.\n' "$run/candidate.json"
exit 2

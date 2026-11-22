#!/bin/bash -p
set -Eeuo pipefail

# A clean initial launcher is part of the documented TCB. Privileged Bash
# disables imported functions; this diagnostic also rejects supported startup
# injection variables before any repository program is executed.
while IFS= read -r -d '' environment_entry; do
  case $environment_entry in
    BASH_ENV=*|ENV=*|LD_*=*|BASH_FUNC_*%%=*|PYTHONHOME=*|PYTHONPATH=*|\
    PYTHONUSERBASE=*|PYTHONSTARTUP=*|PYTHONINSPECT=*|PYTHONWARNINGS=*|\
    PYTHONBREAKPOINT=*|PYTHONHASHSEED=*|PYTHONSAFEPATH=*)
      environment_name=${environment_entry%%=*}
      printf 'unsupported launcher environment: %s\n' "$environment_name" >&2
      exit 2
      ;;
  esac
done <"/proc/$$/environ"

if (( EUID == 0 )); then
  printf 'kernel builder must run rootless\n' >&2
  exit 2
fi

usage() {
  printf 'usage: %s [build] builder-a|builder-b|canonical | compare | meta-requirements BUILDER | lifecycle-check\n' "$0" >&2
  exit 2
}
case $#:${1-} in
  1:builder-a|1:builder-b|1:canonical)
    supervisor_command=run
    builder_id=$1
    ;;
  2:build)
    supervisor_command=run
    builder_id=$2
    ;;
  1:compare|1:lifecycle-check)
    supervisor_command=$1
    builder_id=canonical
    ;;
  2:meta-requirements)
    supervisor_command=$1
    builder_id=$2
    ;;
  *) usage ;;
esac
case $builder_id in
  builder-a|canonical)
    outer_timezone=UTC
    outer_umask=0022
    ;;
  builder-b)
    outer_timezone=Pacific/Honolulu
    outer_umask=0077
    ;;
  *)
    usage
    ;;
esac

launcher=${BASH_SOURCE[0]}
case $launcher in
  /*) ;;
  *) launcher=$PWD/$launcher ;;
esac
if [[ -L $launcher ]]; then
  printf 'kernel build launcher must not be a symlink\n' >&2
  exit 2
fi
launcher_name=${launcher##*/}
launcher_directory=${launcher%/*}
if [[ $launcher_name != build-kernel.sh ]]; then
  printf 'kernel build launcher name is invalid\n' >&2
  exit 2
fi
if ! cd -P -- "$launcher_directory"; then
  printf 'kernel build launcher directory is unavailable\n' >&2
  exit 2
fi
physical_launcher_directory=$PWD
if [[ $launcher != "$physical_launcher_directory/$launcher_name" ]]; then
  printf 'kernel build launcher path contains a symlink\n' >&2
  exit 2
fi
if ! cd -P -- "$physical_launcher_directory/../.."; then
  printf 'kernel build repository is unavailable\n' >&2
  exit 2
fi
repository=$PWD
launcher=$repository/scripts/gate01/build-kernel.sh
bootstrap=$repository/tools/gate01/kernel_bootstrap.py
if [[ $physical_launcher_directory != "$repository/scripts/gate01" || \
      ! -f $launcher || -L $launcher || ! -f $bootstrap || -L $bootstrap ]]; then
  printf 'kernel build launcher is not in its exact repository location\n' >&2
  exit 2
fi

umask "$outer_umask"
case $supervisor_command in
  run) supervisor_arguments=(run --repo "$repository" "$builder_id") ;;
  compare) supervisor_arguments=(compare --repo "$repository") ;;
  meta-requirements) supervisor_arguments=(meta-requirements --repo "$repository" --builder "$builder_id") ;;
  lifecycle-check) supervisor_arguments=(lifecycle-check --repository "$repository") ;;
  *) usage ;;
esac
readonly builder_id repository launcher bootstrap outer_timezone outer_umask supervisor_command
readonly -a supervisor_arguments
# Opening this fixed descriptor is the documented clean-launch TCB instant.
# The stdlib-only bootstrap proves its executing bytes against the exact held
# repository closure before any repository package can be imported.
exec 60<"$bootstrap"
exec /usr/bin/env -i \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  HOME=/tmp \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  TZ="$outer_timezone" \
  /usr/bin/python3 -I -S -B /proc/self/fd/60 \
  --bootstrap-fd 60 --repository "$repository" -- \
  "${supervisor_arguments[@]}"

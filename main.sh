#!/usr/bin/env bash

source ./utils.sh || { echo "Failed to load utilities module!"; exit 1; }





check_non_root() {
  if [[ $EUID -eq 0 ]]; then
    fmtr::fatal "Do not run as root.\n"
    exit 1
  fi
}




detect_distro() {
  local EXPERIMENTAL=${EXPERIMENTAL:-0}
  local id=""

  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    id=${ID,,}
  fi

  case "$id" in
    arch|manjaro|endeavouros|arcolinux|garuda|artix)
      DISTRO="Arch"
      ;;
    *)
      if command -v pacman >/dev/null 2>&1 && [[ -d /etc/pacman.d ]]; then
        DISTRO="Arch"
      elif (( EXPERIMENTAL )); then
        if command -v apt >/dev/null 2>&1; then
          DISTRO="Debian"
        elif command -v zypper >/dev/null 2>&1; then
          DISTRO="openSUSE"
        elif command -v dnf >/dev/null 2>&1; then
          DISTRO="Fedora"
        else
          fmtr::fatal "${id:-Unknown} distro isn't supported."
        fi
      else
        fmtr::fatal "${id:-Unknown} distro isn't supported (Arch only)."
      fi
      ;;
  esac

  export DISTRO
  readonly DISTRO
}





cpu_detect() {
  local cpuinfo
  cpuinfo=$(</proc/cpuinfo)

  case "$cpuinfo" in
    *GenuineIntel*)
      CPU_VENDOR_ID="GenuineIntel"
      CPU_VIRTUALIZATION="vmx"
      CPU_MANUFACTURER="Intel"
      ;;
    *AuthenticAMD*)
      CPU_VENDOR_ID="AuthenticAMD"
      CPU_VIRTUALIZATION="svm"
      CPU_MANUFACTURER="AMD"
      ;;
    *)
      fmtr::fatal "Unsupported CPU vendor"
      ;;
  esac

  export CPU_VENDOR_ID CPU_VIRTUALIZATION CPU_MANUFACTURER
  readonly CPU_VENDOR_ID CPU_VIRTUALIZATION CPU_MANUFACTURER
}





main_menu() {
  # Option labels and corresponding module scripts (empty = not ready)
  declare -A menu=(
    [1]="Virtualization Setup|virtualization.sh"
    [2]="QEMU (Patched) Setup|qemu.sh"
    [3]="EDK2 (Patched) Setup|edk2.sh"
    [4]="GPU Passthrough Setup|vfio.sh"
    [5]="Kernel (Patched) Setup|"
    [6]="Looking Glass Setup|"
    [7]="Deploy Auto/Unattended XML|deploy.sh"
  )

  local EXIT_OPTION="Exit"

  while :; do
    clear
    fmtr::box_text " >> AutoVirt << "; echo ""

    # Print menu
    for i in "${!menu[@]}"; do
      local label="${menu[$i]%%|*}"
      printf '  %b[%d]%b %s\n' "$TEXT_BRIGHT_YELLOW" "$i" "$RESET" "$label"
    done
    printf '\n  %b[0]%b %s\n\n' "$TEXT_BRIGHT_RED" "$RESET" "$EXIT_OPTION"

    # Prompt
    local choice
    choice="$(prmt::quick_prompt '  Enter your choice [0-7]: ')" || continue
    clear

    if [[ $choice == 0 ]]; then
      prmt::yes_or_no "$(fmtr::ask 'Do you want to clear the logs directory?')" &&
        rm -f -- "${LOG_PATH}"/*.log
      exit 0
    fi

    # Validate selection
    if [[ -n "${menu[$choice]}" ]]; then
      local label="${menu[$choice]%%|*}"
      local script="${menu[$choice]#*|}"

      fmtr::box_text "$label"
      if [[ -n "$script" ]]; then
        ./modules/"$script"
      else
        fmtr::warn "This module isn't ready yet."
      fi
    else
      fmtr::error "Invalid option, please try again."
    fi

    prmt::quick_prompt "$(fmtr::info 'Press any key to continue...')"
  done
}





main() {
  check_non_root
  detect_distro
  cpu_detect
  main_menu
}

main

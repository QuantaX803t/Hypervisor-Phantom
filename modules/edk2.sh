build_ovmf() {
  # --- Phase 1: Build Environment & Compilation ---
  fmtr::info "Initializing build environment..."

  export WORKSPACE="$(pwd)"
  export EDK_TOOLS_PATH="$WORKSPACE/BaseTools"
  export CONF_PATH="$WORKSPACE/Conf"

  if [[ ! -d BaseTools/Build ]]; then
    make -C BaseTools -j"$(nproc)" &>>"$LOG_FILE" || {
      fmtr::fatal "BaseTools build failed"; return 1;
    }
  fi

  source edksetup.sh &>>"$LOG_FILE" || {
    fmtr::fatal "edksetup.sh failed"; return 1;
  }

  build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b RELEASE -n 0 -s \
    -D SECURE_BOOT_ENABLE=TRUE -D SMM_REQUIRE=TRUE \
    -D TPM1_ENABLE=TRUE -D TPM2_ENABLE=TRUE &>>"$LOG_FILE" || {
      fmtr::fatal "OVMF build failed"; return 1;
    }

  # --- Phase 2: Variable Extraction & NVRAM Injection ---
  local efivars_json name guid path full_hex attr sep=""
  local -r build_fv="Build/OvmfX64/RELEASE_GCC5/FV"
  local -r EFI_GLOBAL_VARIABLE=8be4df61-93ca-11d2-aa0d-00e098032b8c
  local -r EFI_IMAGE_SECURITY_DATABASE_GUID=d719b2cb-3d3a-4596-a3bc-dad00e67656f
  local -a keys=(
    "PK:$EFI_GLOBAL_VARIABLE"               "KEK:$EFI_GLOBAL_VARIABLE"
    "db:$EFI_IMAGE_SECURITY_DATABASE_GUID"  "dbx:$EFI_IMAGE_SECURITY_DATABASE_GUID"
    "PKDefault:$EFI_GLOBAL_VARIABLE"        "KEKDefault:$EFI_GLOBAL_VARIABLE"
    "dbDefault:$EFI_GLOBAL_VARIABLE"        "dbxDefault:$EFI_GLOBAL_VARIABLE"
  )

  efivars_json="$(mktemp)" || return 1
  trap 'rm -f "$efivars_json"' RETURN

  fmtr::info "Extracting host EFI keys..."

  {
    printf '{\n    "version": 2,\n    "variables": [\n'

    for entry in "${keys[@]}"; do
      IFS=: read -r name guid <<< "$entry"
      path="/sys/firmware/efi/efivars/${name}-${guid}"
      [[ -f "$path" ]] || continue

      full_hex=$(hexdump -ve '1/1 "%.2x"' "$path" 2>/dev/null) || continue
      attr=$(printf '%d' "0x${full_hex:6:2}${full_hex:4:2}${full_hex:2:2}${full_hex:0:2}")

      printf '%s        { "name": "%s", "guid": "%s", "attr": %d, "data": "%s" }' \
          "$sep" "$name" "$guid" "$attr" "${full_hex:8}"
      sep=$',\n'
    done

    printf '\n    ]\n}\n'
  } > "$efivars_json"

  fmtr::info "Populating OVMF NVRAM..."

  $ROOT_ESC cp "$build_fv/OVMF_CODE.fd" "$OUT_DIR/firmware/OVMF_CODE.fd" || return 1

  $ROOT_ESC virt-fw-vars \
    --input "$build_fv/OVMF_VARS.fd" \
    --output "$OUT_DIR/firmware/OVMF_VARS.fd" \
    --secure-boot \
    --set-json "$efivars_json" &>>"$LOG_FILE" || {
      fmtr::fatal "NVRAM injection failed"; return 1;
    }

  fmtr::log "Secure Boot provisioning complete."
}

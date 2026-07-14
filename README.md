<div align="center">

# AutoVirt

This project automates complex Linux virtualization tasks.

[![](https://dcbadge.limes.pink/api/server/https://discord.gg/hNVHChp7PX)](https://discord.gg/hNVHChp7PX)

</div>

---






## Instructions

<details>
<summary>Expand for details...</summary>

#### 1. Clone Git repository
```sh
git clone --single-branch --depth=1 https://github.com/Scrut1ny/AutoVirt
```

#### 2. Change directory
```sh
cd AutoVirt/
```

#### 3. Execute
```sh
./main.sh
```
- Experimental distro support:
```sh
EXPERIMENTAL=1 ./main.sh
```

---

### 4. Update repository
- ***Make sure you're in the `AutoVirt/` root directory when running the command below!***
```sh
git fetch --all && git reset --hard origin/main
```

</details>





---

## Supported Distros

| Distro         | Status       |
|----------------|--------------|
| Arch based     | Supported    |
| Debian based   | Experimental |
| Fedora based   | Experimental |
| openSUSE based | Experimental |

## Prerequisites

- `git` package
- Supported Linux distribution
- UEFI/BIOS Settings:
 - CPU virtualization extensions (VT-x / AMD-V)
 - IOMMU support (VT-d / AMD-Vi)
 - **IMPORTANT** - Disable `Pre-boot DMA Protection`
  - (*Change `IOMMU` from `[Auto]` to `[Enabled]` to find hidden setting*)
- A dGPU for passthrough (recommended)






---

<a href="https://www.star-history.com/#Scrut1ny/AutoVirt&type=date&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Scrut1ny/AutoVirt&type=date&theme=dark&legend=bottom-right" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Scrut1ny/AutoVirt&type=date&legend=bottom-right" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Scrut1ny/AutoVirt&type=date&legend=bottom-right" />
 </picture>
</a>

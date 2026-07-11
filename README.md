<div align="center">

# AutoVirt

This project automates complex Linux virtualization tasks,
including GPU passthrough setup, VM configuration, and VFIO binding.

[![](https://dcbadge.limes.pink/api/server/https://discord.gg/hNVHChp7PX)](https://discord.gg/hNVHChp7PX)

</div>

---

## Supported Distros

| Distro | Status |
|--------|--------|
| Arch Linux / Manjaro / EndeavourOS / Garuda | Supported |
| Debian / Ubuntu / Linux Mint / Pop!_OS | Experimental (`EXPERIMENTAL=1`) |
| Fedora / CentOS / RHEL / Rocky | Experimental (`EXPERIMENTAL=1`) |
| openSUSE / SLES | Experimental (`EXPERIMENTAL=1`) |

## Prerequisites

- A supported Linux distribution
- CPU with virtualization extensions (VT-x / AMD-V)
- IOMMU support enabled in BIOS (VT-d / AMD-Vi)
- A secondary GPU for passthrough (recommended)
- `git` installed
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

<a href="https://www.star-history.com/#Scrut1ny/AutoVirt&type=date&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Scrut1ny/AutoVirt&type=date&theme=dark&legend=bottom-right" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Scrut1ny/AutoVirt&type=date&legend=bottom-right" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Scrut1ny/AutoVirt&type=date&legend=bottom-right" />
 </picture>
</a>

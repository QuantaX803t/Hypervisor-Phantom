## 📖 Manual Development

<details>
<summary>Expand for more...</summary>

## QEMU

#### Clone repo
```
git clone --depth=1 --branch "v11.0.0" "https://gitlab.com/qemu-project/qemu.git"
```

#### Git diff patched repo
```
git add .

git diff HEAD > "v11.0.0.patch"
```

#### Patch repo
```
git apply < "v11.0.0.patch"
```

## EDK2

#### Clone repo
```
git clone --depth=1 --branch "edk2-stable202602" "https://github.com/tianocore/edk2.git"
```

#### Git diff patched repo
```
git diff HEAD > "edk2-stable202602.patch"
```

#### Patch repo
```
git apply < "edk2-stable202602.patch"
```

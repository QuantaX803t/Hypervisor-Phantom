## 📖 Manual Development

<details>
<summary>Expand for more...</summary>





---





## QEMU

#### clone
```
git clone --depth=1 --branch "v11.0.0" "https://github.com/qemu/qemu.git"
```

#### diff
```
git add .

git diff HEAD > "v11.0.0.patch"
```

#### patch
```
git apply < "v11.0.0.patch"
```





---





## EDK2

#### clone
```
git clone --depth=1 --branch "edk2-stable202602" "https://github.com/tianocore/edk2.git"
```

#### diff
```
git diff HEAD > "edk2-stable202602.patch"
```

#### patch
```
git apply < "edk2-stable202602.patch"
```





---





## SWTPM

#### clone
```
git clone --depth=1 --branch "v0.10.1" "https://github.com/stefanberger/swtpm.git"
```

#### diff
```
git add .

git diff HEAD > "v0.10.1.patch"
```

#### patch
```
git apply < "v0.10.1.patch"
```





---

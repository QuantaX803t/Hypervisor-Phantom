## 📖 Manual Development

<details>
<summary>Expand for more...</summary>





---





## QEMU

#### clone
```sh
git clone --depth=1 --branch "v11.0.0" "https://github.com/qemu/qemu.git"
```

#### diff
```sh
git add .

git diff HEAD > "v11.0.0.patch"
```

#### patch
```sh
git apply < "v11.0.0.patch"
```





---





## EDK2

#### clone
```sh
git clone --depth=1 --branch "edk2-stable202602" "https://github.com/tianocore/edk2.git"
```

#### diff
```sh
git diff HEAD > "edk2-stable202602.patch"
```

#### patch
```sh
git apply < "edk2-stable202602.patch"
```





---





## LIBTPMS

#### clone
```sh
git clone --depth=1 --branch "v0.10.2" "https://github.com/stefanberger/libtpms.git"
```

#### diff
```sh
git add .

git diff HEAD > "v0.10.2.patch"
```

#### patch
```sh
git apply < "v0.10.2.patch"
```

#### building
```sh
autoreconf -i
./configure
make -j"$(nproc)"
```

#### cleanup
```sh
make clean
make distclean
```






--- 







## SWTPM

#### clone
```sh
git clone --depth=1 --branch "v0.10.1" "https://github.com/stefanberger/swtpm.git"
```

#### diff
```sh
git add .

git diff HEAD > "v0.10.1.patch"
```

#### patch
```sh
git apply < "v0.10.1.patch"
```







---

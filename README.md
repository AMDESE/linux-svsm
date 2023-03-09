# Linux SVSM (Secure VM Service Module)

## Table of contents

1. [What is this magic?](#introduction)
2. [Preparing the host](#host)
3. [Installation](#install)
4. [Running Linux SVSM](#run)
5. [Contribution](#contribute)
6. [Authors and License](#authors)

## What is this magic? <a name="introduction"></a>

Linux SVSM (Secure VM Service Module) implements a guest communication
interface so that VM guests can offload sensitive operations (for example,
updating access permissions on protected pages) onto a privileged\* guest
acting as service module. Linux SVSM relies on AMD's Secure Nested Paging
(SNP) and prior Secure Encrypted Virtualization technologies (See
[SEV documentation](https://developer.amd.com/sev/)).

The idea is that Linux SVSM will not only offload security operations,
but will also be able to provide other services such as live VM migration;
the privilege separation model of SVSM permits the existence of a virtual
Trusted Platform Module (virtual TPM).

\* AMD SNP introduces the Virtual Machine Privilege Level (VMPLs) for
enhanced security control. VMPL0 is the highest level of privilege.
Linux SVSM runs at VMPL 0, as opposed to other guests running under
VMPL >=1. Certain operations become architecturally impossible to guests
running at lower privilege levels (e.g. use of the PVALIDATE instruction
and certain forms of RMPADJUST).

Generate and read source code documentation with:

```
# make doc
```

which will also install necessary prerequisites.

## Preparing the host <a name="host"></a>

Linux SVSM assumes a host with support for AMD's SEV-SNP, as well as
compatible guest, Qemu and OVMF BIOS. We provide bash scripts to automate
the installation process of these prerequisites. The remainder of these
instructions were tested on Ubuntu 22.04 server, installed with kernel
5.15.0-46-generic.

Start by verifying that the following BIOS settings are enabled. The
settings may vary depending on the vendor BIOS. The menu options below are
from AMD's BIOS.

```
  CBS -> CPU Common ->
                SEV-ES ASID space Limit Control -> Manual
                SEV-ES ASID space limit -> 100
                SNP Memory Coverage -> Enabled
                SMEE -> Enabled
      -> NBIO common ->
                SEV-SNP -> Enabled
```

We now need to build the host and guest kernels, Qemu and OVMF BIOS used for
launching the SEV-SNP guest.

```
$ cd scripts/
$ ./build.sh --package
```

If build fails, read subsection [Build troubleshooting](#trouble-build). On
successful build, the binaries will be available in `snp-release-<DATE>`.

Now we need to install the Linux kernel on the host machine:

```
$ cd snp-release-<date>
$ sudo ./install.sh
```

Reboot the machine and choose SNP Host kernel from the grub menu. You can
check you have a kernel with the proper SNP support with:

```
$ sudo dmesg | grep SEV
[    7.393321] SEV-SNP: RMP table physical address 0x0000000088a00000 - 0x00000000a8ffffff
[   18.958687] ccp 0000:22:00.1: SEV firmware update successful
[   21.081484] ccp 0000:22:00.1: SEV-SNP API:1.51 build:3
[   21.286378] SEV supported: 255 ASIDs
[   21.290367] SEV-ES and SEV-SNP supported: 254 ASIDs
```

### Build troubleshooting <a name="trouble-build"></a>

The most likely source of build errors is missing a tool. Try installing
the following:

```
$ sudo apt install make ninja-build libglib2.0-dev libpixman-1-dev python3
$ sudo apt install nasm iasl flex bison libelf-dev libssl-dev
```

If your error is during OVMF's compilation, you can try getting a verbose
form of the error, running manually with -v. In our case:

```
$ cd ovmf
$ source edksetup.sh
$ nice build -v -q --cmd-len=64436 -DDEBUG_ON_SERIAL_PORT -n 32 -t GCC5 -a X64 -p OvmfPkg/OvmfPkgX64.dsc
```

If your error involves still not finding Python, you may try to replace `python`
with `python3` in the file `BaseTools/Tests/GNUmakefile` of the `ovmf` folder
that you have just cloned.

## Installation <a name="install"></a>

Linux SVSM requires the Rust nightly tool-chain, as well as components that
can be downloaded from rustup. The process can be automated with:

```
# make prereq
```

You can select default installation for rustup. After that, make sure rust-lld
can be found in your PATH. You can edit your ~/.bashrc with:

```
export PATH="/(YOUR PATH)/rustlib/x86_64-unknown-linux-gnu/bin/:$PATH"
```

To build:

```
# make
```

To build with serial output progress information, for debugging:

```
# make FEATURES=verbose
```

You should NEVER have to specify the cargo target, as we have
.cargo/config.toml. The Makefile includes a basic clean target. To
force prerequisites re-installation on the next execution of make do:

```
# make superclean
```

## Running Linux SVSM <a name="run"></a>

The building process will generate svsm.bin that can be passed to Qemu (svsm
parameter). Inside directory scripts/ we provide launch-qemu.sh to ease the
execution of the Qemu virtual machine. First, we need an empty virtual disk
image and distribution (in our example, Ubuntu):

```
# qemu-img create -f qcow2 guest.qcow2 30G
# wget <link-to-iso> ubuntu.iso
```

Once we have an image prepared, we can boot with the command below. In the
Grub option of installation, you can edit the linux kernel command adding
'console=tty0 console=ttyS0,115200n8' and then Ctr+X.

```
# ./launch-qemu.sh -hda guest.qcow2 -cdrom ubuntu.iso
```

after that, we can simply boot and install the kernel \*.debs/\*.rpms from
within the guest VM.

```
[host@snp-host ~]#  ./launch-qemu.sh -hda guest.qcow2
[guest@snp-guest ~]# scp host@ip:/<dir>/scripts/linux/<version>*guest*.deb .
[guest@snp-guest ~]# chmod +x *.deb && dpkg -i *.deb
[guest@snp-guest ~]# reboot
```

Finally, we will have to execute the script again, this time providing the
SVSM binary. Once the SVSM guest is up, you can check it is running on
VMPL1 (lower privilege level) with:

```
[host@snp-host ~]#  ./launch-qemu.sh -hda guest.qcow2 -sev-snp -svsm svsm.bin
[guest@snp-guest ~]# dmesg | grep VMPL
[    1.264552] SEV: SNP running at VMPL1.
```

By default, SVSM lives at 512 GB (SVSM\_GPA), and has 256 MB of memory
(SVSM\_MEM). This can be changed at compilation. For example:

```
# make SVSM_GPA=0x90000000 SVSM_MEM=0x20000000
```

The SVSM page table applies an offset to its virtual addresses.

## Contribution <a name="contribute"></a>

Please read CONTRIBUTING.md for instructions on contribution and style.

## Authors and License <a name="authors"></a>

The original authors and maintainers of this software are:

- [Thomas Lendacky](https://github.com/tlendacky)
- [Carlos Bilbao](https://github.com/Zildj1an)

and they will act as reviewers for future contributions.

Other developers have made substantial contributions to this project, to
obtain the full list, please refer to the [Contributors](https://github.com/AMDESE/linux-svsm/graphs/contributors)
page or review the authorship information in the project's source code
headers.

Linux SVSM is distributed under the MIT license. For more information, read
file LICENSE. To obtain information about the crates that Linux SVSM
depends on, you can run:

```
$./scripts/crates.sh
```

# Welcome to the Underhill HCL!

## Downloading the binary from the artifact storage
You don't have to clone and build as it might be more convenient to download the binaries from the artifact storage.
For that, you'll need the [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)
```bash
az login
# OR
# 	az login --use-device-code
# OR
# 	Create Personal Access token:
# 	https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&viewFallbackFrom=vsts 
#
#	export AZURE_DEVOPS_EXT_PAT=PAT

az extension add --name azure-devops
az devops configure -d project=LSG-linux
az devops configure -d organization=https://msazure.visualstudio.com

az pipelines runs artifact download --artifact-name drop_linux_stage_linux_dom0_hyperv --run-id 39058039 --path hcl_downloads 
```

## Setting up the development environment

WSL2 is the most convenient platform for development.
Packages you'll need: 
```bash
# Building the kernel (required)
sudo apt-get install -y build-essential flex bison libelf-dev bc

# Buidling the init process image (required)
sudo apt-get install -y libklibc-dev musl-tools execstack

# Manual pages
sudo apt-get install -y manpages-posix manpages-dev man-db

# Various utilities that are not required but may be of some help and covinience
sudo apt-get install -y socat gdb golang python3 mc tmux screen

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-unknown-linux-musl

# To build Rust code:
cargo build --release --target x86_64-unknown-linux-musl

# To build hvlite
cargo build --release --features underhill --target x86_64-unknown-linux-musl
```

To relay data between named pipes and WSL, there is [NPipeRelay](https://github.com/jstarks/npiperelay).

## Running Underhill HCL VMs
1. Run `build-hcl-kernel.sh` to produce the initial RAM FS.
That will create the kernel images `build/vmlinux` (and `build/vmlinux.unstripped`
with the debug information inside it). 

In the case, you are using the package that already contains the kernel, might need to
only inject `hvlite` and `hcl-init` into it. Please run
```bash
./update-rootfs.py ./vmlinux-dev ./hcl-init ./hvlite ./vmlinux-hvlite
```
To start the shell, please add `--interactive` to the command line. Then you can
start `hvlite`:
```bash
hvlite --uefi --underhill &
```
With the command line option `--debug`, the script will build
an initial RAM FS that starts `gdbserver` attached to `hvlite`.

For building the IGVM file, please use the updated image `./vmlinux-hvlite`

2. Copy out `./vmlinux-hvlite` from the `build` directory to the machine that will run the VM.

3. Create the VM with 
```powershell
New-TestVm -VmName <VMNAME> -GuestIsolation None
```
Currently, running with up to 64 CPUs has been tested.

4. Use the `setup_uh.ps1` script fropm the VM repo to configure the VM. Its parameters have to provide
full paths to `vmlinux-hvlite` and the name of the VM. Optionally, you can specify the path to the UEFI image. 
The script will produce an IGVM file, store it to the `%SystemRoot%\System32` directory, and configure the VM
use it an an HCL.

5. For the serial console logging, you'll need to build a private `vmserial.dll`.
In the file `SerialControllerDevice.cpp` from the `official/rs_onecore_base2_hyp` branch,
set `m_HclMode = false` in `SerialControllerDevice::Initialize`.

The console will be available on the COM3 port, and the kernel debugger on COM4.
Here is an example of how to start named pipe relays to make them available inside WSL:
```bash
# Console
exec socat PTY,link="./con" SYSTEM:"while npiperelay.exe -p -ei //./pipe/HclVm00-com3; do true; done" &
# GDB attched
exec socat PTY,link="./gdb" SYSTEM:"while npiperelay.exe -p -ei //./pipe/HclVm00-com4; do true; done" &
```

![The dev. environment](./notes/dev-setup.png "The dev. environment")

![UEFI PEI verbose logging](./notes/dev-setup-kgdb-pei.png "UEFI PEI verbose logging")
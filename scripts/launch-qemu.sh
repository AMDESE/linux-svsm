# SPDX-License-Identifier: MIT
#!/bin/bash

#
# user changeable parameters
#
HDA_FILE=""
HDB_FILE=""
CPU="EPYC-v4"
CPU_FEATURES=""
MEM="4G"
MAX_MEM=""
SMP_NCPUS="4"
MAX_NCPUS=""
SEV_GUEST=""
SEV_ES_GUEST=""
SEV_SNP_GUEST=""
SVSM=""
CONSOLE="serial"
UEFI_BIOS_CODE="./usr/local/share/qemu/OVMF_CODE.fd"
UEFI_BIOS_VARS="./usr/local/share/qemu/OVMF_VARS.fd"
BIOS_DEBUG=""
VNC_PORT=""
ALLOW_DEBUG=""
USE_VIRTIO="1"
BRIDGE=""
SEV_POLICY=""
SNP_FLAGS="0"

QEMU_INSTALL_DIR="./usr/local/bin/"

usage() {
	echo "$0 [options]"
	echo "Available <commands>:"
	echo " -hda          hard disk ($HDA_FILE)"
	echo " -hdb          hard disk ($HDB_FILE)"
	echo " -cpu          CPU model to use ($CPU)"
	echo " -cpu-features CPU features to add/remove (e.g. '-fsgsbase,+ibpb')"
	echo " -sev          enable SEV support"
	echo " -sev-es       enable SEV-ES support"
	echo " -sev-snp      enable SEV-SNP support"
	echo " -svsm         SVSM binary (for use with SEV-SNP)"
	echo " -sev-policy   policy to use for SEV (SEV=0x01, SEV-ES=0x41, SEV-SNP=0x30000)"
	echo " -snp-flags    SEV-SNP initialization flags (0 is default)"
	echo " -mem          guest memory (must specify M or G suffix)"
	echo " -smp          number of cpus"
	echo " -maxcpus      maximum number of cpus"
	echo " -console      display console to use (serial or graphics)"
	echo " -vnc          VNC port to use"
	echo " -bios         use a specific bios code file (default is ./OVMF_CODE.fd)"
	echo " -bios-vars    use a specific bios vars file (default is ./OVMF_VARS.fd)"
	echo " -bios-debug   use the bios debug port (0x402)"
	echo " -kernel       kernel to use"
	echo " -initrd       initrd to use"
	echo " -append       kernel command line arguments to use"
	echo " -noauto       do not autostart the guest"
	echo " -cdrom        CDROM image"
	echo " -allow-debug  allow debugging the VM"
	echo " -bridge       use the specified bridge device for networking"
	echo " -novirtio     do not use virtio devices"
	exit 1
}

add_opts() {
	echo -n "$* " >> ${QEMU_CMDLINE}
}

run_cmd () {
	$*
	if [ $? -ne 0 ]; then
		echo "command $* failed"
		exit 1
	fi
}

stop_network() {
	if [ "$GUEST_TAP_NAME" = "" ]; then
		return
	fi
	run_cmd "ip tuntap del ${GUEST_TAP_NAME} mode tap"
}

setup_bridge_network() {
	# Get last tap device on host
	TAP_NUM="$(ip link show type tun | grep 'tap[0-9]\+' | sed -re 's|.*tap([0-9]+):.*|\1|' | sort -n | tail -1)"
	if [ "$TAP_NUM" = "" ]; then
		TAP_NUM="0"
	fi
	TAP_NUM=$((TAP_NUM + 1))
	GUEST_TAP_NAME="tap${TAP_NUM}"

	[ -n "$USE_VIRTIO" ] && PREFIX="52:54:00" || PREFIX="02:16:1e"
	SUFFIX="$(ip address show dev $BRIDGE | grep link/ether | awk '{print $2}' | awk -F : '{print $4 ":" $5}')"
	GUEST_MAC_ADDR=$(printf "%s:%s:%02x" $PREFIX $SUFFIX $TAP_NUM)

	echo "Starting network adapter '${GUEST_TAP_NAME}' MAC=$GUEST_MAC_ADDR"
	run_cmd "ip tuntap add $GUEST_TAP_NAME mode tap user `whoami`"
	run_cmd "ip link set $GUEST_TAP_NAME up"
	run_cmd "ip link set $GUEST_TAP_NAME master $BRIDGE"

	if [ -n "$USE_VIRTIO" ]; then
		add_opts "-netdev type=tap,script=no,downscript=no,id=net0,ifname=$GUEST_TAP_NAME"
		add_opts "-device virtio-net-pci,mac=${GUEST_MAC_ADDR},netdev=net0,disable-legacy=on,iommu_platform=true,romfile="
	else
		add_opts "-netdev tap,id=net0,ifname=$GUEST_TAP_NAME,script=no,downscript=no"
		add_opts "-device e1000,mac=${GUEST_MAC_ADDR},netdev=net0,romfile="
	fi
}

get_cbitpos() {
	#
	# Get C-bit position directly from the hardware
	#   Reads of /dev/cpu/x/cpuid have to be 16 bytes in size
	#     and the seek position represents the CPUID function
	#     to read.
	#   The skip parameter of DD skips ibs-sized blocks, so
	#     can't directly go to 0x8000001f function (since it
	#     is not a multiple of 16). So just start at 0x80000000
	#     function and read 32 functions to get to 0x8000001f
	#   To get to EBX, which contains the C-bit position, skip
	#     the first 4 bytes (EAX) and then convert 4 bytes.
	#

	cat <<EOF > tmp-cbit.c
#include <stdio.h>
int main() {
	unsigned int eax, ebx, ecx, edx;
	asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "0"(0x8000001f) : "memory");
	printf("%d\n", ebx & 0x3f);
}
EOF

	make tmp-cbit > /dev/null 2>&1
	CBITPOS=`./tmp-cbit`
	rm -f tmp-cbit tmp-cbit.c
}

exit_from_int() {
	stop_network

	rm -rf ${QEMU_CMDLINE}
	# restore the mapping
	stty intr ^c
	exit 1
}

trap exit_from_int SIGINT

if [ `id -u` -ne 0 ]; then
	echo "Must be run as root!"
	exit 1
fi

while [ -n "$1" ]; do
	case "$1" in
		-sev)		SEV_GUEST="1"
				;;
		-sev-es)	SEV_GUEST="1"
				SEV_ES_GUEST="1"
				;;
		-sev-snp)	SEV_GUEST="1"
				SEV_ES_GUEST="1"
				SEV_SNP_GUEST="1"
				;;
		-svsm)		SVSM="${2}"
				shift
				;;
		-sev-policy)	SEV_POLICY="${2}"
				shift
				;;
		-snp-flags)	SNP_FLAGS="${2}"
				shift
				;;
		-hda) 		HDA_FILE="${2}"
				shift
				;;
		-hdb) 		HDB_FILE="${2}"
				shift
				;;
		-cpu)		CPU="$2"
				shift
				;;
		-cpu-features)	CPU_FEATURES="$2"
				shift
				;;
		-mem)  		MEM=$2
				shift
				;;
		-maxmem)	MAX_MEM=$2
				shift
				;;
		-console)	CONSOLE=$2
				shift
				;;
		-smp)		SMP_NCPUS=$2
				shift
				;;
		-maxcpus)	MAX_NCPUS=$2
				shift
				;;
		-vnc)		VNC_PORT=$2
				shift
				if [ "${VNC_PORT}" = "" ]; then
					usage
				fi
				;;
		-bios)		UEFI_BIOS_CODE="$2"
				shift
				;;
		-bios-vars)	UEFI_BIOS_VARS="$2"
				shift
				;;
		-bios-debug)	BIOS_DEBUG="1"
				;;
		-initrd)	INITRD_FILE=$2
				shift
				;;
		-kernel)	KERNEL_FILE=$2
				shift
				;;
		-append)	APPEND_ARGS=$2
				shift
				;;
		-cdrom)		CDROM_FILE=$2
				shift
				;;
		-allow-debug)   ALLOW_DEBUG="1"
				;;
		-bridge)	BRIDGE=$2
				shift
				;;
		-novirtio)      USE_VIRTIO=""
				;;
		*) 		usage;;
	esac
	shift
done

[ -n "$SVSM" ] && SNP_FLAGS=$((SNP_FLAGS | 0x04))

[ -z "$UEFI_BIOS_CODE" ] && UEFI_BIOS_CODE="./OVMF_CODE.fd"
TMP="$(readlink -e $UEFI_BIOS_CODE)"
[ -z "$TMP" ] && {
	echo "UEFI CODE file [$UEFI_BIOS_CODE] not found"
	exit 1
}
UEFI_BIOS_CODE="$TMP"

[ -z "$UEFI_BIOS_VARS" ] && UEFI_BIOS_VARS="./OVMF_VARS.fd"
TMP="$(readlink -e $UEFI_BIOS_VARS)"
[ -z "$TMP" ] && {
	echo "UEFI VARS file [$UEFI_BIOS_VARS] not found"
	exit 1
}
UEFI_BIOS_VARS="$TMP"

if [ -n "$HDA_FILE" -o -n "$CDROM_FILE" ]; then
	[ -n "$HDA_FILE" ] && GUEST_NAME=$HDA_FILE || GUEST_NAME=$CDROM_FILE
	GUEST_NAME="$(basename $GUEST_NAME | sed -re 's|\.[^\.]+$||')"
else
	GUEST_NAME="diskless"
fi

case "$MEM" in
	*M)	MEM_IN_MB="${MEM%M}"
		;;
	*G)	MEM_IN_MB="${MEM%G}"
		MEM_IN_MB=$((MEM_IN_MB * 1024))
		;;
	 *)	echo "Memory must be specified with the 'M' or 'G' suffix"
		exit 1
		;;
esac

# we add all the qemu command line options into a file
QEMU_CMDLINE=/tmp/cmdline.$$
rm -rf ${QEMU_CMDLINE}

add_opts "${QEMU_INSTALL_DIR}qemu-system-x86_64 -enable-kvm"

[ -n "$CPU_FEATURES" ] && CPU="${CPU},$CPU_FEATURES"
CPU="$CPU,host-phys-bits=true"
add_opts "-cpu $CPU"

# add number of VCPUs
[ -n "${SMP_NCPUS}" ] && add_opts "-smp ${SMP_NCPUS}${MAX_NCPUS:+,maxcpus=$MAX_NCPUS}"

# define guest memory
add_opts "-m ${MEM}${MAX_MEM:+,slots=5,maxmem=$MAX_MEM}"

# If this is SEV guest then add the encryption device objects to enable support
if [ -n "${SEV_GUEST}" ]; then
	if [ -z "$SEV_POLICY" ]; then
		if [ -n "${SEV_SNP_GUEST}" ]; then
			POLICY=$((0x30000))
			[ -n "${ALLOW_DEBUG}" ] && POLICY=$((POLICY | 0x80000))
		else
			POLICY=$((0x01))
			[ -n "${ALLOW_DEBUG}" ] && POLICY=$((POLICY & ~0x01))
			[ -n "${SEV_ES_GUEST}" ] && POLICY=$((POLICY | 0x04))
		fi
		SEV_POLICY=$(printf "%#x" $POLICY)
	fi

	get_cbitpos
	add_opts "-machine type=q35,memory-encryption=sev0,vmport=off${SVSM:+,svsm=$SVSM}"

	SEV_COMMON="id=sev0,policy=${SEV_POLICY},cbitpos=${CBITPOS},reduced-phys-bits=1"
	if [ -n "$SEV_SNP_GUEST" ]; then
		SNP_FLAGS=$(printf "%#x" $SNP_FLAGS)
		add_opts "-object sev-snp-guest,$SEV_COMMON,init-flags=${SNP_FLAGS},host-data=b2l3bmNvd3FuY21wbXA"
	else
		add_opts "-object sev-guest,$SEV_COMMON"
	fi
else
	add_opts "-machine type=q35"
fi

# The OVMF binary, including the non-volatile variable store, appears as a
# "normal" qemu drive on the host side, and it is exposed to the guest as a
# persistent flash device.
[ -e ./${GUEST_NAME}.fd ] || run_cmd "cp ${UEFI_BIOS_VARS} ${GUEST_NAME}.fd"
UEFI_BIOS_VARS="./${GUEST_NAME}.fd"
add_opts "-drive if=pflash,format=raw,unit=0,file=${UEFI_BIOS_CODE},readonly=on"
add_opts "-drive if=pflash,format=raw,unit=1,file=${UEFI_BIOS_VARS}"

[ -n "$BIOS_DEBUG" ] && {
	add_opts "-chardev file,id=bios,path=./bios.log"
	add_opts "-device isa-debugcon,iobase=0x402,chardev=bios"
}

# add CDROM if specified
[ -n "${CDROM_FILE}" ] && add_opts "-drive file=${CDROM_FILE},media=cdrom,index=0"

# If harddisk file is specified then add the HDD drive
if [ -n "${HDA_FILE}" ]; then
	case "${HDA_FILE}" in
		*qcow2)		HDA_FORMAT="qcow2"
				;;
		*)		HDA_FORMAT="raw"
				;;
	esac

	if [ -n "$USE_VIRTIO" ]; then
		add_opts "-drive file=${HDA_FILE},if=none,id=disk0,format=${HDA_FORMAT}"
		add_opts "-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true"
		add_opts "-device scsi-hd,drive=disk0"
	else
		add_opts "-drive file=${HDA_FILE},format=${HDA_FORMAT}"
	fi
fi

if [ -n "${HDB_FILE}" ]; then
	case "${HDB_FILE}" in
		*qcow2)		HDB_FORMAT="qcow2"
				;;
		*)		HDB_FORMAT="raw"
				;;
	esac

	if [ -n "$USE_VIRTIO" ]; then
		add_opts "-drive file=${HDB_FILE},if=none,id=disk1,format=${HDB_FORMAT}"
		add_opts "-device virtio-scsi-pci,id=scsi1,disable-legacy=on,iommu_platform=true"
		add_opts "-device scsi-hd,drive=disk1"
	else
		add_opts "-drive file=${HDB_FILE},format=${HDB_FORMAT}"
	fi
fi

# if console is serial then disable graphical interface
if [ "${CONSOLE}" = "serial" ]; then
	add_opts "-nographic"
fi

# if -kernel arg is specified then use the kernel provided in command line for boot
if [ -n "${KERNEL_FILE}" ]; then
	add_opts "-kernel $KERNEL_FILE"
	if [ -n "${APPEND_ARGS}" ]; then
		add_opts "-append \"${APPEND_ARGS}\""
	else
		add_opts "-append \"console=ttyS0 earlyprintk=serial root=/dev/sda2\""
	fi
	[ -n "${INITRD_FILE}" ] && add_opts "-initrd ${INITRD_FILE}"
fi

# start vnc server
[ -n "${VNC_PORT}" ] && add_opts "-vnc :${VNC_PORT}" && echo "Starting VNC on port ${VNC_PORT}"

# start monitor on pty and named socket 'monitor'
add_opts "-monitor pty -monitor unix:monitor,server,nowait"

if [ -n "$BRIDGE" ]; then
	setup_bridge_network
else
	add_opts "-netdev user,id=vmnic -device e1000,netdev=vmnic,romfile="
fi

# log the console  output in stdout.log
QEMU_CONSOLE_LOG=`pwd`/stdout.log

# save the command line args into log file
cat $QEMU_CMDLINE | tee ${QEMU_CONSOLE_LOG}
echo | tee -a ${QEMU_CONSOLE_LOG}


# map CTRL-C to CTRL ]
echo "Mapping CTRL-C to CTRL-]"
stty intr ^]

echo "Launching VM ..."
echo "  $QEMU_CMDLINE"
sleep 1
bash ${QEMU_CMDLINE} 2>&1 | tee -a ${QEMU_CONSOLE_LOG}

# restore the mapping
stty intr ^c

#rm -rf ${QEMU_CMDLINE}
stop_network

#!/bin/bash

# This script is used to add the XanMod kernel repository, fetch additional keys from the keyserver,
# and install the appropriate version of the XanMod kernel based on CPU instruction set.

# Ensure running as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 
   exit 1
fi

# Detect CPU instruction set and set kernel version
level=$(awk 'BEGIN {
    while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1
    if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1
    if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2
    if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3
    if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4
    if (level > 0) { print level; exit level + 1 }
    exit 1
}')

case "$level" in
  1)
    kernel_package="linux-xanmod-lts-x64v1"
    ;;
  2)
    kernel_package="linux-xanmod-lts-x64v2"
    ;;
  3)
    kernel_package="linux-xanmod-lts-x64v3"
    ;;
  4)
    # kernel_package="linux-xanmod-lts-x64v4"
    kernel_package="linux-xanmod-lts-x64v3"
    ;;
  *)
    echo "Unable to determine appropriate Xanmod kernel version."
    exit 1
    ;;
esac

# Download the XanMod kernel
echo "Downloading $kernel_package"
curl -L -o ${kernel_package}.deb https://github.com/myrime/script/raw/main/kernel/${kernel_package}.deb

if [ $? -ne 0 ]; then
    echo "Failed to download $kernel_package"
    exit 1
fi

# Install the XanMod kernel
echo "Installing $kernel_package"
dpkg -i ${kernel_package}.deb

if [ $? -ne 0 ]; then
    echo "Failed to install $kernel_package"
    exit 1
fi

update-grub

echo "The system will reboot in 10 seconds. Press Ctrl+C to cancel."
for i in {10..1}
do
    echo "$i..."
    sleep 1
done
echo "Rebooting now!"
reboot

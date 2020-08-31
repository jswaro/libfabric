#!/bin/bash

PROJECT="OFI-CRAY"
TARGET_ARCH="x86_64"
DEV_NAME="dev"
BRANCH_NAME="master"
IYUM_REPO_NAME_1="os-networking-team"
IYUM_REPO_NAME_2="cuda"

if [[ "${PRODUCT}" = "" ]]
then
    PRODUCT="shasta-premium"
fi

if [[ "${TARGET_OS}" = "" ]]
then
    TARGET_OS="sle15_cn"
fi

echo "$0: --> PRODUCT: '${PRODUCT}'"
echo "$0: --> TARGET_OS: '${TARGET_OS}'"

ZYPPER_OPTS="--verbose --non-interactive"
RPMS="rdma-core rdma-core-devel cuda-cudart-11-0 cuda-cudart-devel-11-0 cuda-driver-devel-11-0 cuda-nvcc-11-0"

OFI_URL="http://car.dev.cray.com/artifactory/${PRODUCT}/${PROJECT}/${TARGET_OS}/${TARGET_ARCH}/${DEV_NAME}/${BRANCH_NAME}/"
CUDA_URL="http://car.dev.cray.com/artifactory/third-party/cuda/${TARGET_OS}/${TARGET_ARCH}/${DEV_NAME}/${BRANCH_NAME}/"

if command -v yum > /dev/null; then
    yum-config-manager --add-repo=$OFI_URL
    yum-config-manager --add-repo=$CUDA_URL
    yum-config-manager --setopt=gpgcheck=0 --save

    yum install -y $RPMS
elif command -v zypper > /dev/null; then
    zypper $ZYPPER_OPTS addrepo --no-gpgcheck --check --priority 1 \
       --name=$IYUM_REPO_NAME_1 $OFI_URL $IYUM_REPO_NAME_1
    zypper $ZYPPER_OPTS addrepo --no-gpgcheck --check --priority 1 \
       --name=$IYUM_REPO_NAME_2 $CUDA_URL $IYUM_REPO_NAME_2
    zypper $ZYPPER_OPTS install $RPMS
else
    "Unsupported package manager or package manager not found -- installing nothing"
fi

# The CUDA device driver RPM provides a usable libcuda.so which is required by
# the libfabric autoconf checks. Since artifactory does not provide this RPM,
# the cuda-driver-devel-11-0 RPM is installed and provides a stub libcuda.so.
# But, this stub libcuda.so is installed into a non-lib path. A symlink is
# created to fix this.
ln -s /usr/local/cuda-11.0/lib64/stubs/libcuda.so /usr/local/cuda-11.0/lib64/libcuda.so

# Convenient symlink which allows the libfabric build process to not have to
# call out a specific versioned CUDA directory.
ln -s /usr/local/cuda-11.0 /usr/local/cuda

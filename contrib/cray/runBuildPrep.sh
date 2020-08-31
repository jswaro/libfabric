#!/bin/bash

PROJECT="OFI-CRAY"
TARGET_ARCH="x86_64"
DEV_NAME="dev"
BRANCH_NAME="master"
IYUM_REPO_NAME_1="os-networking-team"

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
RPMS="rdma-core rdma-core-devel"

URL="http://car.dev.cray.com/artifactory/${PRODUCT}/${PROJECT}/${TARGET_OS}/${TARGET_ARCH}/${DEV_NAME}/${BRANCH_NAME}/"
if command -v yum > /dev/null; then
    yum-config-manager --add-repo=$URL

    yum-config-manager --setopt=gpgcheck=0 --save

    yum install -y $RPMS
elif command -v zypper > /dev/null; then
    zypper $ZYPPER_OPTS addrepo --no-gpgcheck --check --priority 1 \
    	--name=$IYUM_REPO_NAME_1 $URL $IYUM_REPO_NAME_1
    zypper $ZYPPER_OPTS install $RPMS
else
    "Unsupported package manager or package manager not found -- installing nothing"
fi

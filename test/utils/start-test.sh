#!/bin/bash
#
# Execute UCS tests in EC2 or KVM environment
#

set -x

die () {
	echo "$*" >&2
	exit 1
}

test -f "$1" || die "Missing test config file!"

release='4.3-5'
old_release='4.2-5'

export CURRENT_AMI=ami-08b2615e56edd43fa # AMI: Univention Corporate Server (UCS) 4.3 (official image) rev. 5 - ami-08b2615e56edd43fa
export OLD_AMI=ami-e9388b90 # AMI: Univention Corporate Server (UCS) 4.2 (official image) rev. 3 - ami-e9388b90
export UCS_MINORRELEASE="${release%%-*}"
export TARGET_VERSION="${TARGET_VERSION:=$release}"
export UCS_VERSION="${UCS_VERSION:=$release}"
export OLD_VERSION="${OLD_VERSION:=$old_release}"
export KVM_TEMPLATE="${KVM_TEMPLATE:=generic-unsafe}"
export KVM_UCSVERSION="${KVM_UCSVERSION:=$UCS_VERSION}"
export KVM_OLDUCSVERSION="${KVM_OLDUCSVERSION:=$OLD_VERSION}"
export KVM_BUILD_SERVER="${KVM_BUILD_SERVER:=lattjo.knut.univention.de}"
export KVM_USER="${KVM_USER:=$USER}"
export KVM_MEMORY="${KVM_MEMORY:=2048M}"
export KVM_CPUS="${KVM_CPUS:=1}"
export RELEASE_UPDATE="${release_update:=public}"
export ERRATA_UPDATE="${errata_update:=testing}"
export UCSSCHOOL_RELEASE=${UCSSCHOOL_RELEASE:=scope}
export HALT="${HALT:=true}"
export REPLACE="${REPLACE:=false}"
export CFG="$1"

test "$KVM_USER" = "jenkins" && KVM_USER="build"

# if the default branch of UCS@school is given, then build UCS else build UCS@school
if [ -n "$UCSSCHOOL_BRANCH" -o -n "$UCS_BRANCH" ]; then
	BUILD_HOST="10.200.18.180"
	REPO_UCS=git@git.knut.univention.de:univention/ucs.git
	REPO_UCSSCHOOL=git@git.knut.univention.de:univention/ucsschool.git
	if echo "$UCSSCHOOL_BRANCH" | egrep -q "^[0-9].[0-9]$" ; then
		BUILD_BRANCH="$UCS_BRANCH"
		BUILD_REPO="$REPO_UCS"
	else
		BUILD_BRANCH="$UCSSCHOOL_BRANCH"
		BUILD_REPO="$REPO_UCSSCHOOL"
	fi
	# check branch test
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "jenkins@${BUILD_HOST}" python3 \
		/home/jenkins/build -r "${BUILD_REPO}" -b "${BUILD_BRANCH}" \
		> utils/apt-get-branch-repo.list || exit 1
	# replace non deb lines
	sed -i '/^deb /!d' utils/apt-get-branch-repo.list
fi

# create the command and run in ec2 or kvm depending on cfg
if ! grep -Fq kvm_template "$CFG"
then
	exe='ucs-ec2-create'
	test -e ./ucs-ec2-tools/ucs-ec2-create && exe="./ucs-ec2-tools/ucs-ec2-create"
else
	exe='ucs-kvm-create'
	test -e ./ucs-ec2-tools/ucs-kvm-create && exe="./ucs-ec2-tools/ucs-kvm-create"
fi

# start the test
declare -a cmd=("$exe" -c "$CFG")
"$HALT" && cmd+=("-t")
"$REPLACE" && cmd+=("--replace")
PATH="${PATH:+$PATH:}./ucs-ec2-tools"
"${cmd[@]}" &&
[ -e "./COMMAND_SUCCESS" ]

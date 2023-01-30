#!/bin/bash
# SPDX-License-Identifier: MIT
# This script helps keep track of crates we depend on
# Author Carlos Bilbao

CHECK_LICENSE=0

function usage()
{
	echo "$0 prints information of crates included in our dependencies"
	echo "Usage: $0 [OPTIONS]"
	echo "  where OPTIONS are:"
	echo "  --list          Default behavior, list licenses and versions"
	echo "  --check         Return 0 if all licenses have MIT, error otherwise"
	echo "  -h|--help       Usage information"

	exit 1
}

while [ -n "$1" ]
do
	case "$1" in
	--check)
		CHECK_LICENSE="1"
		;;
	-h|--help)
		usage
		;;
	--list)
		;;
	*|-*|--*)
		echo "Unsupported option: [$1]"
		usage
		;;
	esac
	shift
done

if [ "$CHECK_LICENSE" -eq 0 ]
then
	SEPARATE="-------------"
	printf "%-20s %-20s %-20s\n" "Crate" "Version" "License"
	printf "%-20s %-20s %-20s\n" $SEPARATE $SEPARATE $SEPARATE
fi

# Iterate over each crate
cargo tree --prefix none --format "{p} {l}" | while read CRATE VERSION LICENSE
do
	if [ "$CRATE" == "linux_svsm" ]
	then
		continue
	fi

	LICENSE=${LICENSE//(proc-macro) /}

	if [ "$CHECK_LICENSE" -eq 0 ]
	then
		# Print the name, version and license of the crate
		printf "%-20s %-20s %-20s\n" "$CRATE" "$VERSION" "$LICENSE"

	elif [ "$LICENSE" != "${LICENSE//MIT/}" ]
	then
		exit 1
	fi
done

exit 0

#!/bin/bash

if [ $# != 2 ]
	then
	echo "failed: The number of arguments is incorrect"
	exit 1	
fi

writefile=$1
writestr=$2

install -Dv /dev/null $writefile
echo $writestr > $writefile


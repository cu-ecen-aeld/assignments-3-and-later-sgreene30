#!/bin/bash

if [ $# != 2 ]
then
	echo "failed: expected 2 arguments"
	echo "correct arguments are:"
	echo "	1) filesdir"
	echo "	2) searchstr"
	exit 1
fi

filesdir=$1
searchstr=$2


if [ -d $filesdir ] 
	then
	FILECOUNT=$( find $filesdir -type f | wc -l )
	STRCOUNT=$( grep -r $searchstr $filesdir | wc -l )
	echo "The number of files are ${FILECOUNT} and the number of matching lines are ${STRCOUNT}"
	
else
	echo "filesdir is not a directory"
	exit 1
fi	
exit 0

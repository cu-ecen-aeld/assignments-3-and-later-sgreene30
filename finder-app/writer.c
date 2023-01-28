#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>


int main(int argc, char *argv[])
{
	openlog(NULL, 0, LOG_USER);
	if(argc != 3)
	{
		syslog(LOG_ERR, "Incorrect number of arguments specified");
		printf("Incorrect number of arguments specified");
		exit(1);
	}
	
	FILE *fp;
	fp = fopen(argv[1], "w");
	
	if(fp == NULL)
	{
		perror("Filepointer is NULL: ");
		syslog(LOG_ERR, "Filepointer is NULL");
		exit(1);
	}
	else
	{
		fputs(argv[2], fp);
		syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
		printf("Writing %s to %s\n", argv[2], argv[1]);
		fclose(fp);
	}
	
	
	return 0;
}

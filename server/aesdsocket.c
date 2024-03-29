/*
    Samuel Greene
    AESD Assignment 9
*/

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/queue.h>
#include <pthread.h>
#include <time.h>
#include "time_functions_shared.h"
#include "../aesd-char-driver/aesd_ioctl.h"

#define PORT "9000"
#define BACKLOG 20
#define SOCKET_DATA "/dev/aesdchar"
#define BUF_LEN 1024

bool caught_signal = false;

struct thread_struct 
{
    int accept_fd;
	int thread_complete;
};

typedef struct slist_data_s slist_data_t;
struct slist_data_s 
{
    pthread_t thread_id;
	struct thread_struct th_data;
	SLIST_ENTRY(slist_data_s) entries;
};

SLIST_HEAD(slisthead,slist_data_s) head = SLIST_HEAD_INITIALIZER(head);
pthread_mutex_t lock;

void process_data(int socket_fd)
{
    size_t recv_rc, packet_size;
    char *buf = malloc(BUF_LEN);
    bool end_flag = false;
    FILE *file;
    int next_char;
    char c;
    int sscanf_nargs = 0;
    struct aesd_seekto seekto;
    bool write_to_buf = true;


    packet_size = 0;
    recv_rc = 0;
    while(!end_flag)
    {
        recv_rc = recv(socket_fd, buf + packet_size, BUF_LEN, 0);
        if(recv_rc == -1)
        {
            perror("recv failure");
            syslog(LOG_ERR, "recv failure");
            return;
        }

        packet_size += recv_rc;
        buf = realloc(buf, packet_size + BUF_LEN);
        memset(buf + packet_size,0,BUF_LEN);
        
        if(strchr(buf, '\n') != NULL)
        {
            end_flag = true;
        }
    }

    if(pthread_mutex_lock(&lock) != 0){
        perror("mutex lock fail");}

    file = fopen(SOCKET_DATA, "a+");

    //check to see if command ioctl is sent
    sscanf_nargs = sscanf(buf, "AESDCHAR_IOCSEEKTO:%d,%d", &seekto.write_cmd, &seekto.write_cmd_offset);
    
    if(sscanf_nargs == 2)
    {
        ioctl(fileno(file), AESDCHAR_IOCSEEKTO, &seekto.write_cmd, &seekto.write_cmd_offset);
        write_to_buf = false;
    }

    if(write_to_buf)
    {
        fwrite(buf, 1, packet_size, file);
        rewind(file);
    }

    free(buf);

    while(1) //individually print characters of all previous packets
    {
        next_char = fgetc(file);
        if(next_char == EOF)
        {
            break;
        }
        c = next_char;
        if(send(socket_fd, &c, 1, 0) == -1)
        {
            perror("send failure");
            syslog(LOG_ERR, "recv failure");
            return;
        }
    }
    fclose(file);
    if(pthread_mutex_unlock(&lock) != 0){
    perror("mutex lock fail");}

}

static void signal_handler(int sig_num)
{
    if(sig_num == SIGINT)
    {
        syslog(LOG_INFO, "Caught signal, exiting");
    }
    else if(sig_num == SIGTERM)
    {
        syslog(LOG_INFO, "Caught signal, exiting");
    }
    caught_signal = true;
}

void *socket_thread(void *input_args)
{
	struct thread_struct *in_args = input_args;

	process_data(in_args->accept_fd);
    in_args->thread_complete = 1; //set complete flag
	return input_args;
}


int process_entry(int accept_fd)
{
	slist_data_t *entry=NULL;
	slist_data_t *current_entry;

	entry  = malloc(sizeof(slist_data_t));

	entry->th_data.accept_fd = accept_fd;
	entry->th_data.thread_complete = 0;

	pthread_create(&entry->thread_id,NULL,socket_thread,(void *)&entry->th_data);

	if(SLIST_EMPTY(&head) != 0)
    {
		SLIST_INSERT_HEAD(&head, entry, entries);
	}
	else
    {
		SLIST_FOREACH(current_entry, &head, entries){
			if(current_entry->entries.sle_next == NULL){
				SLIST_INSERT_AFTER(current_entry, entry, entries);
				break;
			}
		}
	}
	return 0;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//Check the input argument count to ensure both arguments are provided
int main(int argc, char *argv[])
{

    int writer_fd, sock_fd, new_sock_fd;
    int opt = 1;
    struct addrinfo hints; //hints for bind()
    struct addrinfo *servinfo; //for point results of bind()
    struct sockaddr_storage client_addr;

    socklen_t addr_size;
    char client_address[INET6_ADDRSTRLEN];
	slist_data_t *entry;

	openlog(NULL,0,LOG_USER);
	syslog(LOG_DEBUG,"starting aesdsocket");	
	writer_fd = creat(SOCKET_DATA, 0777);
    close(writer_fd);

	//Initialize SLIST Head
	SLIST_INIT(&head);

	//Setup signal handler
    struct sigaction new_action; //set up signal and handlers
    memset(&new_action, 0, sizeof(struct sigaction));
    new_action.sa_handler=signal_handler;

    if(sigaction(SIGINT, &new_action, NULL) != 0)
    {
        perror("sigaction failure");
        exit(1);
    }
    if(sigaction(SIGTERM, &new_action, NULL) != 0)
    {
        perror("sigaction failure");
        exit(1);
    }

    //clear and set hints struct
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    //populate servinfo with hints set above
    if(getaddrinfo(NULL, PORT, &hints, &servinfo) != 0)
    {
        perror("getaddinfo error");
        syslog(LOG_ERR, "getaddinfo error");
        return -1;
    }

    //create socket
    sock_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if(sock_fd == -1)
    {
        perror("socket creation fail");
        syslog(LOG_ERR, "socket creation fail");
        return -1;
    }

    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) == -1)
    {
        perror("setsockopt failure");
        syslog(LOG_ERR, "setsockopt failure");
        return -1;
    }

    //bind socket
    if(bind(sock_fd, servinfo->ai_addr, servinfo->ai_addrlen))
    {
        close(sock_fd);
        perror("bind failure");
        syslog(LOG_ERR, "bind failure");
        return -1;
    }

    freeaddrinfo(servinfo);

    //listen
    if(listen(sock_fd, BACKLOG) < 0)
    {
        perror("listen failure");
        syslog(LOG_ERR, "listen failure");
        return -1;
    }

    if(argc > 1 && strcmp(argv[1], "-d")==0)
    {
        if(daemon(0, 0)==-1)
        {
            perror("daemon failure");
            syslog(LOG_ERR, "daemon failure");
            exit(1);
        }
    }

    while(1)
    {
        //check to see if signal occured
        if(caught_signal == true)
        {
            SLIST_FOREACH(entry, &head, entries)
            {
                if(entry->th_data.thread_complete == 1)
                {
                    pthread_join(entry->thread_id,NULL);
                }
                //close connection
                close(entry->th_data.accept_fd);
            }
            //free SLIST
            while (!SLIST_EMPTY(&head))
            {
                entry = SLIST_FIRST(&head);
                close(entry->th_data.accept_fd);
                SLIST_REMOVE_HEAD(&head, entries);
                free(entry);
            }

            close(sock_fd);
            unlink(SOCKET_DATA);
            closelog();
            return 0;
        }

        new_sock_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &addr_size);
        if(new_sock_fd == -1)
        {
            perror("accept failure");
            syslog(LOG_ERR, "accept failure");
            return -1;
        }
        else //print client ip to syslog per step 2 part d
        {
            //get client address and store in string client_address
            inet_ntop(client_addr.ss_family,
            get_in_addr((struct sockaddr *)&client_addr),
            client_address, sizeof client_address);
        }

        process_entry(new_sock_fd);
        //join threads that are completed
        SLIST_FOREACH(entry, &head, entries)
        {
            if(entry->th_data.thread_complete == 1)
            {
                syslog(LOG_DEBUG,"SLIST: Attempting to join thread pointed to by %i",entry->th_data.accept_fd);
                pthread_join(entry->thread_id,NULL);
                close(entry->th_data.accept_fd);	
            }
            entry->th_data.thread_complete = 0;
        }
    }
    
    syslog(LOG_DEBUG, "ending aesdsocket");
	return 0;
}

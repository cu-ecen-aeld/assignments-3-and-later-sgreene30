/*
*   AUTHOR: Samuel Greene
*   Assignment 5 Part 1 of AESD
*/

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#define PORT "9000"
#define BACKLOG 5
#define BUF_LEN 1024
#define SOCKET_DATA "/var/tmp/aesdsocketdata"

int sock_fd, new_sock_fd; //socket file descriptor for socket()
int fd = 0;

void clean_exit()
{
    close(sock_fd);
    close(new_sock_fd);
    unlink(SOCKET_DATA);
    exit(1);
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
    
    clean_exit();

}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
void *socket_thread()
{
    char *ptr; //for handling dynamic memory
    int i = 0;
    int received_len = 0;
    FILE *file;
    bool write_flag = false; 
    char buf[BUF_LEN];
    int recv_rc;

    ptr = (char*)malloc(1); //start allocation will realloc below
    if(ptr==NULL)
    {
        perror("malloc failure");
        return NULL;
    }

    //read packet of size BUF_LEN
    recv_rc = recv(new_sock_fd, buf, BUF_LEN, 0);        
    if(recv_rc == -1)
    {
        perror("recv failure");
        syslog(LOG_ERR, "recv failure");
        return NULL;
    }
    while(recv_rc != 0) //while still receiving packets
    {
        for(i=0; i<BUF_LEN; i++) //search latest buf for newline
        {
            if(buf[i] == '\n')
            {          
                i++;
                write_flag = true;
                break;
            }
        }
        
        received_len = received_len + i;
        ptr=(char *)realloc(ptr, received_len + 1); //reallocate memory to current packet size

        if(ptr == NULL)
        {
            perror("realloc failure");
            return NULL;
        }
        memcpy(ptr + received_len - i, buf, i); //copy buf to ptr
        memset(buf,0,BUF_LEN);

        if(write_flag) //if newline received
        {
            fd = open(SOCKET_DATA, O_APPEND | O_WRONLY); //open file for appending
            if(fd == -1)
            {
                perror("open failure");
                return NULL;
            }
            if(write(fd, ptr, received_len) == -1) //write packet contained in ptr
            {
                perror("write failure");
                return NULL;
            }
            close(fd);

            file = fopen(SOCKET_DATA, "rb"); //open file for appending packets
            if(file == NULL)
            {
                perror("fopen failure");
                return NULL;
            }

            while(1) //individually print characters of all previous packets
            {
                int next_char;
                char c;
                next_char = fgetc(file);
                if(next_char == EOF)
                {
                    break;
                }
                c = next_char;
                if(send(new_sock_fd, &c, 1, 0) == -1)
                {
                    perror("send failure");
                    syslog(LOG_ERR, "recv failure");
                    return NULL;
                }
            }

            received_len = 0;
            write_flag = false;
        }
        recv_rc = recv(new_sock_fd, buf, BUF_LEN, 0); //receive next buf
                    
        if(recv_rc == -1)
        {
            perror("recv failure");
            syslog(LOG_ERR, "recv failure");
            return NULL;
        }
    }
    free(ptr); // free memory at end of packet
    return NULL;
}

int main(int argc, char *argv[])
{
    int opt = 1;

    struct addrinfo hints; //hints for bind()
    struct addrinfo *servinfo; //for point results of bind()
    struct sockaddr_storage client_addr;

    socklen_t addr_size;
    char client_address[INET6_ADDRSTRLEN];
      
    
    openlog(NULL, LOG_PID, LOG_USER); //open syslog

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

    //run in daemon mode if argument specified
    if(argc > 1 && strcmp(argv[1], "-d")==0)
    {
        if(daemon(0, 0)==-1)
        {
            perror("daemon failure");
            syslog(LOG_ERR, "daemon failure");
            exit(1);
        }
    }

    //free memory to prevent leak
    freeaddrinfo(servinfo);

    //listen
    if(listen(sock_fd, BACKLOG) < 0)
    {
        perror("listen failure");
        syslog(LOG_ERR, "listen failure");
        return -1;
    }

    //create file
    fd = open(SOCKET_DATA, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if(fd == -1)
    {
        perror("file creation");
        return -1;
    }

    close(fd);

    while(1)
    {
        addr_size = sizeof client_addr;
        //accept connection if found
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
                                
            //print address to syslog and terminal
            syslog(LOG_INFO,"Accepts connection from %s",client_address);
            //printf("Accepts connection from %s\n",client_address);
        }

        pthread_t socket;
        if(pthread_create(&socket, NULL, socket_thread, NULL) != 0)
        {
            perror("pthread_create");
        }
        pthread_join(socket, NULL);

    }
    clean_exit();
    return 0;
}

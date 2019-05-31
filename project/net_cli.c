/******************************************************************************

    descripte:  for test cloud server client
        author:         xianshiwei
        date:           2019/04/08

******************************************************************************/


#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <string.h>

static int new_socket_unix(void) {
    int sfd;
    int flags;

    if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket()");
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("setting O_NONBLOCK");
        close(sfd);
        return -1;
    }
    return sfd;
}

static int new_socket_linux_block(void)
{
    int fd = 0;
    int flags = 0;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket()");
        return -1;
    }

#if 0    
    /*get the file access mode and the file status flags; arg is ignored*/
    if (((flags = fcntl(fd, F_GETFL, 0)) < 0) ||
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("set O_NONBLOCK");
        close(fd);
        return -1;
    }
#endif    
    return fd;
}

void test_change_vim()
{
    return;
}    

void run(char * buf, int len)
{
    if (!buf || len <= 0)
    {
        printf("buf:%p, len:%d \n", buf, len);
        return;
    }
    
    test_change_vim();

    int fd = 0;
    struct sockaddr_in addr;
    int ret = -1;
    int cnt = 600;
    int add = 0;
    char *sip = "192.168.1.253";
    
    //char *sip = "127.0.0.1";
    ssize_t sret = 0;
    //int port = 10007;
    int port = 15000;

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(sip);
    
    fd = new_socket_linux_block(); 
    
    struct sockaddr_in caddr;
    char *cip = "127.0.0.1";
/*    
    bzero(&caddr, sizeof(caddr));
    caddr.sin_family = AF_INET;
    caddr.sin_port = htons(0);
    caddr.sin_addr.s_addr = inet_addr(cip);
    if (bind(fd, (struct sockaddr *)&caddr, sizeof(caddr)))
    {
        perror("bind()");
        goto close_fd;
    }    
*/
    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (0 != ret)
    {
        perror("connect()");
        goto close_fd;
    }

    printf("send buf :%s \n", buf);

    //while(add++ < cnt)
    {
        sret = send(fd, buf, len, 0);   

        //usleep(120*1000*1000);
        usleep(1000*1000);
    }
    
    return;
close_fd:
    close(fd);
}    

int main(int argc, char * argv[])
{
    char buf[128];
    
    if (argc != 2)
    {
        printf("usage error \n");
        exit(EXIT_SUCCESS);
    }

    snprintf(buf, sizeof(buf)-1,  "run cli id : %s \n", argv[1]);
    
    for (int i=0; i<10; i++)
    {    
        run(buf, sizeof(buf));
    }

    return 0;
}

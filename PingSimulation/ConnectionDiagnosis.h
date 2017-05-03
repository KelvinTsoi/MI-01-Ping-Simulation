/**************************************************************************
**
**	The author disclaims copyright to this source code.
** 	In place of a legal notice, here is a bless in:
**
**	May you do good and not evil.
**	May you find forgiveness for yourself and forgive others.
**	May you share freely, never taking more than you give.
**
*************************************************************************/

/*
 * File:   ConnectionDiagnosis.h
 * Author: CAI
 * Created on 2017/5/3, 10:00pm
 */

#ifndef _CONNECTTIONDIAGNOSIS_H
#define _CONNECTTIONDIAGNOSIS_H

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <setjmp.h>
#include <time.h>

#define PACKET_SIZE         4096
#define BUFFER_SIZE         128
#define MAX_WAIT_TIME       1
#define MAX_NO_PACKETS      4
#define LOG_PATH			"ping[%04d-%02d-%02d_%02d:%02d:%02d].log"

#define USAGE() \
do \
{	\
	printf("Usage: ./ConnectionDiagnosis [destination]\n");	\
}while(0)

#define RECORD(format, ...) \
do  \
{   \
    time_t timep;   \
    struct tm *p;   \
    time(&timep);  \
    p = gmtime(&timep); \
    char buffer[BUFFER_SIZE] = {0x00};  \
    memset(buffer, 0, BUFFER_SIZE); \
    char timeStr[BUFFER_SIZE] = {0x00};  \
    memset(timeStr, 0, BUFFER_SIZE);    \
    sprintf(timeStr, "[ %d-%02d-%02d %02d:%02d:%02d ]", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, 8 + p->tm_hour, p->tm_min, p->tm_sec); \
    sprintf(buffer, format, ## __VA_ARGS__); \
    int fd_t = open(storePath, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR); \
    write(fd_t, timeStr, strlen(timeStr));   \
    write(fd_t, " ", 1);   \
    write(fd_t, buffer, strlen(buffer));    \
    write(fd_t, "\n", 1);   \
    close(fd_t); \
} while(0)


class ConnectionDiagnosis
{
public:

    int proceed(char* n_address);

    static ConnectionDiagnosis* Instance();

protected:

    ConnectionDiagnosis();

private:

    void send_packet(void);

    void recv_packet(void);

    int pack(int pack_no);

    int unpack(char *buf, int len);

    void statistics(void);

    void tv_sub(struct timeval *out, struct timeval *in);

    unsigned short cal_chksum(unsigned short *addr, int len);

private:

    char storePath[BUFFER_SIZE];

    char sendpacket[PACKET_SIZE];

    char recvpacket[PACKET_SIZE];

    int sockfd;

    int datalen;

    int nsend;

    int nreceived;

    pid_t pid;

    struct sockaddr_in dest_addr;

    struct sockaddr_in from;

    struct timeval tvrecv;

    struct in_addr addr;

    struct addrinfo *answer, hint, *curr;

    struct timeval tv_out;

    static ConnectionDiagnosis* _instance;
};

#endif /* _CONNECTTIONDIAGNOSIS_H */


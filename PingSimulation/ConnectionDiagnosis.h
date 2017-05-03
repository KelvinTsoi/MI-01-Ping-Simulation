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
#include <signal.h>


#define PACKET_LIMIT        4096        /*  */
#define UBOP                128         /* Universal Buffer Overflow Protection */
#define TIME_LAPSE           1          /*  */
#define MAX_NO_PACKETS       4          /*  */
#define MAX_ICMP_TIMES      1024
#define MICROSECOND_CARRY  1000000
#define LOG_PATH			"ICMP[%04d-%02d-%02d_%02d:%02d:%02d].log"   /* File name to store ICMP information */

//Redirect information
#define PRINT_LOG(format, ...) \
if(logStatus == LOG_REDIRECT)  \
{   \
    time_t timep;   \
    struct tm *p;   \
    time(&timep);  \
    p = gmtime(&timep); \
    char buffer[UBOP] = {0x00};  \
    memset(buffer, 0, UBOP); \
    char timeStr[UBOP] = {0x00};  \
    memset(timeStr, 0, UBOP);    \
    sprintf(timeStr, "[ %d-%02d-%02d %02d:%02d:%02d ]", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, 8 + p->tm_hour, p->tm_min, p->tm_sec); \
    sprintf(buffer, format, ## __VA_ARGS__); \
    int fd_t = open(storePath, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR); \
    write(fd_t, timeStr, strlen(timeStr));   \
    write(fd_t, " ", 1);   \
    write(fd_t, buffer, strlen(buffer));    \
    write(fd_t, "\n", 1);   \
    close(fd_t); \
}   \
else    \
{  \
    printf(""format"\r\n",  ##__VA_ARGS__);    \
}

#define PRINT_DEBUG(format, ...) \
printf("[%s %s %d] "format"\r\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);


//Redirect result or not
typedef enum
{
    LOG_VACANCY = 0,
    LOG_REDIRECT = 1,
}LOG_STATUS;


class ConnectionDiagnosis
{
public:

    /**
     * Summary: Module Entrance
     * Parameters:
     *  n_address: Ip Address store in string format
     *  logStatus: Recording mode setup
     * Return: Return zero if function success, other values signify function error code
     */
    int proceed(char* n_address, LOG_STATUS n_logStatus);

    /**
     * Summary: Singleton Pattern
     * Return: Return a static pointer of Class ConnectionDiagnosis
     */
    static ConnectionDiagnosis* Instance();

private:

    /**
     * Summary: Call back function of Semaphore
     * Parameters:
     *  sig: Signal value
     */
    static void sigActCallBackProc(int sig);

    /**
     * Summary: Execute function of Semaphore
     * Parameters:
     *  sig: Signal value
     */
    void sigActProc(int sig);

    static ConnectionDiagnosis* _instance;  /* A static pointer of Class ConnectionDiagnosis used for calling back */

    static ConnectionDiagnosis* pThis;      /* A static pointer of Class ConnectionDiagnosis used for calling back */

protected:

    /**
     * Summary: Constructor
     */
    ConnectionDiagnosis();

private:

    /**
     * Summary: Sending ICMP message
     */
    void send_packet(void);

    /**
     * Summary: Receiving ICMP message
     */
    void recv_packet(void);


    /**
     * Summary: Packaging ICMP message
     * Parameters:
     *  pack_no: Message sequence number
     * Return: ICMP message size
     */
    int pack(int pack_no);


    /**
     * Summary: Unpacking ICMP message
     * Parameters:
     *  buf: ICMP message content
     *  len: ICMP message size
     * Return:
     */
    int unpack(char *buf, int len);


    /**
     * Summary: Statistics of Current Connection Test
     */
    void statistics(void);

    /**
     * Summary: Calculating time difference between send and receive ICMP packet
     * Parameters:
     *  out: receive packet time record
     *  in: send packet time record
     */
    void tv_sub(struct timeval *out, struct timeval *in);


    /**
     * Summary:
     * Parameters:
     *  addr:
     *  len:
     * Return:
     */
    unsigned short cal_chksum(unsigned short *addr, int len);

private:

    int sockfd;     /*  */

    int datalen;    /*  */
    int nsend;      /*  */
    int nreceived;  /*  */

    pid_t pid;      /*  */

    struct sockaddr_in dest_addr;    /*  */
    struct sockaddr_in from;         /*  */
    struct timeval tvrecv;           /*  */
    struct in_addr addr;             /*  */
    struct addrinfo *answer;         /*  */
    struct addrinfo hint;            /*  */
    struct addrinfo *curr;           /*  */

    struct timeval tv_out;           /*  */

    char sendpacket[PACKET_LIMIT];   /*  */
    char recvpacket[PACKET_LIMIT];   /*  */

    char storePath[UBOP];            /*  */

    LOG_STATUS logStatus;            /*  */

    bool m_DiagnosingStatus;         /*  */

    struct sigaction act;           /* Semaphore Registration Information */
};

#endif /* _CONNECTTIONDIAGNOSIS_H */


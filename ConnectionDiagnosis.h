/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ConnecttionDiagnosis.h
 * Author: CAI
 *
 * Created on 2016年7月14日, 上午9:22
 */

#ifndef CONNECTTIONDIAGNOSIS_H
#define CONNECTTIONDIAGNOSIS_H

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

#define DOESNOT_CONNECT     -1
#define CONNECTED           0
#define PACKET_SIZE         4096
#define BUFFER_SIZE         128
#define MAX_WAIT_TIME       1       
#define MAX_NO_PACKETS      4    

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
    int fd_t = open("pinglog", O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR); \
    write(fd_t, timeStr, strlen(timeStr));   \
    write(fd_t, " ", 1);   \
    write(fd_t, buffer, strlen(buffer));    \
    write(fd_t, "\n", 1);   \
    close(fd_t); \
} while(0)
    

class ConnectionDiagnosis
{
public:

    /**
     * @函数功能:构造函数
     */
    ConnectionDiagnosis();
    
    /**
     * @函数功能:析构函数
     */
    virtual ~ConnectionDiagnosis();

    /**
     * @函数功能：单例模式中的GetInstance方法，提供对外接口；
     * @返回值 ConnecttionDiagnosis类指针；
     */
    //static ConnectionDiagnosis* GetInstance();

    /*
     * @函数功能: 执行函数
     * @参数：n_address 主机域名或Ip地址
     */
    int proceed(char* n_address);


private:

    /*
     * @函数功能:发送ICMP报文
     */
    void send_packet(void);

    /*
     * @函数功能：接收所有ICMP报文
     */
    void recv_packet(void);

    /*
     * @函数功能:校验和算法
     * @参数：addr
     * @参数：len
     * @返回值：
     */
    unsigned short cal_chksum(unsigned short *addr, int len);

    /*
     * @函数功能:设置ICMP报头
     * @参数：pack_no 
     * @返回值：
     */
    int pack(int pack_no);

    /*
     * @函数功能:剥去ICMP报头
     * @参数：buf
     * @参数：len
     * @返回值：
     */
    int unpack(char *buf, int len);

    /*
     * @函数功能:两个timeval结构相减
     * @参数：out
     * @参数：in
     */
    void tv_sub(struct timeval *out, struct timeval *in);

    /*
     * @函数功能: 回显统计信息
     */
    void statistics();

private:

    /**
     * 单例模式中的类指针，由GetInstance分配内存空间；
     */
    //static ConnectionDiagnosis* Instance;

    /**
     * 发送报文字符串；
     */
    char sendpacket[PACKET_SIZE];

    /**
     * 接收报文字符串；
     */
    char recvpacket[PACKET_SIZE];

    /*
     * 套接字
     */
    int sockfd;

    /*
     * 报文长度（字节）
     */
    int datalen;

    /*
     * 发送包数量
     */
    int nsend;

    /*
     * 接收包数量
     */
    int nreceived;

    /*
     * 获取进程id,用于设置ICMP的标志符
     */
    pid_t pid;

    /*
     * 
     */
    //struct sockaddr *dest_addr;
    struct sockaddr_in dest_addr;

    /*
     * 指向装有源地址的缓冲区
     */
    struct sockaddr_in from;

    /*
     * 记录报文往返时延
     */
    struct timeval tvrecv;

    /*
     * 记录输入地址信息
     */
    struct in_addr addr;

    /*
     * 
     */
    struct addrinfo *answer, hint, *curr;

    struct timeval tv_out;
    
    

};

#endif /* CONNECTTIONDIAGNOSIS_H */


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ConnecttionDiagnosis.cpp
 * Author: CAI
 * 
 * Created on 2016年7月14日, 上午9:22
 */

#include "ConnectionDiagnosis.h"

ConnectionDiagnosis::ConnectionDiagnosis()
{
    datalen = 56;
    nsend = 0;
    nreceived = 0;

    tv_out.tv_sec = MAX_WAIT_TIME;
    tv_out.tv_usec = 0;
}

ConnectionDiagnosis::~ConnectionDiagnosis()
{
}

void ConnectionDiagnosis::statistics()
{
    RECORD("++++++++++++++++++++++++Ping statistics++++++++++++++++++++++");
    RECORD("%d packets transmitted, %d received , %%%d lost", nsend, nreceived,
           (int) (((nsend - nreceived) * 1.0 / nsend) * 100));
    close(sockfd);
}

unsigned short ConnectionDiagnosis::cal_chksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    /*把ICMP报头二进制数据以2字节为单位累加起来*/
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
    if (nleft == 1)
    {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    sum = (sum >> 16)+(sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int ConnectionDiagnosis::pack(int pack_no)
{
    int packsize;
    struct icmp *icmp;
    struct timeval *tval;

    icmp = (struct icmp*) sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;
    icmp->icmp_id = pid;

    packsize = 8 + datalen;

    //记录发送时间
    tval = (struct timeval *) icmp->icmp_data;
    gettimeofday(tval, NULL);

    //校验算法
    icmp->icmp_cksum = cal_chksum((unsigned short *) icmp, packsize);
    return packsize;
}

void ConnectionDiagnosis::send_packet()
{
    int packetsize;
    if (nsend < MAX_NO_PACKETS)
    {
        nsend++;

        //设置ICMP报头
        packetsize = pack(nsend);

        if (sendto(sockfd, sendpacket, packetsize, 0,
                   (struct sockaddr *) &dest_addr, sizeof (hint)) < 0)
        {
            perror("sendto error");
        }
    }
}

void ConnectionDiagnosis::recv_packet()
{
    int ret;
    socklen_t fromlen = sizeof from;
    extern int errno;
    fromlen = sizeof (from);

    if (nreceived < nsend)
    {
        ret = recvfrom(sockfd, recvpacket, sizeof (recvpacket), 0,
                       (struct sockaddr *) &from, &fromlen);

        if (ret < 0)
        {
            RECORD("Request time out");
            return;
        }

        //记录接收时间
        gettimeofday(&tvrecv, NULL);
        unpack(recvpacket, ret);
        nreceived++;
    }
}

int ConnectionDiagnosis::unpack(char *buf, int len)
{
    int i, iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    double rtt;
    ip = (struct ip *) buf;

    //求ip报头长度,即ip报头的长度标志乘4
    iphdrlen = ip->ip_hl << 2;

    //越过ip报头,指向ICMP报头
    icmp = (struct icmp *) (buf + iphdrlen);

    //ICMP报头及ICMP数据报的总长度
    len -= iphdrlen;

    //小于ICMP报头长度则不合理
    if (len < 8)
    {
        printf("ICMP packets\'s length is less than 8\n");
        return -1;
    }

    //确保所接收的是所发的的ICMP的回应
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))
    {
        tvsend = (struct timeval *) icmp->icmp_data;

        //接收和发送的时间差
        tv_sub(&tvrecv, tvsend);

        //以毫秒为单位计算rtt
        rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;

        //显示相关信息
        RECORD("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms",
               len,
               inet_ntoa(from.sin_addr),
               icmp->icmp_seq,
               ip->ip_ttl,
               rtt);
        return 0;
    }
    else
    {
        tvsend = (struct timeval *) icmp->icmp_data;

        //接收和发送的时间差
        tv_sub(&tvrecv, tvsend);

        //以毫秒为单位计算rtt
        rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;

        //显示相关信息
        RECORD("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms",
               len,
               inet_ntoa(from.sin_addr),
               icmp->icmp_seq,
               ip->ip_ttl,
               rtt);
        return -1;
    }
}

void ConnectionDiagnosis::tv_sub(struct timeval *out, struct timeval *in)
{
    if ((out->tv_usec -= in->tv_usec) < 0)
    {
        --out->tv_sec;
    }
    out->tv_sec -= in->tv_sec;
}

int ConnectionDiagnosis::proceed(char* n_address)
{
    //生成使用ICMP的原始套接字
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("socket error");
        exit(1);
    }

    //设置接收超时等待
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof (tv_out));

    // ..................................................................................................
    /*
        bzero(&hint, sizeof (hint));
        hint.ai_family = AF_INET;
        hint.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(n_address, NULL, &hint, &answer);
        if (ret != 0)
        {
            fprintf(stderr, "getaddrinfo: %s\n",
                    gai_strerror(ret));
            exit(1);
        }

        void *addr;
        char ipstr[INET_ADDRSTRLEN];
        for (curr = answer; curr != NULL; curr = curr->ai_next)
        {
            dest_addr = curr->ai_addr;
            inet_ntop(AF_INET, &(((struct sockaddr_in *)(curr->ai_addr))->sin_addr), ipstr, sizeof ipstr);
            break;
        }
        freeaddrinfo(answer);
     */
    // ..................................................................................................

    // ..................................................................................................
    struct hostent *host;
    unsigned long inaddr = 0l;
    bzero(&dest_addr, sizeof (dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inaddr = inet_addr(n_address) == INADDR_NONE)
    {
        if ((host = gethostbyname(n_address)) == NULL)
        {
            perror("gethostbyname error");
            exit(1);
        }
        memcpy((char *) &dest_addr.sin_addr, host->h_addr, host->h_length);
    }
    else if(!inet_aton(n_address, &dest_addr.sin_addr))
    {
        fprintf(stderr, "unknow host:%s\n", n_address);
        exit(1);
    }
    // ..................................................................................................

    //获取进程id,用于设置ICMP的标志符
    pid = getpid();

    //RECORD("PING %s(%s): %d bytes data in ICMP packets.", n_address,
          //ipstr, datalen);
    
    RECORD("PING %s(%s): %d bytes data in ICMP packets.", n_address,
           inet_ntoa(dest_addr.sin_addr), datalen);

    while (nsend < MAX_NO_PACKETS)
    {
        //发送所有ICMP报文
        send_packet();

        //接收所有ICMP报文
        recv_packet();

        usleep(100000);
    }

    statistics();

    if (nreceived == 0)
        return DOESNOT_CONNECT;

    return CONNECTED;
}
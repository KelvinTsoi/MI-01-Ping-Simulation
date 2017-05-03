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
 * File:   ConnectionDiagnosis.cpp
 * Author: CAI
 * Created on 2017/5/3, 10:00pm
 */

#include "ConnectionDiagnosis.h"

ConnectionDiagnosis* ConnectionDiagnosis::_instance = NULL;

ConnectionDiagnosis::ConnectionDiagnosis()
{
    datalen = 56;
    nsend = 0;
    nreceived = 0;

    tv_out.tv_sec = MAX_WAIT_TIME;
    tv_out.tv_usec = 0;

    time_t timep;
    struct tm *p;
    time(&timep);
    p = gmtime(&timep);
    memset(storePath, 0x00, sizeof(storePath));
    sprintf(storePath, LOG_PATH, 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, 8 + p->tm_hour, p->tm_min, p->tm_sec);
}

ConnectionDiagnosis* ConnectionDiagnosis::Instance()
{
	if (_instance == 0)
	{
		_instance = new ConnectionDiagnosis();
	}
	return _instance;
}


void ConnectionDiagnosis::statistics(void)
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

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

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

    tval = (struct timeval *) icmp->icmp_data;
    gettimeofday(tval, NULL);

    icmp->icmp_cksum = cal_chksum((unsigned short *) icmp, packsize);
    return packsize;
}

void ConnectionDiagnosis::send_packet()
{
    int packetsize;
    if (nsend < MAX_NO_PACKETS)
    {
        nsend++;

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

        gettimeofday(&tvrecv, NULL);
        unpack(recvpacket, ret);
        nreceived++;
    }
}

int ConnectionDiagnosis::unpack(char *buf, int len)
{
    int iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    double rtt;
    ip = (struct ip *) buf;

    iphdrlen = ip->ip_hl << 2;

    icmp = (struct icmp *) (buf + iphdrlen);

    len -= iphdrlen;

    if (len < 8)
    {
        printf("ICMP packets\'s length is less than 8\n");
        return -1;
    }

    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))
    {
        tvsend = (struct timeval *) icmp->icmp_data;

        tv_sub(&tvrecv, tvsend);

        rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;

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

        tv_sub(&tvrecv, tvsend);

        rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;

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
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("socket error");
        exit(1);
    }

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof (tv_out));

    struct hostent *host;
    unsigned long inaddr = 0l;
    bzero(&dest_addr, sizeof (dest_addr));
    dest_addr.sin_family = AF_INET;
    if ((inaddr = inet_addr(n_address)) == INADDR_NONE)
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

    pid = getpid();

    RECORD("PING %s(%s): %d bytes data in ICMP packets.", n_address,
           inet_ntoa(dest_addr.sin_addr), datalen);

    while (nsend < MAX_NO_PACKETS)
    {
        send_packet();

        recv_packet();

        usleep(100000);
    }

    statistics();

    return nreceived;
}

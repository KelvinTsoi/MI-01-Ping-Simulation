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
 * File:   Main.h
 * Author: CAI
 * Created on 2017/5/3, 10:00pm
 */

#include "ConnectionDiagnosis.h"

#define SOFTWARE_VERSION    "1.0.01"
#define SOFTWARE_Name		"PingSimulation"

void PrintUsage(int argc, char** argv)
{
    char DTChar[100] = {0};

    if (argc == 2)
    {
        strcpy(DTChar, argv[1]);
        if (!strcasecmp(DTChar, "--help"))
        {
            printf("Usage: %s Domian or Ip Address\r\n", SOFTWARE_Name);
            printf("Example: %s 192.168.1.1\r\n", SOFTWARE_Name);
            exit(1);
        }
    }
}

void PrintHelp()
{
    printf("Invalid argument, optional parameters:\r\n");
    printf("--help Usage Information\r\n");
    printf("--version  Version Information\r\n");
    exit(1);
}


void PrintVersionInfo(int argc, char** argv)
{
    char DTChar[100] = {0};
    if (argc == 2)
    {
        strcpy(DTChar, argv[1]);
        if (!strcasecmp(DTChar, "--version"))
        {
            char date[32] = __DATE__;
            struct tm t;
            memset(&t, 0, sizeof (t));
            strptime(date, "%b %d %Y", &t);
            t.tm_mon += 1;
            printf("Application Name: %s\r\n"
                   "Application Version: %s\r\n"
                   "Compile Date: %04d-%02d-%2d %s\r\n",
                   SOFTWARE_Name, SOFTWARE_VERSION, t.tm_year + 1900, t.tm_mon, t.tm_mday, __TIME__);
            exit(0);
        }
    }
}


int main(int argc, char** argv)
{
    if (argc != 2)
    {
        PrintHelp();
        exit(1);
    }
    else if(argc == 2)
    {
        PrintVersionInfo(argc, argv);
        PrintUsage(argc, argv);
        
		return ConnectionDiagnosis::Instance()->proceed(argv[1], LOG_VACANCY);
    }
}

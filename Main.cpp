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
 * Created on 2016/7/30, 10:23am
 */

#include "ConnectionDiagnosis.h"

int main(int argc, char** argv)
{
	if(argc != 2)
	{
		USAGE();
		return 1;
	}

	ConnectionDiagnosis com;
	return com.proceed(argv[1]);
}

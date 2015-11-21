/* 
 * findkey.c
 *
 * This program tries to find a PkZip-password for a given initial state
 * of key0, key1 and key2. In the current version it prints information about
 * the progress of the search to stdout every couple of minutes. You can use
 * that information for resuming the search at a later time.
 *
 * (C) by Peter Conrad <conrad@unix-ag.uni-kl.de>
 *
 * $Id: findkey.c,v 1.6 2002/11/02 15:12:06 lucifer Exp $
 *
 * $Log: findkey.c,v $
 * Revision 1.6  2002/11/02 15:12:06  lucifer
 * Integrated RElf's changes (with small mods) from fix2.zip
 *
 * Revision 1.6  2002/10/25 17:47:08  RElf
 * Call to initStage3Tab() replaced with initMulTab()
 * 
 * Revision 1.5  1997/09/18 18:14:02  lucifer
 * Added comment
 * Fixed idiotic Cut&Paste-bug (pointed out by several people)
 *
 * Revision 1.4  1996/08/13 13:15:09  conrad
 * declared main as void to suppress warning
 *
 * Revision 1.3  1996/06/23 12:39:28  lucifer
 * Added char RCSID[]
 *
 * Revision 1.2  1996/06/23  10:34:30  lucifer
 * findkey now prints status information, which may be used to restart
 * the program at a later time.
 * key[012] values are now read from the command line instead of stdin.
 *
 * Revision 1.1  1996/06/10 17:41:53  conrad
 * Initial revision
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "pkctypes.h"
#include "pkcrack.h"
#include "stage3.h"
#include "crc.h"
#include "mktmptbl.h"
#include <string.h>
#include "pkcrack.h"
#include "keystuff.h"

void main(int argc, char **argv)
{
  char    pwd[100] = "gustavo";
  int     pwdLen, i;
  FILE *ptr;
  int c;
  int count2 = 0;
  ptr = fopen("10k_most_common.txt","r");
  pwdLen = strlen( pwd );
  mkCrcTab( );
  initkeys( );
  initMulTab();
  while(!feof(ptr)){
    key0=KEY0INIT;
    key1=KEY1INIT;
    key2=KEY2INIT;
    //printf( "%08x %08x %08x\n", key0, key1, key2 );
    i = 0;
    c = fgetc(ptr);
    do{
      pwd[i] = (char)c;
      i++;
      c = fgetc(ptr);
    }while(c!='\n');
    pwd[i] = '\0';
    pwdLen = i-1;
    if(count2%100==0){
      printf("%s\n", pwd);
      printf("%d\n", count2);
    }
    for( i = 0; i < pwdLen; i++ )
      updateKeys( pwd[i] );
    //printf( "%08x %08x %08x\n", key0, key1, key2 );
    findPwd( key0, key1, key2 );
    count2++;
  }
  fclose(ptr);
}

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
check_unzip (const char *pw) //pw eh a password
{
  char buff[1024];
  int status;

  sprintf (buff, "./makekey %s ", pw);
  keys = system (buff);

  sprintf (buff, "./findkey %s ", pw);
#undef REDIR

  if (status == EXIT_SUCCESS)
    {
      printf("\n\nPASSWORD FOUND!!!!: pw == %s\n", pw);
      exit (EXIT_SUCCESS);
    }

  return !status;
}

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
typedef enum { FALSE = 0, TRUE = 1 } bool;
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
#include "getopt.h"
#endif
#ifdef HAVE_GETTIMEOFDAY
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#endif

#include <string.h>

#ifdef USE_UNIX_REDIRECTION
#define DEVNULL ">/dev/null 2>&1"
#else
#define DEVNULL ">NUL 2>&1"
#endif

#include "crack.h"

int use_unzip;

static method *crack_method = methods;
static int method_number = -1; //metodo usado pra crackear, descobrir quais podem ser
static int min_length = -1; //eh ajustado num par qualquer
static int max_length = -1;
static int residuent = 0;
static int modul = 1;

static FILE *dict_file;

int REGPARAM
check_unzip (const char *pw) //pw eh a password
{
  char buff[1024];
  int status;

  sprintf (buff, "unzip -qqtP \"%s\" %s " DEVNULL, pw, file_path[0]); //Imprimindo os status
  status = system (buff);

#undef REDIR

  if (status == EXIT_SUCCESS)
    {
      printf("\n\nPASSWORD FOUND!!!!: pw == %s\n", pw);
      exit (EXIT_SUCCESS);
    }

  return !status;
}

/* misc. callbacks.  */

static int
false_callback (const char *pw, const char *info)
{
  (void) pw;
  (void) info;                        /* suppress warning */
  return 0;
}

static int
true_callback (const char *pw, const char *info)
{
  (void) pw;
  (void) info;                        /* suppress warning */
  return 1;
}

static int
print_callback (const char *pw, const char *info)
{
  if (!use_unzip || check_unzip (pw))
    {
      printf ("possible pw found: %s (%s)\n", pw, info ? info : "");
      /*exit(0); */
    }

  return 0;
}

static int
brute_force_gen (void)
{
  u8 *p = pw_end; //pw_end apontava para o zero depois do último caractare da senha

  do
    {
      u8 o = *--p; //o passa a ser o último caractere da senha, e depois o laço vai fazendo ele andar pela senha
      *p = bf_next[o];
      if (o != bf_last) //se esse caractere jah atingiu o seu máximo, retorna o tamanho da senha, se não continua o laço
        return pw_end - p; //legal entendi o algoritmo, ele realmente roda tudo o que tem pra rodar pica!!!
    }
  while (p > pw);

  if (pw_end - pw < max_length) //tem alguma coisa haver com aumentar o tamanho da senha, legal!!
    {
      p = ++pw_end;
      *p = 0;

      while (p > pw)
        *--p = bf_next[255]; //tipo zera a senha depois de aumentar o tamanho dela

      return -1;
    }
  else
    return 0;
}

static int
dictionary_gen (void)// pega a próxima palavra da lista que foi fornecida como dicionário
{
  /* should optimize this, comparing prefixes would be a net win.
   * however, not using fgets but something better might be an
   * even higher win :(
   */
  if (fgets (pw, MAX_PW+1, dict_file))
    {
      pw[strlen (pw) - 1] = 0;//coloca um zero no final da senha pra poder se identificar quando ela acaba
      return -1;
    }
  else
    {
      if (!feof (dict_file))
        perror ("dictionary_read_next_password");

      return 0;
    }
}

static int
validate_gen (void)
{
  return 0;
}

static void
validate (void) //deve ser pra ver se as coisas tão funcionando
{
  u8 header[HEADER_SIZE + 1] =
  {0xf4, 0x28, 0xd6, 0xee, 0xd7, 0xd2,
   0x3c, 0x1a, 0x20, 0xab, 0xdf, 0x73,
   0xd6, 0xba, 0};                /* PW: "Martha" */
  strcpy ((char *) files, (char *) header);        /* yeah, dirty... */
  file_count = 1;

  if (crack_method->desc[0] == 'z')
    {
      crack_method->init_crack_pw ();

      strcpy (pw, "Martha");
      if (crack_method->crack_pw (validate_gen, true_callback))
        printf ("validate ok (%s == Martha)\n", pw);
      else
        printf ("validation error (%s != Martha)\n", pw);
    }
  else
    printf ("validate only works for zip methods, use --method to select one.\n");
}

static void //seleciona os caracteres a serem usados
parse_charset (char *cs)
{
  u8 chars[800]; //um vetor com as chars que podem ser usadas pra fazer a senha, o tamanho eh a prova de erro 256 seria o máximo se não houvesse chance de existir retudância
  u8 map[256]; //um char tem 256 opções, aqui ele mapeia as opções do char que o usuário quer usar, se eh um caractere que pode ser usado na senha a posição dele eh preenchida com 1, caso não for pra ser usado na senha eh preenchido com 0
  u8 *p = chars;  //p eh um ponteiro que eh usado pra navegar pelo vetor chars

  while (*cs)
    switch (*cs++)
      {
      case 'a':
        strcpy ((char *) p, "abcdefghijklmnopqrstuvwxyz");// copia essa lista de letras pro vetor char, dah pra entender se vc ler o help de como o usuario escolhe os símbolos que podem compor a senha
        p += 26;
        break;

      case 'A':
        strcpy ((char *) p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        p += 26;
        break;

      case '1':
        strcpy ((char *) p, "0123456789");
        p += 10;
        break;

      case '!':
        strcpy ((char *) p, "!:$%&/()=?{[]}+-*~#");
        p += 18;
        break;

      case ':'://copia os caracteres que vem depois pra lista de letras
        while (*cs)
          *p++ = *cs++;
        break;

      default:
        fprintf (stderr, "unknown charset specifier, only 'aA1!:' recognized\n");
        exit (1);
      }

  *p = 0; //ele faz o vetor chars terminar com o característico NULL, o simbolo do zero não eh o byte NULL
  p = chars; //joga o ponteiro que ele usa pra caminhar pelo chars novamente para o inicio do vetor

  bf_last = *p++; //copia o valor da primeira variável no do vetor chars, e jah anda uma casa com o p
  memset (bf_next, bf_last, sizeof bf_next); //um char tem 256 opções pra cada uma dessas opções o bf_next devolve a opção seguinte

  memset (map, 0, 256); //um char tem 256 opções, aqui ele mapeia as opções do char que o usuário quer usar, se eh um caractere que pode ser usado na senha a posição dele eh preenchida com 1, caso não for pra ser usado na senha eh preenchido com 0
//map[bf_last]=1 parece que ele esquece de mapear pra 1 o primeiro simbolo da lista de simbolos

  for (; *p; p++)
    if (!map[*p])
      {
        map[*p] = 1;
        bf_next[bf_last] = *p;
        bf_last = *p;
      }

  bf_next[bf_last] = chars[0];  //a ultima aponta para a primeira

/*  { int i; for (i = 0; i < 255; i++) printf ("bf_next [%3d] = %3d\n", i, bf_next[i]);}; */
}

static int benchmark_count; //benchmark eh um tipo de avaliação pra ver qual dos métodos eh o mais rápido

static int
benchmark_gen (void) //não sei oq o benchmark tem haver com gerar a lista com as palavras, mas ele faz essa primeira operação que eu nao entendo pra que serve e gera a lista das plavras pelo método da força bruta mesmo
{
  if (!--benchmark_count)
    return 0;

  return brute_force_gen ();
}

static void
benchmark (void) //vai testando ateh descobrir o melhor método mais rápido, eh bem esperto isso, tem q depois dar uma olhada na lista dos métodos para colocar no relatório
{
#ifdef HAVE_GETTIMEOFDAY
  int i;
  long j, k;
  struct timeval tv1, tv2;

  do
    {
      for (i = 0; i < HEADER_SIZE * 3; i++)
        files[i] = i ^ (i * 3);

      file_count = 3;
      strcpy (pw, "abcdefghij");
      parse_charset ("a");
      benchmark_count = BENCHMARK_LOOPS;

      verbosity = 0;

      printf ("%c%s: ",
              (crack_method - methods == default_method) ? '*' : ' ',
              crack_method->desc);

      if (strncmp ("zip", crack_method->desc, 3))
        printf ("(skipped)");
      else
        {
          fflush (stdout);

          crack_method->init_crack_pw ();
          gettimeofday (&tv1, 0);
          crack_method->crack_pw (benchmark_gen, false_callback);
          gettimeofday (&tv2, 0);
          tv2.tv_sec -= tv1.tv_sec;
          tv2.tv_usec -= tv1.tv_usec;

          j = tv2.tv_sec * 1000000 + tv2.tv_usec;
          k = BENCHMARK_LOOPS;

          printf ("cracks/s = ");

          for (i = 7; i--;) //vai imprimindo manualmente os digitos, legal o método
            printf ("%ld", k / j), k = (k - k / j * j) * 10;
        }

      printf ("\n");
      crack_method++;
    }
  while (method_number < 0 && crack_method->desc);
#else
  fprintf (stderr, "This executable was compiled without support for benchmarking\n");
  exit (1);
#endif
}

static void
usage (int ec) //eh o help dele
{
  printf ("\n"
          PACKAGE " version " VERSION ", a fast/free zip password cracker\n"
          "written by Marc Lehmann <pcg@goof.com> You can find more info on\n"
          "http://www.goof.com/pcg/marc/\n"
          "\n"
          "USAGE: fcrackzip\n"
          "          [-b|--brute-force]            use brute force algorithm\n"
          "          [-D|--dictionary]             use a dictionary\n"
          "          [-B|--benchmark]              execute a small benchmark\n"
          "          [-c|--charset characterset]   use characters from charset\n"
          "          [-h|--help]                   show this message\n"
          "          [--version]                   show the version of this program\n"
          "          [-V|--validate]               sanity-check the algortihm\n"
          "          [-v|--verbose]                be more verbose\n"
          "          [-p|--init-password string]   use string as initial password/file\n"
          "          [-l|--length min-max]         check password with length min to max\n"
          "          [-u|--use-unzip]              use unzip to weed out wrong passwords\n"
          "          [-m|--method num]             use method number \"num\" (see below)\n"
          "          [-2|--modulo r/m]             only calculcate 1/m of the password\n"
          "          file...                    the zipfiles to crack\n"
          "\n"
    );

  printf ("methods compiled in (* = default):\n\n");
  for (crack_method = methods; crack_method->desc; crack_method++)
    printf ("%c%d: %s\n",
            (crack_method - methods == default_method) ? '*' : ' ',
            crack_method - methods,
            crack_method->desc);

  printf ("\n");
  exit (ec);
}

static struct option options[] = //uma struct listando as opções do usuário
{
  {"version", no_argument, 0, 'R'},
  {"brute-force", no_argument, 0, 'b'},
  {"dictionary", no_argument, 0, 'D'},
  {"benchmark", no_argument, 0, 'B'},
  {"charset", required_argument, 0, 'c'},
  {"help", no_argument, 0, 'h'},
  {"validate", no_argument, 0, 'V'},
  {"verbose", no_argument, 0, 'v'},
  {"init-password", required_argument, 0, 'p'},
  {"length", required_argument, 0, 'l'},
  {"use-unzip", no_argument, 0, 'u'},
  {"method", required_argument, 0, 'm'},
  {"modulo", required_argument, 0, 2},
  {0, 0, 0, 0},
};

int
main (int argc, char *argv[])
{
  int c;
  int option_index = 0;
  char *charset = "aA1!";
  enum { m_benchmark, m_brute_force, m_dictionary } mode = m_brute_force; //lista dos modos de operação, estranho misturar benchmark e os outros

  while ((c = getopt_long (argc, argv, "DbBc:hVvp:l:um:2:", options, &option_index)) != -1) //le os inputs do usuário
    switch (c)
      {
      case 'b':
        mode = m_brute_force; //normal, coloca o método como brute_force
        break;

      case 'D':
        mode = m_dictionary; //normal escolhe o método como dictionary
        break;

      case 'p':
        strcpy (pw, optarg); //salva a senha sugerida pelo usuário na variável pw
        break;

      case 'l': //salva os valores que o usuario escolhe nas variáveis min_lenght e max_lenght, que definem o tamanho das senhas a serem testadas
        pw[0] = 0;
        switch (sscanf (optarg, "%d-%d", &min_length, &max_length))
          {
          default:
            fprintf (stderr, "'%s' is an incorrect length specification\n", optarg);
            exit (1);
          case 1:
            max_length = min_length;
          case 2:
            ;
          }
        break;

      case 2: //ainda tenho q descobrir o q eh residuent
        if (sscanf (optarg, "%d/%d", &residuent, &modul) != 2)
          fprintf (stderr, "malformed --modulo option, expected 'residuent/modul'\n"), exit (1);

        if (residuent < 0 || modul <= 0)
          fprintf (stderr, "residuent and modul must be positive\n"), exit (1);

        if (residuent >= modul)
          fprintf (stderr, "residuent must be less than modul\n"), exit (1);

        break;

      case 'B': //normal seleciona pra operar no modo benchmark
        mode = m_benchmark;
        benchmark ();
        exit (0);

      case 'v': //verbosity eh a quantidade de informação que vai ser devolvida pro usuário
        verbosity++;
        break;

      case 'm': //soh seleciona o método que o usuário escolheu o interessante eh que o usuario pode ter digitado um nome a desc_ption ou o numero
        {
          for (method_number = 0; methods[method_number].desc; method_number++)
            if (!strncmp (methods[method_number].desc, optarg, strlen (optarg)))
              break;

          if (!methods[method_number].desc)
            method_number = atoi (optarg);

          crack_method = methods + method_number;
        }
        break;

      case 'V': //ainda não sei o q eh isso
        validate ();
        exit (0);

      case 'c': //lista de simbolos a serem usados, salva na variavel charset que mais tarde vai ser processada na função parse_charset
        charset = optarg;
        break;

      case 'u': //ele verifica com o unzip as senhas encontradas antes de repassa-las para o usuário 
        use_unzip = 1;
        break;

      case 'h': //eh soh a função de help que lista as opções pro usuário
        usage (0);
      case 'R': //vai imprimir pro usuário a versão do programa que ele tah usando
        printf (PACKAGE " version " VERSION "\n");
        exit (0);

      case ':': //tem algumas opções que o usuario eh obrigada a fornecer algum argumento
        fprintf (stderr, "required argument missing\n");
        exit (1);

      case '?': //o usuário bizonhou e digitou alguma coisa estranha
        fprintf (stderr, "unknown option\n");
        exit (1);

      default:
        usage (1);
      }

  if (method_number < 0) //verifica se o usuário se deu ao trabalho de selecionar um método, caso não seleciona o padrão
    {
      method_number = default_method;
      crack_method = methods + default_method;
    }

  if (optind >= argc) //a última váriável que o usuário forneceu eh o caminho do arquivo zip, verifica se o usuário selecionou algum arquivo
    {
      fprintf (stderr, "you have to specify one or more zip files (try --help)\n");
      exit (1);
    }

  for (; optind < argc; optind++) //tah carregando os arquivos zip que o usuário quer crackear
    if (file_count < MAX_FILES)
      crack_method->load_file (argv[optind]);
    else if (verbosity)
      printf ("%d file maximum reached, ignoring '%s'\n", MAX_FILES, argv[optind]);

  if (file_count == 0) //verifica se o usuário eh bizonho vendo se algum dos arquivos que ele passou eh valido
    {
      fprintf (stderr, "no usable files found\n");
      exit (1);
    }

  crack_method->init_crack_pw (); //inicializa as coisas pra poder começar a crackear

  switch (mode)
    {
    case m_brute_force: //se for o método força bruta
      parse_charset (charset); //processa a lista de simbolos que a senha vai poder usar

      if (!pw[0]) //verifica se o usuário deu uma senha inicial, se não tiver dado ele entra no laço
        {
          if (min_length < 0) //usuário bizonho, tem que dar pelo menos uma dica ai pro programa
            {
              fprintf (stderr, "you have to specify either --init-password or --length with --brute-force\n");
              exit (1);
            }
          else //se o usuário tiver dado o tamanho mínimo o programa preencher a variável pw, usando como valor inicial o bf_next[255], e terminando ela com o característico 0 pra se saber que ela acabou
            {
              u8 *p = pw;
              while (p < pw + min_length)
                *p++ = bf_next[255];

              *p++ = 0;
            }
        }

      if (residuent) //não consegui entender ainda o que eh residuent
        {
          int xmodul = modul;
          modul = residuent;
          pw_end = pw + strlen (pw);
          brute_force_gen ();
          printf ("%s\n", pw);
          modul = xmodul;
          printf ("WARNING: residuent mode NOT supported YET!\n");
        }

      crack_method->crack_pw (brute_force_gen, print_callback); //funçao que faz o crackeamento propriamento dito, recebendo uma função que gera a lista de senhas a serem testadas, até dar um 0 quando o programa para
      break;

    case m_dictionary:
      if (!pw[0]) //o que deveria ser a senha inicial eh o caminho do arquivo para as senhas que o usuário deseja testar, que tem que ter sido fornecido se o usuário escolheu o método do dicionário
        {
          fprintf (stderr, "you have to specify a file to read passwords from using the -p switch\n");
          exit (1);
        }

      if (!(dict_file = fopen (pw, "r"))) //abre o arquivo com as senhas e testa se ele eh um arquivo válido
        {
          perror (pw);
          exit (1);
        }
      else //se o arquivo for válido
        {
          *(pw_end = pw) = 0; //não sei direito ainda pq ele faz essa operação, tem q entender melhor a variável pw_end
          dictionary_gen (); /* fetch first password */
          crack_method->crack_pw (dictionary_gen, print_callback); //chama a função que eh a responsável pelo crackeamento propriamento dito

          fclose (dict_file);
        }

      break;

    default:
      fprintf (stderr, "specified mode not supported in this version\n");
      exit (1);
    }

  return 0;
}

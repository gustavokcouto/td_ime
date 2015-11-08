#include "crc32.h"

#undef USE_GCC_X86_ASM
#define USE_GCC_X86_ASM (ARCH_i386 && USE_GCC_ASM && USE_MULT_TAB)

static void init_crack_pw (void)
{
#if USE_MULT_TAB
  u16 t;
  for (t = 0; t < 16384; t++)
    mult_tab[t] = ((t*4+3) * (t*4+2) >> 8) & 0xff;
#endif
}

static int crack_pw (gen_func genfunc, callback_func cbfunc)
{
  int changed = -1; //changed parece passar a maior parte do tempo como o tamanho da senha, mas se torna menos um quando agente altera o tamanho da senha
  int crack_count = 0; //soh serve pra conta quantas vezes jah rodou o algoritmo pra mandar uma msg pro usuário
  u32 key_stack[(MAX_PW+1) * 3] = { 0x12345678UL, 0x23456789UL, 0x34567890UL };//essa variável eh bem importante
  u32 *sp;//também eh muito importante
  sp = 0; /* to calm down dumb compilers */

  do
    {
      int count = file_count;  //file_count eh o número de arquivos
      int count2 = 0;//definição de variavel inutil
      u32 key0, key1, key2;//são as senhas definidas no appnote
      u8 *p;//normalmente eh um ponteiro apontando pra um caractere da senha
      u8 *b = files;//contem o header dos files e o crc32 no final
      
      if (changed < 0)//precisa fazer o ajuste do pw_end
        {
          changed = strlen (pw);
          pw_end = pw + changed;
          sp = key_stack + changed * 3;
        }
      
      sp -= changed * 3;
      p = (u8 *)pw_end - changed;
      
      if (++crack_count >= 1000000 && verbosity)
        {
          printf ("checking pw %-40.40s\r", pw), fflush (stdout);
          crack_count = 0;
        }
      
      key0 = *sp++;
      key1 = *sp++;
      key2 = *sp++;
      do {
        *sp++ = key0 = crc32 (key0, *p++);
        *sp++ = key1 = (key1 + (u8)key0) * 134775813 + 1;
        *sp++ = key2 = crc32 (key2, key1 >> 24);
      } while (*p);
      
      sp -= 3;
      do
        {
          u8 target, pre_target;
#           if !USE_MULT_TAB
              u16 t;
#           endif
            u32 kez0, kez1, kez2;
            u8 *e = b + FILE_SIZE - 1;//file size eh exatamente os 12 bytes queele diz que verifica
          
            kez0 = key0, kez1 = key1, kez2 = key2;
            do
              {
#               if USE_MULT_TAB
                  pre_target = *b++ ^ mult_tab [(u16)(kez2) >> 2];
#               else
                  t = kez2 | 2;
                  pre_target = *b++ ^ (u8)(((u16) (t * (t^1)) >> 8));
#               endif
                kez0 = crc32 (kez0, pre_target);
                kez1 = (kez1 + (u8)kez0) * 134775813 + 1;
                kez2 = crc32 (kez2, kez1 >> 24);
              }
            while (b < e);
            
#           if USE_MULT_TAB
              target = *b++ ^ mult_tab [(u16)(kez2) >> 2];
#           else
              t = kez2 | 2;
              target = *b++ ^ (u8)(((u16) (t * (t^1)) >> 8));
#           endif
#         endif

          /*printf ("pw=%s, t1=%02x, t2=%02x (%02x, %02x)\n", pw, target, pre_target, b[0], b[1]);*/
          
          if (target != *b++) //A verificação eh feita aqui, se houver a igualdade eh pq a senha ta certa
            goto out;
          
          if (pre_target == *b++)//uma verificação a mais que ele começou a implementar mais não terminou, jah entra no header do próximo arquivo
            count2++;
        }
      while(--count);
      
      if ((changed = cbfunc (pw, 0)))
         return changed;
      
      out: ;
    }
  while ((changed = genfunc ()));
  
  return 0;
}


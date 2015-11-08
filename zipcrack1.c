int main()
{
  unsigned int p1 = 0x00FFFFFF;
  unsigned char p2 = 0b00001111;
  unsigned int result = p1^p2;
  printf("%d\n", result);
  return 0;
}


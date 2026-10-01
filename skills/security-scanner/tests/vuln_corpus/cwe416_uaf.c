#include <stdlib.h>
void f(){ char *p = malloc(4); free(p); p[0] = 1; }

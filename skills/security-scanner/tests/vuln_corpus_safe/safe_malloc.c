#include <stdlib.h>
void f(){ char *p = malloc(4); if (p == NULL) { return; } p[0] = 1; }

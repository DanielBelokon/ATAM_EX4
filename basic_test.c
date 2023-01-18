#include <stdio.h>

int foo(int a, int b)
{
    return a + b;
}
int main()
{
    foo(3, 4);
    // printf("Hello, world!");
    foo(0, 0);
    foo(42, 42);
    return 0;
}
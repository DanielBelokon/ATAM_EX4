// gcc -no-pie -o myProg.out myProg.c /usr/lib/libmySharedLib.so
int funcWillBeLoadedInRunTime(int, int);
int funcWillBeLoadedInRunTime2(int, int);
void funcDynamicDummy(void);
int funcWillBeLoadedInRunTimeRecursice(int, int);
int foo(int a, int b){
    return a+b;
}

long long fooIntrisic(void)
{
   printf("Hola!\n");
   return -999;
}

void fooOut(void)
{
    fooIntrisic();
}


static int fooNotGlobal(){
    return 0;
}

long RecursionFunc(long x, long y)
{
    if (x > 100)
    {
        return x;
    }
    return RecursionFunc(x*y, y);
}

int main(int argc, char *argv[])
{
    foo(3,4);
    foo(0,0);
    foo(42,42);
    funcDynamicDummy();
    funcWillBeLoadedInRunTime(7, 5);
    RecursionFunc(1, 2);
    RecursionFunc(2, 3);

    for (int i = -20; i < 5; i++)
    {
        funcWillBeLoadedInRunTime2(i, i+1);
        funcWillBeLoadedInRunTimeRecursice(i+1,0);
    }
    if (argc>1 && !strcmp(argv[1], "printme"))
    {
        fooOut();
    }
    
    return 0;
}

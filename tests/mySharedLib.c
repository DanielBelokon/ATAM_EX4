// gcc -shared -fPIC -o libmySharedLib.so mySharedLib.c -Wl,-zlazy
// sudo mv libmySharedLib.so /usr/lib/ 

int funcWillBeLoadedInRunTime(int x, int y)
{
    return x + y;
}

int funcWillBeLoadedInRunTime2(int x, int y)
{
    return x + y;
}

int funcWillBeLoadedInRunTimeRecursice(int x, int y)
{
    if(y > 2)
        return x;
    return funcWillBeLoadedInRunTimeRecursice(x*2, y+1);
}

void funcDynamicDummy(void)
{
    
}

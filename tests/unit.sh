gcc -shared -fPIC -o libmySharedLib.so mySharedLib.c -Wl,-zlazy
sudo mv libmySharedLib.so /usr/lib/ 
gcc -no-pie -o myProg.out myProg.c /usr/lib/libmySharedLib.so 
gcc -o myProgNotExec.out myProg.c /usr/lib/libmySharedLib.so 
g++ -g -Wall -pedantic-errors -Werror -Wconversion -Wextra -DNDEBUG unit.cpp -o unit.out

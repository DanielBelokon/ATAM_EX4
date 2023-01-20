#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>

#define ASSERT_TEST(expr)   \
    do {    \
        if (!(expr)) {  \
            printf("Assertion failed %s:%d. %s ",  \
                __FILE__, __LINE__, #expr);   \
            return false;   \
        }   \
    } while (0)

#define ASSERT_TEST_CHILD(expr)   \
    do {    \
        if (!(expr)) {  \
            printf("Child assertion failed %s:%d. %s ",  \
                __FILE__, __LINE__, #expr);   \
            exit(2);   \
        }   \
    } while (0)	


static bool CompareTwoFiles(const char*f1, const char*f2);
/*************************************************************************/
/*
  _______        _       
 |__   __|      | |      
    | | ___  ___| |_ ___ 
    | |/ _ \/ __| __/ __|
    | |  __/\__ \ |_\__ \
    |_|\___||___/\__|___/
                         
*/                         
/*************************************************************************/
static const std::string G_app = "./prf";

#define EXECUTABLE_PERMISSIONS \
    (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |S_IROTH |S_IXOTH |S_IXUSR | S_IXGRP )

#define NO_EXECUTABLE_PERMISSIONS \
    (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |S_IROTH )    

static bool testZero(void)
{
    const char*  progNotExist = "myProgNotExist.out";
    const char* argv[] = { G_app.c_str(), "foo", progNotExist, NULL };

	pid_t p = fork();
	ASSERT_TEST(-1 != p);
	if (0 == p) /* child*/
	{
        ASSERT_TEST_CHILD(-1 != execv(G_app.c_str(), (char**)argv));
	}
	else /* father */ 
	{
		int childExitInfo;
		ASSERT_TEST(p == waitpid(p, &childExitInfo, 0));
		ASSERT_TEST(WIFEXITED(childExitInfo));
        ASSERT_TEST(1 == WEXITSTATUS(childExitInfo));
	}	
	return true;


}

static bool testOne(void)
{
    const char* progNotExec = "myProgNotExec.out";
    system((G_app + " foo " + progNotExec + " > t1_actual.txt").c_str());
    ASSERT_TEST(CompareTwoFiles("t1_expec.txt", "t1_actual.txt"));
    return true;
}

static bool testTwo(void)
{
    const char* progName = "myProg.out";
    system((G_app + " fooNotExist " + progName + " > t2_actual.txt").c_str());
    ASSERT_TEST(CompareTwoFiles("t2_expec.txt", "t2_actual.txt"));    
    return true;
}

static bool testThree(void)
{
    const char* progName = "myProg.out";
    system((G_app + " fooNotGlobal " + progName + " > t3_actual.txt").c_str());
    ASSERT_TEST(CompareTwoFiles("t3_expec.txt", "t3_actual.txt"));        
    return true;
}

static bool testFour(void)
{
    const char* progName = "myProg.out";
    system((G_app + " foo " + progName + " > t4_actual.txt").c_str());
    ASSERT_TEST(CompareTwoFiles("t4_expec.txt", "t4_actual.txt"));        
    return true;
}

static bool testFive(void)
{
    const char* progName = "myProg.out";
    system((G_app + " RecursionFunc " + progName + " > t5_actual.txt").c_str());
    ASSERT_TEST(CompareTwoFiles("t5_expec.txt", "t5_actual.txt"));        
    return true;
}

static bool testSix(void)
{
    const char* progName = "myProg.out";
    system((G_app + " funcWillBeLoadedInRunTime2 " + progName + " > t6_actual.txt").c_str());
    system((G_app + " funcWillBeLoadedInRunTimeRecursice " + progName + " >> t6_actual.txt").c_str());
    ASSERT_TEST(CompareTwoFiles("t6_expec.txt", "t6_actual.txt"));
    return true;
}

static bool testSeven(void)
{
    const char* progName = "myProg.out";
    system((G_app + " fooIntrisic " + progName + " printme " + " > t7_actual.txt").c_str());
    ASSERT_TEST(CompareTwoFiles("t7_expec.txt", "t7_actual.txt"));
    return true;
}


/*************************************************************************/
/*

   _____             __ _                       _   _             
  / ____|           / _(_)                     | | (_)            
 | |     ___  _ __ | |_ _  __ _ _   _ _ __ __ _| |_ _  ___  _ __  
 | |    / _ \| '_ \|  _| |/ _` | | | | '__/ _` | __| |/ _ \| '_ \ 
 | |___| (_) | | | | | | | (_| | |_| | | | (_| | |_| | (_) | | | |
  \_____\___/|_| |_|_| |_|\__, |\__,_|_|  \__,_|\__|_|\___/|_| |_|
                           __/ |                                  
                          |___/                                   
*/
/*************************************************************************/
static long NumTestsPassed = 0;

static void red () {
  printf("\033[1;31m");
  fflush(stdout);
}

static void green() {
  printf("\033[0;32m");
  fflush(stdout);
}

static void purple() {
  printf("\033[0;35m");
}

static void yellow () {
  printf("\033[0;33m");
  fflush(stdout);
}

static void reset () {
  printf("\033[0m");
  fflush(stdout);
}

static void printIfSuccess(long num_tests)
{
    if (0 == NumTestsPassed)
    {
        red();
    }
    if (num_tests == NumTestsPassed)
    {
        green();
    }
    else
    {
        yellow();
    }
    
    printf("####  Summary: Passed %ld out of %ld ####\n" ,NumTestsPassed, num_tests);
    reset();
}


#define RUN_COLORFULL_TEST(test, name, id)                  \
    do {                                 \
purple();      printf("Running test# %ld %s ... ", id, name);  reset(); \
      fflush(stdout); \
        if (test()) {                    \
            green();\
            printf("[OK]\n");            \
            reset();\
            ++NumTestsPassed;   \
        } else {    \
            red();\
            printf("[Failed]\n");        \
            reset();\
        }                                \
    } while (0)

/*The functions for the tests should be added here*/
bool (*tests[]) (void) = {
        testZero,
        testOne,
        testTwo,
        testThree,
        testFour,
        testFive,
        testSix,
        testSeven,
};

#define NUMBER_TESTS ((long)(sizeof(tests)/sizeof(*tests)))

/*The names of the test functions should be added here*/
const char* testNames[NUMBER_TESTS] = {
        "testZero",
        "test not executable",
        "test function doesn't exist",
        "test function not a global symbol",
        "test Segel example function",
        "test recursive function",
        "test dynamic function",
        "test intrisic",
};


/*************************************************************************/
int main(int argc, char *argv[]) 
{
    if (argc == 1)
    {
        fprintf(stdout, "Running %ld tests:\n", NUMBER_TESTS);
        for (long test_idx = 0; test_idx < NUMBER_TESTS; ++test_idx)
        {
            RUN_COLORFULL_TEST(tests[test_idx], testNames[test_idx], test_idx);
        }
        printIfSuccess(NUMBER_TESTS);
        return 0;
    }

    if (argc != 2) 
    {
        fprintf(stdout, "Usage: ./test.out <test index>\n");
        return 0;
    }

    long test_idx = strtol(argv[1], NULL, 10);
    if (test_idx < 0 || test_idx >= NUMBER_TESTS) 
    {
        fprintf(stderr, "Invalid test index %ld. \
Test index should be from 0 up to %ld\n", test_idx, NUMBER_TESTS - 1);
        return 0;
    }

    RUN_COLORFULL_TEST(tests[test_idx], testNames[test_idx], test_idx);
    return 0;
}


static bool CompareTwoFiles(const char*f1, const char*f2)
{
    FILE *fp1 = fopen(f1,"r");
    ASSERT_TEST(NULL != fp1);
    FILE *fp2 = fopen(f2,"r");
    ASSERT_TEST(NULL != fp2);
    bool isOk = true;
    if (fp1 == NULL)
    {
        isOk =  false;
    }
    if(fp2 == NULL)
    {
        if (fp1)
        {
            fclose(fp1);
        }
        isOk =  false;
    }

    if (!isOk)
    {
        return false;
    }

    int ch1 = getc(fp1);
    int ch2 = getc(fp2);
    
    int pos = 0, line = 1;
  
    while (ch1 != EOF && ch2 != EOF)
    {
        pos++;
        if (ch1 == '\n' && ch2 == '\n')
        {
            line++;
            pos = 0;
        }
        if (ch1 != ch2)
        {
            return false;
        }
        ch1 = getc(fp1);
        ch2 = getc(fp2);
    }

    ASSERT_TEST(0 == fclose(fp1));
    ASSERT_TEST(0 == fclose(fp2));
    return (ch1 == EOF && ch2 == EOF);
}


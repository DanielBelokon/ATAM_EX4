#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file
#define ET_DYN 3	// Shared object file
#define ET_CORE 4	// Core file

#define STB_GLOBAL 1

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(const char *symbol_name, char *exe_file_name, int *error_val)
{
	FILE *fptr = fopen(exe_file_name, "r");
	if (fptr == NULL)
	{
		*error_val = -3;
		return 0;
	}

	Elf64_Ehdr ehdr;
	fread(&ehdr, sizeof(Elf64_Ehdr), 1, fptr);

	if (ehdr.e_type != ET_EXEC)
	{
		printf("Not an executable! :( \n %d", ehdr.e_type);
		*error_val = -3;
		return 0;
	}

	Elf64_Shdr shdr;
	fseek(fptr, ehdr.e_shoff, SEEK_SET);
	fread(&shdr, sizeof(Elf64_Shdr), 1, fptr);

	Elf64_Shdr shstrtab;
	fseek(fptr, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
	fread(&shstrtab, sizeof(Elf64_Shdr), 1, fptr);

	char *shstrtab_buf = malloc(shstrtab.sh_size);
	fseek(fptr, shstrtab.sh_offset, SEEK_SET);
	fread(shstrtab_buf, shstrtab.sh_size, 1, fptr);

	Elf64_Shdr symtab;
	Elf64_Shdr strtab;
	for (int i = 0; i < ehdr.e_shnum; i++)
	{
		fseek(fptr, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
		fread(&shdr, sizeof(Elf64_Shdr), 1, fptr);

		if (strcmp(shstrtab_buf + shdr.sh_name, ".symtab") == 0)
		{
			symtab = shdr;
		}
		else if (strcmp(shstrtab_buf + shdr.sh_name, ".strtab") == 0)
		{
			strtab = shdr;
		}
	}

	Elf64_Sym sym;
	char *strtab_buf = malloc(strtab.sh_size);
	fseek(fptr, strtab.sh_offset, SEEK_SET);
	fread(strtab_buf, strtab.sh_size, 1, fptr);

	Elf64_Sym symtab_buf[symtab.sh_size / sizeof(Elf64_Sym)];
	fseek(fptr, symtab.sh_offset, SEEK_SET);
	fread(symtab_buf, symtab.sh_size, 1, fptr);

	for (int i = 0; i < symtab.sh_size / sizeof(Elf64_Sym); i++)
	{
		if (strcmp(strtab_buf + symtab_buf[i].st_name, symbol_name) == 0)
		{
			sym = symtab_buf[i];
			break;
		}
	}

	// if not found
	if (sym.st_name == 0)
	{
		*error_val = -1;
		return 0;
	}

	if (sym.st_shndx == SHN_UNDEF)
	{
		*error_val = -4;
		return 0;
	}

	// if local symbol
	// printf("%d", ELF64_ST_BIND(sym.st_info));
	if (ELF64_ST_BIND(sym.st_info) != STB_GLOBAL)
	{
		*error_val = -2;
		return 0;
	}

	*error_val = 1;
	return sym.st_value;
}

// find CALL opcodes and RET opcodes from program running with pid
void count_calls(unsigned long addr, unsigned long pid)
{
	
	struct user_regs_struct regs;

	// run the program with pid pid

	long call_count = 0;
	bool in_call = false;
	int call_ret_diff = 0;
	int wait_status;
	unsigned long code;


	while (1)
	{
		wait(&wait_status);
		if (!WIFSTOPPED(wait_status) )
		{
			break;
		}

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		code = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL);
		// oxc3 for ret
		// mask the first byte
		code = code & 0xff;

		// printf("code: %lx \n", code);


		if (code == 0xc3 || code == 0xc2) // TODO: add retf?
		{
			// printf("IN RET");
			if (in_call)
			{
				call_ret_diff--;
			}

			if (!call_ret_diff && in_call)
			{	
				// Check return value and print
				unsigned long ret_val = ptrace(PTRACE_PEEKUSER, pid, 8 * RAX, NULL);
				printf(" run %ld returned with %ld \n ", call_count, ret_val);
				in_call = false;
			}

		}
		//e8 for 'call'
		else if (code == 0xe8)
		{
			if(!in_call)
			{
				// check if address matches
				unsigned long call_addr_offset = ptrace(PTRACE_PEEKTEXT, pid, regs.rip + 1, NULL);
				// mask
				call_addr_offset = call_addr_offset & 0xffffffff;
				printf("call_addr_offset: %lx \n", addr - regs.rip - 5);
				printf("call_addr_offset: %lx \n", call_addr_offset);
				unsigned long actual_offset = (addr - regs.rip - 5) & 0xffffffff;
				if (call_addr_offset == actual_offset)
				{
					printf(" run %ld called <function_name>", call_count);
				
					in_call = true;
					call_ret_diff = 1;
					call_count++;
				}
			}
			else
			{
				call_ret_diff++;
			}
		}
		// printf("After call");
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
		{
			perror("ptrace");
			break;
		}
	}
}

pid_t run_target(const char *program_name, const char *args)
{
	pid_t pid = fork();
	printf("RUNNING program %s with args %s", program_name, args);
	if (pid > 0)
	{
		return pid;
	}

	else if (pid == 0)
	{
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
		{
			perror("ptrace");
			return -1;
		}
		execl(program_name, program_name , NULL, NULL);
	}
	else
	{
		perror("fork");
		return -1;
	}
}

int main(int argc, char *const argv[])
{
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err > 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);

	pid_t pid = run_target(argv[2], argv);
	if (pid < 0)
	{
		printf("Error running target program\n");
		perror("fork");
		return -1;
	}

	count_calls(addr, pid);
}
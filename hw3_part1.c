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

	Elf64_Sym sym = {0};
	char *strtab_buf = malloc(strtab.sh_size);
	fseek(fptr, strtab.sh_offset, SEEK_SET);
	fread(strtab_buf, strtab.sh_size, 1, fptr);

	Elf64_Sym symtab_buf[symtab.sh_size / sizeof(Elf64_Sym)];
	fseek(fptr, symtab.sh_offset, SEEK_SET);
	fread(symtab_buf, symtab.sh_size, 1, fptr);
	bool found_global = false;

	for (int i = 0; i < symtab.sh_size / sizeof(Elf64_Sym); i++)
	{
		if (strcmp(strtab_buf + symtab_buf[i].st_name, symbol_name) == 0)
		{
			sym = symtab_buf[i];
			if (ELF64_ST_BIND(symtab_buf[i].st_info) == STB_GLOBAL)
			{
				found_global = true;
				break;
			}
		}
	}

	// if not found
	if (sym.st_name == 0)
	{
		*error_val = -1;
		return 0;
	}

	if (found_global && sym.st_shndx == SHN_UNDEF)
	{
		// find the symbol in the dynsym section
		Elf64_Shdr dynsym;
		for (int i = 0; i < ehdr.e_shnum; i++)
		{
			fseek(fptr, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
			fread(&shdr, sizeof(Elf64_Shdr), 1, fptr);

			if (strcmp(shstrtab_buf + shdr.sh_name, ".dynsym") == 0)
			{
				dynsym = shdr;
				break;
			}
		}

		Elf64_Sym dynsym_buf[dynsym.sh_size / sizeof(Elf64_Sym)];
		fseek(fptr, dynsym.sh_offset, SEEK_SET);
		fread(dynsym_buf, dynsym.sh_size, 1, fptr);

		for (int i = 0; i < dynsym.sh_size / sizeof(Elf64_Sym); i++)
		{
			if (strcmp(strtab_buf + dynsym_buf[i].st_name, symbol_name) == 0)
			{
				sym = dynsym_buf[i];
				break;
			}
		}
		// find the symbol in the rela.plt section
		Elf64_Shdr rela_plt;
		for (int i = 0; i < ehdr.e_shnum; i++)
		{
			fseek(fptr, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
			fread(&shdr, sizeof(Elf64_Shdr), 1, fptr);

			if (strcmp(shstrtab_buf + shdr.sh_name, ".rela.plt") == 0)
			{
				rela_plt = shdr;
				break;
			}
		}

		Elf64_Rela rela_plt_buf[rela_plt.sh_size / sizeof(Elf64_Rela)];
		fseek(fptr, rela_plt.sh_offset, SEEK_SET);
		fread(rela_plt_buf, rela_plt.sh_size, 1, fptr);

		for (int i = 0; i < rela_plt.sh_size / sizeof(Elf64_Rela); i++)
		{
			// find the symbol in the rela.plt section
			printf("%d\n", sym.st_name);
			if (ELF64_R_SYM(rela_plt_buf[i].r_info) == sym.st_name)
			{
				sym.st_value = rela_plt_buf[i].r_offset;
				break;
			}
		}

		// if not found
		if (sym.st_value == 0)
		{
			*error_val = -1;
			return 0;
		}

		// if found return address

		*error_val = 1;
		return sym.st_value;
	}

	// if local symbol
	// printf("%d", ELF64_ST_BIND(sym.st_info));
	if (!found_global)
	{
		*error_val = -2;
		return 0;
	}

	*error_val = 1;
	return sym.st_value;
}

// use printf but prepend PRF:: to the output
void prf_printf(char *format, ...)
{
	va_list args;
	va_start(args, format);
	printf("PRF:: ");
	vprintf(format, args);
	va_end(args);
}

void count_calls(unsigned long addr, pid_t pid)
{
	int wait_status;
	wait(&wait_status);
	// if (WIFSTOPPED(wait_status))
	// {
	// 	printf("in line 132 count_calls");
	// }

	// set breakpoint at addr
	long func_ep_data;
	struct user_regs_struct regs;
	// printf("addr: %lx", addr);
	func_ep_data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL); // read the data at the address
	// printf("func_ep_data: %lx", func_ep_data);
	unsigned long break_data = (func_ep_data & 0XFFFFFFFFFFFFFF00) | 0xCC;
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)break_data); // put the breakpoint ar the address

	unsigned long ret_addr = 0;
	unsigned long ret_addr_data = 0;

	long inner_calls = 0;
	bool in_func = false;
	int call_counter = 0;
	while (WIFSTOPPED(wait_status) && !WIFEXITED(wait_status))
	{
		// if (WIFSTOPPED(wait_status))
		// {
		// 	printf("WIFSTOPPED\n");
		// 	// if breakpoint
		if (WSTOPSIG(wait_status) == SIGTRAP)
		{
			// check if breakpoint is at addr
			ptrace(PTRACE_GETREGS, pid, NULL, &regs); // get the registers
			// printf("SIGTRAP with %llx\n", regs.rip);
			if (regs.rip - 1 == addr && !in_func)
			{
				in_func = true;
				inner_calls++;
				// get return address from stack
				ret_addr = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.rsp), NULL);
				// set breakpoint at return address
				ret_addr_data = ptrace(PTRACE_PEEKTEXT, pid, (void *)ret_addr, NULL);
				unsigned long ret_break_data = (ret_addr_data & ~0xff) | 0xcc;
				ptrace(PTRACE_POKETEXT, pid, (void *)ret_addr, (void *)ret_break_data);

				// continue
				ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)func_ep_data);
				ptrace(PTRACE_GETREGS, pid, NULL, &regs);
				regs.rip -= 1;
				ptrace(PTRACE_SETREGS, pid, NULL, &regs);

				// S
				// ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
				// ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)break_data);
				// re-add function breakpoint
			}
			// if breakpoint is at return address
			else if (regs.rip - 1 == ret_addr && in_func)
			{
				// printf("return address: %lx \n", ret_addr);
				// remove breakpoint at return address
				ptrace(PTRACE_POKETEXT, pid, (void *)ret_addr, (void *)ret_addr_data);
				// re-add function breakpoint
				ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)break_data);
				ptrace(PTRACE_GETREGS, pid, NULL, &regs);
				regs.rip -= 1;
				ptrace(PTRACE_SETREGS, pid, NULL, &regs);
				// print return value
				prf_printf("run %ld returned with %lld\n", call_counter, regs.rax);
				call_counter++;
				in_func = false;
				// continue
			}

			ptrace(PTRACE_CONT, pid, NULL, NULL);
		}
		else
		{
			// printf("in_else line 202\n");
			// printf("rip: %lx \n", regs.rip);
			ptrace(PTRACE_CONT, pid, NULL, NULL);
		}
		wait(&wait_status);
	}
}

pid_t run_target(const char *program_name, char *const args[])
{
	pid_t pid = fork();
	if (pid > 0)
	{
		// printf("RUNNING program %s on new process %d\n", program_name, pid);
		return pid;
	}

	else if (pid == 0)
	{
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
		{
			perror("ptrace");
			return -1;
		}
		// printf("running program %s on new process %d\n", program_name, pid);
		execl(program_name, program_name, NULL);
		return 0;
	}
	else
	{
		perror("fork");
		// printf("pid < 0 line 237 \n");
		return -1;
	}
}

int main(int argc, char *const argv[])
{
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err > 0)
		// prf_printf("%s will be loaded to 0x%lx\n", argv[1], addr);
		(void)0;
	else if (err == -2)
		prf_printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		prf_printf("%s not found!\n", argv[1]);
	else if (err == -3)
		prf_printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		prf_printf("%s is a global symbol, but will come from a shared library with address %lx\n", argv[1], addr);

	pid_t pid = run_target(argv[2], argv);
	if (pid < 0)
	{
		printf("Error running target program\n");
		perror("fork");
		return -1;
	}
	if (pid > 0)
	{
		count_calls(addr, pid);
	}
	else
	{
		printf("Error running target program\n");
		perror("fork");
		return -1;
	}
}
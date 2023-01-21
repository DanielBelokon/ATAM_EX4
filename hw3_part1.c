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

		// find dynstr section
		Elf64_Shdr dynstr;
		for (int i = 0; i < ehdr.e_shnum; i++)
		{
			fseek(fptr, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
			fread(&shdr, sizeof(Elf64_Shdr), 1, fptr);

			if (strcmp(shstrtab_buf + shdr.sh_name, ".dynstr") == 0)
			{
				dynstr = shdr;
				break;
			}
		}

		char *dynstr_buf = malloc(dynstr.sh_size);
		fseek(fptr, dynstr.sh_offset, SEEK_SET);
		fread(dynstr_buf, dynstr.sh_size, 1, fptr);

		Elf64_Sym dynsym_buf[dynsym.sh_size / sizeof(Elf64_Sym)];
		fseek(fptr, dynsym.sh_offset, SEEK_SET);
		fread(dynsym_buf, dynsym.sh_size, 1, fptr);
		long dynsym_index = 0;
		for (dynsym_index = 0; dynsym_index < dynsym.sh_size / sizeof(Elf64_Sym); dynsym_index++)
		{
			// printf("dynsym name: %s\n", dynstr_buf + dynsym_buf[dynsym_index].st_name);
			if (strcmp(dynstr_buf + dynsym_buf[dynsym_index].st_name, symbol_name) == 0)
			{
				sym = dynsym_buf[dynsym_index];
				// printf("found in dynsym with index %ld", dynsym_index);
				break;
			}
		}

		// printf("dynsym size: %ld \n", dynsym.sh_size);
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

		// printf("rela.plt size: %ld \n", rela_plt.sh_size);

		Elf64_Rela rela_plt_buf[rela_plt.sh_size / sizeof(Elf64_Rela)];
		fseek(fptr, rela_plt.sh_offset, SEEK_SET);
		fread(rela_plt_buf, rela_plt.sh_size, 1, fptr);

		for (int i = 0; i < rela_plt.sh_size / sizeof(Elf64_Rela); i++)
		{
			// find the symbol in the rela.plt section
			// printf("%d at index %d, comparing to %ld\n", sym.st_name, dynsym_index, ELF64_R_SYM(rela_plt_buf[i].r_info));
			if (ELF64_R_SYM(rela_plt_buf[i].r_info) == dynsym_index) ///
			{
				// printf("found in rela.plt \n");
				sym.st_value = rela_plt_buf[i].r_offset;
				break;
			}
		}

		// printf("sym value: %ld \n", sym.st_value);

		// if not found
		if (sym.st_value == 0)
		{
			*error_val = -1;
			return 0;
		}

		// if found return address

		*error_val = 2; // success
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

Elf64_Shdr get_section_header(FILE *fptr, Elf64_Ehdr ehdr, char *section_name)
{
	Elf64_Shdr shdr;
	Elf64_Shdr shstrtab;
	// read the section header string table
	for (int i = 0; i < ehdr.e_shnum; i++)
	{
		fseek(fptr, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
		fread(&shdr, sizeof(Elf64_Shdr), 1, fptr);

		if (strcmp(section_name, ".shstrtab") == 0)
		{
			shstrtab = shdr;
			break;
		}
	}

	char *shstrtab_buf = malloc(shstrtab.sh_size);
	fseek(fptr, shstrtab.sh_offset, SEEK_SET);
	fread(shstrtab_buf, shstrtab.sh_size, 1, fptr);

	// read the section header
	for (int i = 0; i < ehdr.e_shnum; i++)
	{
		fseek(fptr, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
		fread(&shdr, sizeof(Elf64_Shdr), 1, fptr);

		if (strcmp(shstrtab_buf + shdr.sh_name, section_name) == 0)
		{
			return shdr;
		}
	}

	// if not found
	shdr.sh_name = 0;
	return shdr;
}

// Set breakpoint and return original data
unsigned long add_breakpoint(unsigned long addr, pid_t pid)
{
	unsigned long data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
	unsigned long break_data = (data & ~0xff) | 0xcc;
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)break_data);
	return data;
}

// Remove breakpoint and restore original data
void remove_breakpoint(unsigned long addr, unsigned long data, pid_t pid)
{
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data);
}

// continue after breakpoint and return it
void step_breakpoint(unsigned long addr, unsigned long data, pid_t pid)
{
	remove_breakpoint(addr, data, pid);
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	regs.rip -= 1;
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
	add_breakpoint(addr, pid);
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

void count_calls(unsigned long addr, pid_t pid, bool dynamic_addr)
{
	int wait_status;
	wait(&wait_status);
	if (dynamic_addr)
	{
		addr = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
	}

	// set breakpoint at addr
	unsigned long func_ep_data = add_breakpoint(addr, pid);
	struct user_regs_struct regs;
	// printf("addr: %lx", addr);

	unsigned long ret_addr = 0;
	unsigned long ret_addr_data = 0;

	long inner_calls = 0;
	bool in_func = false;
	int call_counter = 0;
	while (WIFSTOPPED(wait_status))
	{
		if (true)
		{
			printf("Looking for addrs: %lx, %lx \n", addr, ret_addr);
			// check if breakpoint is at addr
			ptrace(PTRACE_GETREGS, pid, NULL, &regs); // get the registers
			// printf("Current addrs: %lx, in function: %d\n", regs.rip - 1, in_func);
			if (regs.rip - 1 == addr)
			{
				// printf("in function\n");
				in_func = true;
				inner_calls++;
				// get return address from stack
				ret_addr = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.rsp), NULL);
				// set breakpoint at return address
				ret_addr_data = add_breakpoint(ret_addr, pid);
				// continue
				step_breakpoint(addr, func_ep_data, pid);
				// add_breakpoint(addr, pid);
				// remove_breakpoint(addr, func_ep_data, pid);
			}
			// if breakpoint is at return address
			else if (regs.rip - 1 == ret_addr)
			{
				// printf("return address: %lx \n", ret_addr);
				inner_calls--;
				in_func = false;
				if (inner_calls == 0)
				{
					// remove_breakpoint(ret_addr, ret_addr_data, pid);
					// regs.rip -= 1;
					// ptrace(PTRACE_SETREGS, pid, NULL, &regs);
					// add_breakpoint(addr, pid);
				}
				else
				{
				}
				// print return value
				call_counter++;
				int ret_val = regs.rax;
				prf_printf("run %ld returned with %d\n", call_counter, ret_val);
				step_breakpoint(ret_addr, ret_addr_data, pid);
				// remove_breakpoint(ret_addr, ret_addr_data, pid);
			}
		}
		else
		{
			// printf("in_else line 202\n");
			// printf("rip: %lx \n", regs.rip);
		}
		ptrace(PTRACE_CONT, pid, NULL, NULL);
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
		execl(program_name, program_name, args + 2, NULL);
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
	// printf("addr: %lx \n", addr);
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
		// printf("Error running target program\n");
		perror("fork");
		return -1;
	}
	if (pid > 0)
	{
		count_calls(addr, pid, err == 2);
	}
	else
	{
		// printf("Error running target program\n");
		perror("fork");
		return -1;
	}
}
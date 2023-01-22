/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 *
 * Enache Stefan
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "exec_parser.h"

int fd;
static so_exec_t *exec;
struct sigaction old_sa;
size_t pageSize;

int getPageSegment(uintptr_t address)
{
	for (int i = 0; i < exec->segments_no; i++)
	{
		so_seg_t *seg = &(exec->segments[i]);

		if (address >= seg->vaddr && address < seg->vaddr + seg->mem_size)
			return i;
	}

	return -1;
}

int getSizeInPages(size_t size)
{
	int pages = size / pageSize;
	/*Dimensiunea unui segment nu este aliniata la nivel de pagina
, daca dimensiunea segmentului nu este multiplu de dimensiunea paginii
  atunci se va aloca o pagina in plus*/
	if (size % pageSize != 0)
		pages++;

	return pages;
}
static void segv_handler(int signum, siginfo_t *info, void *context)
{
	/* TODO - actual loader implementation */
	if (signum != SIGSEGV)
		return;
	struct so_seg *seg = NULL;
	uintptr_t addr = (uintptr_t)info->si_addr;
	int pageNr = 0;
	void *ret;
	int segNr;
	/*Cerinta: identificam din ce segment se face accesul*/
	segNr = getPageSegment(addr);
	if (segNr == -1)
	{
		/*INVALID MEMORY ACCESS -- INVALID SEGMENT*/
		old_sa.sa_sigaction(signum, info, context);
		return;
	}
	else
	{

		seg = &(exec->segments[segNr]);
		pageNr = (addr - seg->vaddr) / pageSize;

		/*PAGINA ESTE DEJA MAPATA -> ACCES INVALID LA MEMORIE*/
		char *data = (char *)seg->data;
		if (data[pageNr] == 1)
			old_sa.sa_sigaction(signum, info, context);
		/*PAGINA NU ESTE MAPATA IN MEMORIE*/
		else if (data[pageNr] == 0)
		{

			int relative = pageNr * pageSize;

			/*Segmentul poate fi mai mare in memorie decat in fisier*/
			/*.bss nu contine date in fisierul obiect, se intializeaza la run-time*/
			if (seg->file_size < seg->mem_size)
			{
				int inMem_pages = getSizeInPages(seg->mem_size);
				int inFile_pages = getSizeInPages(seg->file_size);
				/*CAZ I: Dimensiunea este mai mare in memorie decat in fisier,
						 dar numarul de pagini alocate este identic (fragmentare interna mai mica in ultima pagina)*/
				if (inMem_pages == inFile_pages)
				{
					// verificam daca suntem in pagina respectiva

					ret = mmap((void *)seg->vaddr + relative, pageSize, seg->perm, MAP_FIXED, fd, seg->offset + relative);
					if (ret == MAP_FAILED)
						exit(-1);
					if ((pageNr + 1) * pageSize > seg->file_size) // pagNr from 0, suntem in ultima pagina
					{
						int internalDif = (pageNr + 1) * pageSize - seg->file_size;
						int internalOffset = pageSize - internalDif;
						uintptr_t pageStart = seg->vaddr + relative + internalOffset;
						memset((char *)pageStart, 0, internalDif);
					}
				}
				else
				{
					/* CAZ 2:Avem un numar mai mare de pagini alocate, paginile extre nu au fisier aferent, sunt
								initializate cu 0,trebuie sa le face mmap cu MAP_ANONYMOUS*/
					if (relative > seg->file_size) // pagina extra
					{
						ret = mmap((void *)seg->vaddr + relative, pageSize, seg->perm, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, fd, 0);
						if (ret == MAP_FAILED)
							exit(-1);
						data[pageNr] = 1;
						return;
					}
					ret = mmap((void *)seg->vaddr + relative, pageSize, seg->perm, MAP_PRIVATE | MAP_FIXED, fd, seg->offset + relative);
					if (ret == MAP_FAILED)
						exit(-1);
					if ((pageNr + 1) * pageSize > seg->file_size) // pagina comuna (fragmentare interna distincta)
					{
						int internalDif = (pageNr + 1) * pageSize - seg->file_size;
						int internalOffset = pageSize - internalDif;
						uintptr_t pageStart = seg->vaddr + relative + internalOffset;
						memset((char *)pageStart, 0, internalDif);
					}

					data[pageNr] = 1;
					return;
				}
			}
			else
			{
				ret = mmap((void *)seg->vaddr + relative, pageSize, seg->perm, MAP_PRIVATE | MAP_FIXED, fd, seg->offset + relative);
				if (ret == MAP_FAILED)
					exit(-1);
				data[pageNr] = 1;
			}
		}
	}
}

void memCleanup()
{
	for (int i = 0; i < exec->segments_no; i++)
	{
		int ret;
		int noPages;
		so_seg_t *seg = &(exec->segments[i]);
		noPages = getSizeInPages(seg->mem_size);
		char *data = seg->data;
		for (int j = 0; j < noPages; j++)
		{

			if (data[j] == 1)
			{
				ret = munmap((void *)seg->vaddr + j * pageSize, pageSize);
				if (ret == -1)
					exit(-1);
			}
		}
		free(exec->segments[i].data);
	}
	free(exec->segments);
	free(exec);
}
void dataInit()
{ /*Stocam in seg->data o evidenta a paginilor mapate in memorie*/
	int noPages;
	for (int i = 0; i < exec->segments_no; i++)
	{
		so_seg_t *seg = &(exec->segments[i]);
		noPages = getSizeInPages(seg->mem_size);

		seg->data = malloc(noPages);
		/*Pentru verificare vom indexa vectorul prin numarul de pagina
			data[pagina]=0 -> pagina nu a fost incarcata in memoria fizica
			data[pagina]=1 ->pagina a fost incarcata*/
		memset(seg->data, 0, noPages);
		if (seg->data == NULL)
			exit(-1);
	}
}
int so_init_loader(void)
{
	int rc;
	struct sigaction sa;
	pageSize = getpagesize();
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, &old_sa);
	if (rc < 0)
	{
		perror("sigaction");
		exit(-1);
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	/*Deschidem fisierul ELF pe care dorim sa il incarcam in memorie*/
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;

	/*Initializam structura care descrie fisierul*/
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	/*Initializam vectorul de gestiune al paginilor incarcate*/
	dataInit();

	so_start_exec(exec, argv);

	memCleanup();
	close(fd);
	return -1;
}

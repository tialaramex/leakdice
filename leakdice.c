/*  leakdice - Monte Carlo sampling of heap data

    Copyright (C) 2009 Nick Lamb
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* This is useful when for some reason a methodical approach to identifying memory leaks isn't available
 * e.g. because the process is already running and it's too late to instrument it
 * it's inspired in part by Raymond Chen's blog article "The poor man's way of identifying memory leaks" */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <sys/ptrace.h>

/* it's OK if the page size is actually larger than this */
#define ASSUME_PAGE_SIZE 4096

#if RAND_MAX < 10000000
#warning prefer a better random number generator
#endif

#define MAX_HEAP_COUNT 2000

static void dump_ascii(off_t offset, uint8_t *buffer, int count)
{
    int rows = (count + 15) / 16;
    int row, skip = 0;

    for (row = 0; row < rows; ++row) {
        int k, width = 16;
        if (row * 16 + width > count) width = count - (row * 16);

        if (row > 0) {
            for (k = 0 ; k < width; ++k) {
                if (buffer[row * 16 + k] != buffer[(row-1) * 16 + k]) break;
            }
            if (k == width) {
                if (skip == 0) printf(" ...\n");
                skip = 1;
                continue;
            } else {
                skip = 0;
            }
        }

        printf("%08lx ", offset + (row * 16));

        for (k = 0; k < width; ++k) {
            if (buffer[row * 16 + k] >= 0x20 && buffer[row * 16 + k] < 0x7f) {
                putchar(buffer[row * 16 + k]);
            } else {
                putchar('.');
            }
        }
        while (k < 17) {
            printf("  ");
            k++;
        }
        for (k = 0; k < width; ++k) {
            printf("%02x ", buffer[row * 16 + k]);
        }
        putchar('\n');
    }
}

static int read_page(int fd, off_t offset)
{
    uint8_t buffer[ASSUME_PAGE_SIZE];
    if (pread(fd, buffer, sizeof(buffer), offset) == -1) {
        return -1;
    }

    dump_ascii(offset, buffer, sizeof(buffer));
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2 || !strcmp(argv[1], "--help")) {
        fprintf(stderr, "%s <pid> [<address>]: dump some heap pages from a process to diagnose leaks\n", argv[0]);
        exit(1);
    }

    pid_t pid = atoi(argv[1]);

    char mem[] = "/proc/XXXXXXXXXX/mem";
    sprintf(mem, "/proc/%u/mem", pid);

    int fd = open(mem, O_RDONLY | O_NOATIME);
    if (fd == -1) {
        perror("leakdice: couldn't open /proc/$pid/mem file");
        exit(1);
    }

    /* we must ptrace(2) a process before reading memory,
       the purpose of this restriction is unclear */

    long trace = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (trace == -1) {
        perror("leakdice: ptrace failed");
        exit(1);
    }

    int status;
    pid_t result = waitpid(pid, &status, 0);
    if (result == -1) {
        perror("leakdice: waitpid failed");
        ptrace(PTRACE_DETACH, pid, NULL, SIGCONT);
        exit(1);
    } else if (!WIFSTOPPED(status)) {
        fprintf(stderr, "process signalled but not as intended?\n");
    }

    if (argc == 3) {
        unsigned long offset = strtoul(argv[2], NULL, 16);
        offset &= ~(ASSUME_PAGE_SIZE - 1);
        if (read_page(fd, offset) == -1) {
            perror("leakdice: fixed offset pread failed");
            ptrace(PTRACE_DETACH, pid, NULL, SIGCONT);
            exit(1);
        } else {
            exit(0);
        }
    }

    char maps[] = "/proc/XXXXXXXXXX/maps";
    sprintf(maps, "/proc/%u/maps", pid);
    FILE *file = fopen(maps, "r");
    if (!file) {
        perror("leakdice: couldn't open /proc/$pid/maps file");
        exit(1);
    }
    unsigned long offsets[MAX_HEAP_COUNT], sizes[MAX_HEAP_COUNT];
    unsigned long total = 0;
    int heaps = 0;

    while (!feof(file)) {
        unsigned long from, to, offset, inode;
        char perms[5];
        unsigned int devlo, devhi;
        char filename[512];

        int count = fscanf(file, "%lx-%lx %4s %lx %x:%x %lu%[^\n]\n", &from, &to, perms, &offset, &devhi, &devlo, &inode, filename);
        if (count == 8 && inode == 0 && (to - from > ASSUME_PAGE_SIZE) && !strcmp(perms, "rw-p")) {
            /* most likely this is heap data */
            offsets[heaps] = from;
            sizes[heaps] = (to - from) / ASSUME_PAGE_SIZE;
            total += sizes[heaps];
            heaps++;
        }
        if (heaps >= MAX_HEAP_COUNT) {
            break;
        }
    }

    fclose(file);

    if (total == 0) {
        fprintf(stderr, "This process appears to have no heap?\n");
        exit(0);
    }

    srand(getpid());
    unsigned long r = rand() % total;
    unsigned long pages = 0, offset = 0;
    int k;

    for (k = 0; k < heaps; ++k) {
        if (pages + sizes[k] > r) {
            offset = offsets[k] + ((r - pages) * ASSUME_PAGE_SIZE);
            break;
        } else {
            pages+= sizes[k];
        }
    }

    if (read_page(fd, offset) == -1) {
        perror("leakdice: pread failed");
        ptrace(PTRACE_DETACH, pid, NULL, SIGCONT);
        exit(1);
    }

    close(fd);
    ptrace(PTRACE_DETACH, pid, NULL, SIGCONT);
}

/* vi:set ts=8 sts=4 sw=4 et: */

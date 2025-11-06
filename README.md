# xv6 Demand Paging and Swapping
> xv6 is my literal actual opp

This repo implements demand paging, page replacement, and swapping for the xv6 operating system. Pages are allocated lazily on first access, evicted using FIFO when memory is full, and written to per-process swap files when dirty. A new `memstat()` system call exposes internal memory state for debugging and testing.

Key files:
- `vm.c` — virtual memory management, page fault handling, demand paging logic
- `proc.c` — process management, swap file creation/cleanup, per-process page tracking
- `trap.c` — page fault trap handler, calls demand paging routines
- `syscall.c` — system call dispatcher, includes `memstat()` implementation
- `memstat.h` — data structures for `memstat()` system call

What anol I've done
--------
- **Demand paging**: pages allocated only when accessed (text/data loaded from executable, heap/stack zero-filled)
- **FIFO page replacement**: oldest resident page evicted when `kalloc()` fails
- **Per-process swap files**: dirty pages written to `/pgswpXXXXX` (PID-based filename), max 1024 pages per process
- **Dirty tracking**: software-based dirty bit tracking, clean pages discarded without writing to swap
- **System state inspection**: `memstat()` system call reports page states (UNMAPPED, RESIDENT, SWAPPED), dirty bits, FIFO sequence numbers

Build
-----
```bash
cd xv6
make
```

Run / Usage
-----------
```bash
# Run xv6 in QEMU
make qemu
# or
make qemu-nox
```

Inside xv6:
```bash
# Test programs 
$ memtest
$ forktest
$ swaptest
$ usertests
```



Protocol and behavior summary
------------------------------
- **Page fault handling**: on page fault, kernel checks if address is valid (text/data/heap/stack). Valid pages are allocated or loaded; invalid accesses terminate the process.
- **FIFO replacement**: each resident page assigned a sequence number. When memory full, victim is the page with lowest sequence number in the faulting process's resident set.
- **Swap management**: swap file created on `exec()`, deleted on process exit. Dirty pages written to free swap slots; clean pages (with backing copy in executable) discarded. Max 1024 slots per process; if full and dirty eviction needed, process terminated.
- **Logging**: all operations logged to console with exact format (e.g., `[pid X] PAGEFAULT va=0xY access=read cause=heap`). See project spec for complete logging requirements.

Notes:
- Page size: 4096 bytes
- All addresses in logs are page-aligned, lowercase hex with `0x` prefix
- Stack pages allocated if fault address within one page below stack pointer
- Swap slots freed immediately when page reloaded from swap
- `memstat()` reports up to 128 pages; test cases do not exceed this limit

> obento

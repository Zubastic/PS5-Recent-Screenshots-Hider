/*
 * procio.h - cross-process memory IO for PS5 payloads.
 *
 * The Sony mdbg memop syscall (573) accepts READ memops under the
 * COREDUMP authid, but WRITE memops fail with EPERM on FW 11.20
 * (verified live: read self-test OK, write EPERM errno=1).
 *
 * Writes therefore go straight through the kernel direct map, the same
 * way as ps5-payload-sdk crt/kernel_procio.c does after its mdbg
 * attempt: walk the target's page tables (PML4 via vmspace->vm_pmap,
 * all reads with kernel_copyout), then kernel_copyin into
 * dmap_base + physical address.  kernel_copyin is the pipe/IPV6_PKTINFO
 * primitive and only needs kernel-space addresses, so user-space page
 * protections of the target do not matter.
 *
 * Requires the ps5 payload crt to have initialized
 * KERNEL_OFFSET_VMSPACE_VM_PMAP (done by __kernel_init).  The dmap base
 * is not taken from the crt (libkernel.a does not export
 * KERNEL_ADDRESS_DMAP_BASE) - proc_dmap_base() derives it at runtime
 * from our own pmap: pml4u - cr3.
 *
 * 2026-11-15 crash verdict (SceShellUI "proxied exception", Thread Pool
 * Worker): the kernel executes a foreign mdbg memop by borrowing a
 * thread of the TARGET process (restricted mode, syscall whitelist
 * 0x1B0/0x259/0x27A in amd64_syscall).  A fault inside the proxied op
 * is delivered to that innocent host thread as SIGSEGV - one stale
 * pointer that reaches a read memop kills the host.  Foreign READS are
 * therefore PTE-validated dmap walks ONLY (proc_read): a not-present
 * page fails the read (rc=-1) instead of the host.  mdbg stays for the
 * self-tests and for the explicit fault-in call sites that gate fn
 * first.  proc_getpaddr also rejects zombie/stale kernel pointers
 * (vmspace == 0 after the target died) before touching any table.
 *
 * (hardened 2026-11-18; this payload is dmap-only,
 * the unused wrappers keep their unused-attributes)
 */

#ifndef PROCIO_H
#define PROCIO_H

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

/* be gentle with the redirected pipe buffer */
#define PROC_CHUNK 0x1000UL

/*
 * The installed libkernel.a does not export KERNEL_ADDRESS_DMAP_BASE,
 * so compute it ourselves with the same trick the page-table walk uses:
 * for our own process, vmspace->vm_pmap holds the dmap alias of the user
 * PML4 (+0x20) and the physical cr3 (+0x28); pml4u - cr3 == dmap base
 * (mirrors crt/kernel_procio.c, which subtracts the raw cr3 as well).
 */
static uint64_t
proc_dmap_base(void) {
  static uint64_t base;
  uint64_t proc, vmspace, pml4u, cr3;

  if (base)
    return base;
  if ((proc = (uint64_t)kernel_get_proc(getpid())) == 0)
    return 0;
  if (kernel_copyout((intptr_t)(proc + KERNEL_OFFSET_PROC_P_VMSPACE),
                     &vmspace, sizeof(vmspace)) != 0)
    return 0;
  if (kernel_copyout((intptr_t)(vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP + 0x20),
                     &pml4u, sizeof(pml4u)) != 0)
    return 0;
  if (kernel_copyout((intptr_t)(vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP + 0x28),
                     &cr3, sizeof(cr3)) != 0)
    return 0;
  base = pml4u - cr3;
  return base;
}

#define PROC_PG_FRAME 0xffffffffff000ULL
#define PROC_PG_V     0x01
#define PROC_PG_PS    0x80

/* mirror of SDK kernel_is_heap_addr / jw_kptr_ok: rejects NULL,
 * misaligned and kernel .text/.rodata windows (hi16 0x0000/0xffff).
 * Guards every kernel pointer BEFORE it is dereferenced by a copyout -
 * a zombie proc has vmspace == 0 and a stale slot can hold anything. */
static int
proc_kptr_ok(uint64_t p) {
  unsigned int hi;
  if (!p || (p & 7))
    return 0;
  if ((p >> 48) != 0xffffull)
    return 0;
  hi = (unsigned int)((p >> 32) & 0xffffull);
  if (hi == 0 || hi == 0xffff)
    return 0;
  return 1;
}

/*
 * Walk the 4-level page tables of pid and return the physical address
 * backing vaddr plus the remaining length within that page/big page.
 */
static int
proc_getpaddr(pid_t pid, uintptr_t vaddr, uint64_t *paddr, uint64_t *plen) {
  uintptr_t proc = (uintptr_t)kernel_get_proc(pid);
  uint64_t vmspace = 0, pml4u = 0, cr3 = 0, pte = 0;

  if (!proc)
    return -1;
  if (kernel_copyout((intptr_t)(proc + KERNEL_OFFSET_PROC_P_VMSPACE),
                     &vmspace, sizeof(vmspace)) != 0)
    return -1;
  if (!proc_kptr_ok(vmspace))
    return -1; /* zombie/released vmspace (0) or a stale proc slot */
  if (kernel_copyout((intptr_t)(vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP + 0x20),
                     &pml4u, sizeof(pml4u)) != 0)
    return -1;
  if (kernel_copyout((intptr_t)(vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP + 0x28),
                     &cr3, sizeof(cr3)) != 0)
    return -1;
  if (!(pml4u & ~0xfffull) || (pml4u >> 48) != 0xffffull ||
      !(cr3 & ~0xfffull) || cr3 >= pml4u || cr3 >= 0x8000000000ull)
    return -1; /* pmap shape check: dmap alias above raw phys cr3 */

  /* pml4u - cr3 == dmap base: user-space alias minus physical address */
  pte = cr3;
  for (long bitpos = 39; bitpos >= 12; bitpos -= 9) {
    uint64_t table_offset = ((vaddr >> bitpos) & 0x1ffULL) * 8;
    pte &= PROC_PG_FRAME;
    if (kernel_copyout((intptr_t)(pml4u - cr3 + table_offset + pte),
                       &pte, sizeof(pte)) != 0)
      return -1;
    if (!(pte & PROC_PG_V))
      return -1;
    if (!(pte & PROC_PG_FRAME) ||
        (pte & PROC_PG_FRAME) >= 0x8000000000ull)
      return -1; /* garbage frame: never deref it as the next table */
    if ((pte & PROC_PG_PS) || bitpos == 12) {
      *paddr = (pte & ((1ULL << 52) - (1ULL << bitpos))) |
               (vaddr & ((1ULL << bitpos) - 1));
      *plen = ((*paddr | ((1ULL << bitpos) - 1)) + 1) - *paddr;
      return 0;
    }
  }
  return -1;
}

/*
 * KP guard (session verdict 2026-11-10): every dmap access must land
 * inside the kernel dmap window and far from the device/MMIO apertures
 * (DRAM on the PS5 sits below them; phys >= 0x400000000 is already
 * apertures).  A present user PTE maps RAM, but a wrong frame or an
 * overflowed dmap address would touch unmapped kernel space - and the
 * kernel memops do NOT handle faults (KP).  The JWFAST page-walk keeps
 * its own identical checks (jw_readphys), this one protects the generic
 * proc_read_dmap/proc_write_dmap paths.
 */
static int
proc_paddr_safe(uint64_t dmap, uint64_t paddr) {
  if (paddr == 0 || paddr >= 0x8000000000ull)
    return 0;
  if (((dmap + paddr) >> 48) != 0xffffull)
    return 0;
  return 1;
}

/* read through the dmap (fallback when the mdbg read memop fails) */
static int
proc_read_dmap(pid_t pid, uintptr_t addr, void *buf, size_t len) {
  uint8_t *dst = (uint8_t *)buf;
  uint64_t dmap = proc_dmap_base();
  size_t done = 0;

  if (dmap == 0)
    return -1;
  while (done < len) {
    uint64_t paddr, plen;
    size_t n = len - done;
    if (proc_getpaddr(pid, addr + done, &paddr, &plen) != 0)
      return -1;
    if ((uint64_t)n > plen)
      n = (size_t)plen;
    if (n > PROC_CHUNK)
      n = PROC_CHUNK;
    if (!proc_paddr_safe(dmap, paddr))
      return -1;
    if (kernel_copyout((intptr_t)(dmap + paddr),
                       dst + done, n) != 0)
      return -1;
    done += n;
  }
  return 0;
}

/* write into a foreign process through the dmap */
static int
proc_write_dmap(pid_t pid, uintptr_t addr, const void *buf, size_t len) {
  const uint8_t *src = (const uint8_t *)buf;
  uint64_t dmap = proc_dmap_base();
  size_t done = 0;

  if (dmap == 0)
    return -1;
  while (done < len) {
    uint64_t paddr, plen;
    size_t n = len - done;
    if (proc_getpaddr(pid, addr + done, &paddr, &plen) != 0)
      return -1;
    if ((uint64_t)n > plen)
      n = (size_t)plen;
    if (n > PROC_CHUNK)
      n = PROC_CHUNK;
    if (!proc_paddr_safe(dmap, paddr))
      return -1;
    if (kernel_copyin(src + done,
                      (intptr_t)(dmap + paddr), n) != 0)
      return -1;
    done += n;
  }
  return 0;
}

/* chunked read.  2026-11-15: NO mdbg on the foreign path anymore - the
 * kernel proxies foreign read memops into a thread of the target
 * process, and a stale pointer (GC moved the object, module unloaded,
 * zombie host) faults there and kills the innocent thread.  The
 * PTE-validated dmap walk fails cleanly (rc=-1) for the same cases.
 * mdbg remains for the self-tests (getpid) and the gated fault-in call
 * sites.  (unused in this dmap-only payload - attribute silences) */
__attribute__((unused)) static int
proc_read(pid_t pid, uintptr_t addr, void *buf, size_t len) {
  return proc_read_dmap(pid, addr, buf, len);
}

/* mdbg-only read.  NOTE: for a dead/reaped-between-checks proc the kernel
 * memop can return success WITHOUT copying anything, leaving the caller's
 * buffer untouched - never trust this path alone; pair it with the dmap
 * walk (host sanity check compares the two).
 * (unused in payloads without the sanity check - attribute silences) */
__attribute__((unused)) static int
proc_read_mdbg(pid_t pid, uintptr_t addr, void *buf, size_t len) {
  uint8_t *dst = (uint8_t *)buf;
  size_t done = 0;

  while (done < len) {
    size_t n = len - done;
    if (n > PROC_CHUNK)
      n = PROC_CHUNK;
    if (mdbg_copyout(pid, (intptr_t)(addr + done), dst + done, n) != 0)
      return -1;
    done += n;
  }
  return 0;
}

/* chunked write: dmap walk only (mdbg write is EPERM on FW 11.20)
 * (unused in this payload - attribute silences) */
__attribute__((unused)) static int
proc_write(pid_t pid, uintptr_t addr, const void *buf, size_t len) {
  return proc_write_dmap(pid, addr, buf, len);
}

#endif /* PROCIO_H */

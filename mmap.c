// Name- SHIVAM KUMAR                  ROLL NO. 170669

#include <mmap.h>
#include <types.h>

/**
 * Function will invoked whenever there is page fault. (Lazy allocation)
 *
 * For valid acess. Map the physical page
 * Return 1
 *
 * For invalid access,
 * Return -1.
 */
int vm_area_pagefault(struct exec_context* current, u64 addr, int error_code) {
        struct vm_area* head = current->vm_area;
        long base = (u64)osmap(current->pgd);
        while (head != NULL) {
                if (addr < head->vm_start) return -1;
                if (addr >= head->vm_start && addr < head->vm_end) break;
                head = head->vm_next;
        }
        if (!head) {
                return -1;
        }
        if ((error_code & 2) && (!(head->access_flags & PROT_WRITE))) return -1;
        if ((error_code & 0x1) != 0x1) {
                map_physical_page(base, addr, head->access_flags, 0);
                return 1;
        }
        return -1;
}

void update_access(struct exec_context* current, struct vm_area* vm) {
        int prot = vm->access_flags;
        unsigned long vaddr;
        for (vaddr = vm->vm_start; vaddr < vm->vm_end; vaddr += PAGE_SIZE) {
                u64* pte_entry = get_user_pte(current, vaddr, 0);
                if (((*pte_entry) & 0x1) && ((*pte_entry) & 0x4)) {
                        if (prot & PROT_WRITE)
                                *pte_entry = *pte_entry | PROT_WRITE;
                        else if ((*pte_entry) & PROT_WRITE)
                                *pte_entry = *pte_entry ^ PROT_WRITE;
                }
                asm volatile("invlpg (%0);" ::"r"(vaddr)
                             : "memory");  // Flush TLB
        }
}

/**
 * mprotect System call Implementation.
 */
int vm_area_mprotect(struct exec_context* current, u64 addr, int length,
                     int prot) {
        struct vm_area* head = current->vm_area;
        if (length % 4096 != 0) length = (length / 4096 + 1) * 4096;
        if (length == 0) return 0;
        while (head != NULL) {
                if (addr < head->vm_end) {
                        if (addr < head->vm_start) return -1;
                        struct vm_area* start = head;
                        int num_newvm = 1;
                        int num_oldvm = 1;
                        if (addr > start->vm_start &&
                            start->access_flags != prot)
                                num_newvm += 1;
                        while (head != NULL && addr + length > head->vm_end) {
                                if (head->vm_next == NULL ||
                                    head->vm_next->vm_start != head->vm_end)
                                        return -1;
                                head = head->vm_next;
                                num_oldvm += 1;
                        }

                        if (head == NULL) return -1;
                        if (addr + length < head->vm_end &&
                            head->access_flags != prot)
                                num_newvm += 1;
                        struct vm_area* cur = current->vm_area;
                        int total_vm = 0;
                        while (cur != NULL) {
                                total_vm++;
                                cur = cur->vm_next;
                        }
                        if (total_vm + num_newvm - num_oldvm > 128) return -1;

                        struct vm_area* last = head;
                        struct vm_area* newstart;
                        long start_accessflag = start->access_flags;
                        if (addr > start->vm_start &&
                            prot != start->access_flags) {
                                newstart = alloc_vm_area();
                                newstart->vm_start = addr;
                                newstart->access_flags = prot;
                                newstart->vm_next = start->vm_next;
                                newstart->vm_end = start->vm_end;
                                start->vm_next = newstart;
                                start->vm_end = addr;
                        } else {
                                newstart = start;
                                newstart->access_flags = prot;
                        }
                        head = newstart->vm_next;
                        if (start != last) {
                                head = newstart->vm_next;
                                while (head != last) {
                                        newstart->vm_next = head->vm_next;
                                        newstart->vm_end = head->vm_end;
                                        struct vm_area* temp = head->vm_next;
                                        dealloc_vm_area(head);
                                        head = temp;
                                }
                                if (addr + length < last->vm_end &&
                                    newstart->access_flags !=
                                        last->access_flags) {
                                        last->vm_start = addr + length;
                                        newstart->vm_end = addr + length;
                                } else {
                                        newstart->vm_end = last->vm_end;
                                        dealloc_vm_area(last);
                                }
                        } else {
                                if (addr + length < newstart->vm_end &&
                                    prot != start_accessflag) {
                                        last = alloc_vm_area();
                                        last->vm_end = newstart->vm_end;
                                        last->vm_start = addr + length;
                                        last->access_flags = start_accessflag;
                                        last->vm_next = newstart->vm_next;
                                        newstart->vm_end = addr + length;
                                        newstart->vm_next = last;
                                }
                        }
                        update_access(current, newstart);
                        return 0;
                }
                head = head->vm_next;
        }
        return -1;
}
/**
 * mmap system call implementation.
 */

u32 myinstall_ptable_multi(unsigned long pgd, unsigned long start, int count,
                           int write) {
        void* os_addr;
        u64 pfn, start_pfn, last_pfn;
        int ctr;
        unsigned long* ptep =
            (unsigned long*)pgd + ((start & PGD_MASK) >> PGD_SHIFT);
        if (!*ptep) {
                pfn = os_pfn_alloc(OS_PT_REG);
                *ptep = (pfn << PAGE_SHIFT) | 0x7;
                os_addr = osmap(pfn);
                bzero((char*)os_addr, PAGE_SIZE);
        } else {
                os_addr = (void*)((*ptep) & FLAG_MASK);
        }
        ptep = (unsigned long*)os_addr + ((start & PUD_MASK) >> PUD_SHIFT);
        if (!*ptep) {
                pfn = os_pfn_alloc(OS_PT_REG);
                *ptep = (pfn << PAGE_SHIFT) | 0x7;
                os_addr = osmap(pfn);
                bzero((char*)os_addr, PAGE_SIZE);
        } else {
                os_addr = (void*)((*ptep) & FLAG_MASK);
        }
        ptep = (unsigned long*)os_addr + ((start & PMD_MASK) >> PMD_SHIFT);
        if (!*ptep) {
                pfn = os_pfn_alloc(OS_PT_REG);
                *ptep = (pfn << PAGE_SHIFT) | 0x7;
                os_addr = osmap(pfn);
                bzero((char*)os_addr, PAGE_SIZE);
        } else {
                os_addr = (void*)((*ptep) & FLAG_MASK);
        }
        ptep = (unsigned long*)os_addr + ((start & PTE_MASK) >> PTE_SHIFT);

        start_pfn = os_pfn_alloc(USER_REG);
        for (ctr = 0; ctr < count; ++ctr) {
                if (!ctr) {
                        pfn = start_pfn;
                } else {
                        pfn = os_pfn_alloc(USER_REG);
                        if (last_pfn != pfn - 1)
                                printk("BUG! PFN not in sequence\n");
                }
                *ptep = (pfn << PAGE_SHIFT) | 0x5;
                if (write) *ptep |= 0x2;
                ptep++;
                last_pfn = pfn;
        }
        return start_pfn;
}
void allocate_mypfn(struct exec_context* current, u64 start, int length,
                    int prot) {
        int npages = length / 4096;
        int i = 0;
        long base = (u64)osmap(current->pgd);
        while (npages > 0) {
                int nleft = ((u64)1 << 9) - ((start & PTE_MASK) >> PTE_SHIFT);
                if (nleft >= npages) {
                        myinstall_ptable_multi(base, start, npages,
                                               (prot & PROT_WRITE));
                        return;
                } else {
                        myinstall_ptable_multi(base, start, nleft,
                                               (prot & PROT_WRITE));
                        start = (start & 0xffffffe00000UL) + (0x200000);
                        npages = npages - nleft;
                }
        }
}
long vm_area_map(struct exec_context* current, u64 addr, int length, int prot,
                 int flags) {
        long ret_addr = -1;
        long start, end;
        if (!addr && (addr % 4096 != 0)) return -1;
        if (length % 4096 != 0) length = (length / 4096 + 1) * 4096;

        struct vm_area* head = current->vm_area;
        int total_vm = 0;
        while (head) {
                total_vm++;
                head = head->vm_next;
        }
        head = current->vm_area;
        if (head != NULL) {
                if (addr) {
                        if ((addr < MMAP_AREA_START ||
                             addr + length > MMAP_AREA_END) &&
                            (flags & MAP_FIXED))
                                return -1;
                        if (addr >= MMAP_AREA_START && addr < head->vm_start) {
                                if (addr + length - 1 < head->vm_start) {
                                        if (addr + length == head->vm_start &&
                                            prot == (head->access_flags))
                                                head->vm_start = addr;
                                        else {
                                                if (total_vm >= 128) return -1;
                                                struct vm_area* vm =
                                                    alloc_vm_area();
                                                vm->vm_start = addr;
                                                vm->vm_end = addr + length;
                                                vm->access_flags = prot;
                                                current->vm_area = vm;
                                                vm->vm_next = head;
                                        }

                                        if (flags & MAP_POPULATE)
                                                allocate_mypfn(current, addr,
                                                               length, prot);
                                        return addr;
                                } else if (flags & MAP_FIXED)
                                        return -1;

                        } else {
                                while (head != NULL) {
                                        if (addr >= head->vm_start &&
                                            addr < head->vm_end &&
                                            (flags & MAP_FIXED))
                                                return -1;
                                        start = head->vm_end;
                                        end = (head->vm_next)
                                                  ? head->vm_next->vm_start
                                                  : MMAP_AREA_END;
                                        if (addr >= start && addr < end) {
                                                if (addr + length <= end) {
                                                        if (addr == start &&
                                                            (prot ==
                                                             head->access_flags)) {
                                                                head->vm_end =
                                                                    addr +
                                                                    length;
                                                                if (head->vm_next &&
                                                                    addr + length ==
                                                                        end &&
                                                                    (prot ==
                                                                     head->vm_next
                                                                         ->access_flags)) {
                                                                        head->vm_end =
                                                                            head->vm_next
                                                                                ->vm_end;
                                                                        head->vm_next =
                                                                            head->vm_next
                                                                                ->vm_next;
                                                                        dealloc_vm_area(
                                                                            head->vm_next);
                                                                }

                                                        } else if (
                                                            head->vm_next &&
                                                            addr + length ==
                                                                end &&
                                                            (prot ==
                                                             head->vm_next
                                                                 ->access_flags)) {
                                                                head->vm_next
                                                                    ->vm_start =
                                                                    addr;
                                                        } else {
                                                                if (total_vm >=
                                                                    128)
                                                                        return -1;
                                                                struct vm_area* vm =
                                                                    alloc_vm_area();
                                                                vm->vm_start =
                                                                    addr;
                                                                vm->vm_end =
                                                                    addr +
                                                                    length;
                                                                vm->access_flags =
                                                                    prot;
                                                                vm->vm_next =
                                                                    head->vm_next;
                                                                head->vm_next =
                                                                    vm;
                                                        }

                                                        if (flags &
                                                            MAP_POPULATE)
                                                                allocate_mypfn(
                                                                    current,
                                                                    addr,
                                                                    length,
                                                                    prot);
                                                        return addr;
                                                } else if (flags & MAP_FIXED)
                                                        return -1;
                                                else
                                                        break;
                                        }
                                        head = head->vm_next;
                                }
                        }
                }
                head = current->vm_area;
                start = MMAP_AREA_START;
                end = head->vm_start;
                if (start + length <= end) {
                        if (start + length == end &&
                            (prot == head->access_flags))
                                head->vm_start = start;
                        else {
                                if (total_vm >= 128) return -1;
                                struct vm_area* vm = alloc_vm_area();
                                vm->vm_start = start;
                                vm->vm_end = start + length;
                                vm->access_flags = prot;
                                current->vm_area = vm;
                                vm->vm_next = head;
                        }
                        if (flags & MAP_POPULATE)
                                allocate_mypfn(current, start, length, prot);
                        return start;
                }
                while (head != NULL) {
                        start = head->vm_end;
                        end = (head->vm_next) ? head->vm_next->vm_start
                                              : MMAP_AREA_END;
                        if (start + length <= end) {
                                if (prot == head->access_flags) {
                                        if ((head->vm_next) &&
                                            (start + length == end) &&
                                            (prot ==
                                             head->vm_next->access_flags)) {
                                                head->vm_end =
                                                    head->vm_next->vm_end;
                                                head->vm_next =
                                                    head->vm_next->vm_next;
                                                dealloc_vm_area(head->vm_next);
                                        } else
                                                head->vm_end = start + length;
                                } else if (head->vm_next &&
                                           start + length == end &&
                                           (prot ==
                                            head->vm_next->access_flags)) {
                                        head->vm_next->vm_start = start;
                                } else {
                                        if (total_vm >= 128) return -1;
                                        struct vm_area* vm = alloc_vm_area();
                                        vm->vm_start = start;
                                        vm->vm_end = start + length;
                                        vm->access_flags = prot;
                                        vm->vm_next = head->vm_next;
                                        head->vm_next = vm;
                                }
                                if (flags & MAP_POPULATE)
                                        allocate_mypfn(current, start, length,
                                                       prot);
                                return start;
                        }
                        head = head->vm_next;
                }
        } else {
                if (MMAP_AREA_START + length <= MMAP_AREA_END) {
                        if (total_vm >= 128) return -1;
                        struct vm_area* vm = alloc_vm_area();
                        vm->vm_start = MMAP_AREA_START;
                        vm->vm_end = MMAP_AREA_START + length;
                        vm->access_flags = prot;
                        vm->vm_next = NULL;
                        current->vm_area = vm;
                        if (flags & MAP_POPULATE)
                                allocate_mypfn(current, MMAP_AREA_START, length,
                                               prot);
                        return MMAP_AREA_START;
                } else
                        return -1;
        }
        return -1;
}
/**
 * munmap system call implemenations
 */
void do_myunmap_user(struct exec_context* current, u64 addr, int length) {
        int length_unmapped = 0;
        for (int length_unmapped = 0; length_unmapped < length;
             length_unmapped += PAGE_SIZE) {
                do_unmap_user(current, addr + length_unmapped);
        }
}
int vm_area_unmap(struct exec_context* current, u64 addr, int length) {
        // printk("in vm_area_unmap\n");
        struct vm_area* head = current->vm_area;
        int total_vm = 0;
        while (head) {
                total_vm++;
                head = head->vm_next;
        }
        if (total_vm > 128) return -1;
        head = current->vm_area;
        while (head) {
                if (addr < head->vm_end) {
                        if (addr > head->vm_start &&
                            addr + length < head->vm_end && total_vm >= 128)
                                return -1;
                        else
                                break;
                }
                head = head->vm_next;
        }
        head = current->vm_area;
        if (length % 4096 != 0) length = (length / 4096 + 1) * 4096;
        struct vm_area* prev = NULL;
        while (head != NULL) {
                if (addr < head->vm_end) {
                        if (addr + length - 1 < head->vm_start) return 0;
                        if (addr > head->vm_start) {
                                if (total_vm >= 128) {
                                        head->vm_end = addr;
                                        prev = head;
                                        head = head->vm_next;
                                } else {
                                        struct vm_area* next = alloc_vm_area();
                                        next->vm_start = addr;
                                        next->vm_end = head->vm_end;
                                        next->access_flags = head->access_flags;
                                        next->vm_next = head->vm_next;
                                        head->vm_next = next;
                                        head->vm_end = addr;
                                        prev = head;
                                        head = next;
                                }
                        }
                        while (head != NULL && head->vm_end <= addr + length) {
                                struct vm_area* temp = head->vm_next;
                                dealloc_vm_area(head);
                                head = temp;
                        }
                        if (head != NULL) {
                                if (addr + length - 1 >= head->vm_start)
                                        head->vm_start = addr + length;
                        }
                        if (prev)
                                prev->vm_next = head;
                        else
                                current->vm_area = head;
                        do_myunmap_user(current, addr, length);
                        return 0;
                }
                prev = head;
                head = head->vm_next;
        }
        return 0;
}

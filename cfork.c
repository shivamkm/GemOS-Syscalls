// Name- SHIVAM KUMAR                  ROLL NO. 170669

#include <cfork.h>
#include <mmap.h>
#include <page.h>

void vfork_copy_mm(struct exec_context *child, struct exec_context *parent) {
        void *os_addr;
        u64 vaddr;
        struct mm_segment *seg;
        os_addr = osmap(child->pgd);
        seg = &parent->mms[MM_SEG_STACK];
        u64 new_stack_length = (seg->end - parent->regs.rbp + 1) * 2;
        u64 old_stack_length = seg->end - seg->next_free;
        u64 offset = seg->end - parent->regs.rbp;
        while (new_stack_length > old_stack_length) {
                u64 pfn = map_physical_page(
                    (u64)os_addr, seg->next_free - PAGE_SIZE, MM_WR, 0);
                seg->next_free = seg->next_free - PAGE_SIZE;
                old_stack_length += PAGE_SIZE;
        }
        for (vaddr = seg->end - 0x8; vaddr >= parent->regs.rbp; vaddr -= 0x8) {
                u64 *parent_pte = get_user_pte(parent, vaddr, 0);
                if (parent_pte) {
                        u64 pfn = install_ptable((u64)(parent->pgd), seg,
                                                 vaddr - offset,
                                                 0);  // Returns the blank page
                        pfn = (u64)osmap(pfn);
                        memcpy((char *)(vaddr - offset), (char *)(vaddr), 0x8);
                        asm volatile("invlpg (%0);" ::"r"(vaddr) : "memory");

                        asm volatile("invlpg (%0);" ::"r"(vaddr - offset)
                                     : "memory");
                }
        }
        u64 entry_rsp = (parent->regs).entry_rsp;
        u64 oldbp;
        u64 new_sp = entry_rsp - offset;
        vaddr = new_sp;
        while (vaddr < entry_rsp) {
                memcpy(((char *)&oldbp), (char *)(vaddr), 8);
                oldbp = oldbp - offset;
                memcpy((char *)(vaddr), ((char *)&oldbp), 8);
                vaddr = oldbp;
        }
        (child->regs).entry_rsp = new_sp;
        (child->regs).rbp = (parent->regs).rbp - offset;
        parent->state = WAITING;
        child->state = READY;
        child->mms[MM_SEG_STACK] = parent->mms[MM_SEG_STACK];
        return;
}

void vfork_exit_handle(struct exec_context *ctx) {
        struct exec_context *parent_ctx = get_ctx_by_pid(ctx->ppid);
        if (!parent_ctx || parent_ctx->state != WAITING) return;

        struct mm_segment *seg = &parent_ctx->mms[MM_SEG_STACK];
        for (int i = 0; i < MAX_MM_SEGS - 1; i++) {
                parent_ctx->mms[i] = ctx->mms[i];
        }
        parent_ctx->vm_area = ctx->vm_area;
        parent_ctx->state = READY;
        u64 num_original_pages = (seg->end - parent_ctx->regs.rbp) / PAGE_SIZE;
        if ((seg->end - parent_ctx->regs.rbp) % (PAGE_SIZE) > 0)
                num_original_pages++;

        u64 num_child_pages = (seg->end - seg->next_free) / PAGE_SIZE;
        u64 num_created_pages = num_child_pages - num_original_pages;

        for (int i = 0; i < num_created_pages; i++) {
                do_unmap_user(ctx, seg->next_free);
                seg->next_free += PAGE_SIZE;
        }
        return;
}

void cfork_copy_mm(struct exec_context *child, struct exec_context *parent) {
        void *os_addr;
        u64 vaddr;
        struct mm_segment *seg;

        child->pgd = os_pfn_alloc(OS_PT_REG);

        os_addr = osmap(child->pgd);
        bzero((char *)os_addr, PAGE_SIZE);

        // CODE segment
        seg = &parent->mms[MM_SEG_CODE];
        for (vaddr = seg->start; vaddr < seg->next_free; vaddr += PAGE_SIZE) {
                u64 *parent_pte = get_user_pte(parent, vaddr, 0);
                if (parent_pte) {
                        u64 pfn = install_ptable(
                            (u64)os_addr, seg, vaddr,
                            (*parent_pte & FLAG_MASK) >> PAGE_SHIFT);
                        struct pfn_info *info = get_pfn_info(pfn);
                        increment_pfn_info_refcount(info);
                }
        }
        // RODATA segment

        seg = &parent->mms[MM_SEG_RODATA];
        for (vaddr = seg->start; vaddr < seg->next_free; vaddr += PAGE_SIZE) {
                u64 *parent_pte = get_user_pte(parent, vaddr, 0);
                if (parent_pte) {
                        u64 pfn = install_ptable(
                            (u64)os_addr, seg, vaddr,
                            (*parent_pte & FLAG_MASK) >> PAGE_SHIFT);
                        struct pfn_info *info = get_pfn_info(pfn);
                        increment_pfn_info_refcount(info);
                }
        }

        // DATA segment
        seg = &parent->mms[MM_SEG_DATA];
        for (vaddr = seg->start; vaddr < seg->next_free; vaddr += PAGE_SIZE) {
                u64 *parent_pte = get_user_pte(parent, vaddr, 0);
                if (parent_pte) {
                        *parent_pte =
                            (((*parent_pte) >> PAGE_SHIFT) << PAGE_SHIFT) | 0x5;
                        u64 pfn = map_physical_page(
                            (u64)os_addr, vaddr, PROT_READ,
                            (*parent_pte & FLAG_MASK) >> PAGE_SHIFT);
                        asm volatile("invlpg (%0);" ::"r"(vaddr)
                                     : "memory");  // Flush TLB
                        struct pfn_info *info = get_pfn_info(pfn);
                        increment_pfn_info_refcount(info);
                }
        }

        // STACK segment
        seg = &parent->mms[MM_SEG_STACK];
        for (vaddr = seg->end - PAGE_SIZE; vaddr >= seg->next_free;
             vaddr -= PAGE_SIZE) {
                u64 *parent_pte = get_user_pte(parent, vaddr, 0);

                if (parent_pte) {
                        u64 pfn = install_ptable((u64)os_addr, seg, vaddr,
                                                 0);  // Returns the blank page
                        pfn = (u64)osmap(pfn);
                        memcpy((char *)pfn, (char *)(*parent_pte & FLAG_MASK),
                               PAGE_SIZE);
                }
        }

        copy_os_pts(parent->pgd, child->pgd);
        struct vm_area *phead = parent->vm_area;
        struct vm_area *chead = NULL;
        struct vm_area *cur, *prev = NULL;
        while (phead) {
                cur = alloc_vm_area();
                cur->vm_start = phead->vm_start;
                cur->vm_end = phead->vm_end;
                cur->access_flags = phead->access_flags;
                cur->vm_next = NULL;
                if (prev)
                        prev->vm_next = cur;
                else
                        chead = cur;
                phead = phead->vm_next;
                prev = cur;
                for (vaddr = cur->vm_start; vaddr < cur->vm_end;
                     vaddr += PAGE_SIZE) {
                        u64 *parent_pte = get_user_pte(parent, vaddr, 0);
                        if (parent_pte) {
                                *parent_pte = (((*parent_pte) >> PAGE_SHIFT)
                                               << PAGE_SHIFT) |
                                              0x5;
                                u64 pfn = map_physical_page(
                                    (u64)os_addr, vaddr, PROT_READ,
                                    (*parent_pte & FLAG_MASK) >> PAGE_SHIFT);
                                asm volatile("invlpg (%0);" ::"r"(vaddr)
                                             : "memory");  // Flush TLB
                                struct pfn_info *info = get_pfn_info(pfn);
                                increment_pfn_info_refcount(info);
                        }
                }
        }
        child->vm_area = chead;
        return;
}

int handle_cow_fault(struct exec_context *current, u64 cr2) {
        u64 *pte = get_user_pte(current, cr2, 0);
        if (!pte) return -1;
        void *os_addr = osmap(current->pgd);
        if ((cr2 >= (current->mms)[MM_SEG_DATA].start) &&
            (cr2 <= (current->mms)[MM_SEG_DATA].end)) {
                if (cr2 < (current->mms)[MM_SEG_DATA].next_free) {
                        if (((current->mms[MM_SEG_DATA]).access_flags &
                             MM_WR) &&
                            (!(*pte & MM_WR))) {
                                u64 upfn = ((*pte) >> PAGE_SHIFT);
                                struct pfn_info *info = get_pfn_info(upfn);
                                if (get_pfn_info_refcount(info) > 1) {
                                        upfn = map_physical_page(
                                            (u64)os_addr, cr2,
                                            current->mms[MM_SEG_DATA]
                                                .access_flags,
                                            0);
                                        upfn = (u64)osmap(upfn);
                                        memcpy((char *)upfn,
                                               (char *)(*pte & FLAG_MASK),
                                               PAGE_SIZE);
                                        decrement_pfn_info_refcount(info);
                                }
                                *pte = (*pte) | MM_WR;
                                asm volatile("invlpg (%0);" ::"r"(cr2)
                                             : "memory");  // Flush TLB
                                asm volatile("invlpg (%0);" ::"r"(*pte)
                                             : "memory");
                                return 1;
                        }
                        return -1;
                }
                return -1;
        }
        if (cr2 >= MMAP_AREA_START && cr2 < MMAP_AREA_END) {
                struct vm_area *head = current->vm_area;
                long base = (u64)osmap(current->pgd);
                while (head != NULL) {
                        if (cr2 < head->vm_start) return -1;
                        if (cr2 >= head->vm_start && cr2 < head->vm_end) break;
                        head = head->vm_next;
                }
                if (!head) return -1;
                if (!(head->access_flags & PROT_WRITE)) return -1;
                if (!((*pte) & MM_WR)) {
                        u64 upfn = ((*pte) >> PAGE_SHIFT);
                        struct pfn_info *info = get_pfn_info(upfn);
                        if (get_pfn_info_refcount(info) > 1) {
                                upfn = map_physical_page((u64)os_addr, cr2,
                                                         head->access_flags, 0);
                                upfn = (u64)osmap(upfn);
                                memcpy((char *)upfn, (char *)(*pte & FLAG_MASK),
                                       PAGE_SIZE);
                                decrement_pfn_info_refcount(info);
                        }
                        *pte = (*pte) | MM_WR;
                        asm volatile("invlpg (%0);" ::"r"(cr2)
                                     : "memory");  // Flush TLB
                        return 1;
                }
                return -1;
        }
        return -1;
}

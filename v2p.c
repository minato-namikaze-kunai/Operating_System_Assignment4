#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>
#include <apic.h>
#include <entry.h>
#include <idt.h>
#include <kbd.h>
#include <memory.h>
#include <schedule.h>
#include <context.h>
#include <file.h>
#include <fs.h>
#include <init.h>
#include <lib.h>
#include <pipe.h>
#include <serial.h>

/*
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables
 * */

// defining macrons for future use
#define PGD_SHIFT 0x27
#define PUD_SHIFT 0x1E
#define PMD_SHIFT 0x15
#define PTE_SHIFT 0xC
#define ADDR_SHIFT 0xC
// As given in thee PS, that max number of vma should be 128
#define MAX_VMA_COUNT 128

// This pfn from the address
// Is used in many places, so made a macron
#define PFN_FROM_ENTRY(entry) (((entry) & ~0xFFFUL) >> ADDR_SHIFT)

// we reload CR3 to wipe the TLB clean,
void flush_tlbs(void)
{
    u64 cr3_value;
    asm volatile(
        "mov %%cr3, %0" // Move the value from CR3 into the variable
        : "=r"(cr3_value));

    asm volatile(
        "mov %0, %%rax\n\t" // Move the CR3 value into RAX
        "mov %%rax, %%cr3"  // Move the content of RAX into CR3
        :
        : "r"(cr3_value)
        : "eax");
}

// cleasrs out the 4kb page size by setting all the bits in it to 0
// we use it when we allocated a new page
static void page_clear(u64 *page_va)
{
    if (page_va == NULL)
    {
        return;
    }

    int end = PAGE_SIZE / sizeof(u64);
    for (int i = 0; i < end; i++)
    {
        page_va[i] = 0;
    }
}

// this will allocates or make new vm area
static struct vm_area *allocate_vm_area()
{
    struct vm_area *new_vma = (struct vm_area *)os_alloc(sizeof(struct vm_area));

    if (new_vma)
    {
        new_vma->vm_start = 0;
        new_vma->vm_end = 0;
        new_vma->access_flags = 0;
        new_vma->vm_next = NULL;
        stats->num_vm_area++;
    }
    return new_vma;
}

// This function will free and delete the vm area
static void free_vm_area(struct vm_area *vma)
{

    if (vma)
    {
        stats->num_vm_area--;
        os_free(vma, sizeof(struct vm_area));
    }
}

// THis checks whether ranges s1,e1 and s2,e2 overlap or not
static int ranges_overlap(u64 s1, u64 e1, u64 s2, u64 e2)
{

    if (s1 >= e1 || s2 >= e2)
    {
        return 0;
    }

    return (s1 < e2) && (s2 < e1);
}

/**
 * mprotect System call Implementation.
 */

// This is used for mprotect and unmap functions/
// This will take the virtual address and return thr pte address
u64 *pte_address(struct exec_context *current, u64 page_vaddr)
{
    u64 *pte_addr = NULL;
    u64 *pgd_va = (u64 *)osmap(current->pgd);
    u64 *pud_va = NULL;
    u64 *pmd_va = NULL;
    u64 *pte_table_va = NULL;
    u64 entry_value;
    u64 table_pfn;

    // 0x1 used to check whether the present bit is set or not
    // if present bit 1 is 0, then it means there page entry is not present, so return NULL
    // We can see in this function that when ever present bit is 0, we are retuning NULL

    u32 pgd_index = (page_vaddr >> PGD_SHIFT) & 0x1FF;
    entry_value = *(pgd_va + pgd_index);
    if (!(entry_value & 0x1))
    {
        return NULL;
    }
    table_pfn = PFN_FROM_ENTRY(entry_value);
    pud_va = (u64 *)osmap(table_pfn);

    u32 pud_index = (page_vaddr >> PUD_SHIFT) & 0x1FF;
    entry_value = *(pud_va + pud_index);
    if (!(entry_value & 0x1))
    {
        return NULL;
    }
    table_pfn = PFN_FROM_ENTRY(entry_value);
    pmd_va = (u64 *)osmap(table_pfn);

    u32 pmd_index = (page_vaddr >> PMD_SHIFT) & 0x1FF;
    entry_value = *(pmd_va + pmd_index);
    if (!(entry_value & 0x1))
    {
        return NULL;
    }
    table_pfn = PFN_FROM_ENTRY(entry_value);
    pte_table_va = (u64 *)osmap(table_pfn);

    u32 pte_index = (page_vaddr >> PTE_SHIFT) & 0x1FF;
    pte_addr = pte_table_va + pte_index;

    return pte_addr;
}

long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    // if prot is not read or write we return false
    if (!(prot == PROT_READ || prot == (PROT_READ | PROT_WRITE)))
    {
        return -1;
    }

    // address is not page alined
    if (addr % PAGE_SIZE != 0)
    {
        return -1;
    }

    u64 start_add = addr;
    u64 end_add = addr + length;
    if (end_add > MMAP_AREA_END)
    {
        end_add = MMAP_AREA_END;
    }

    if (end_add % PAGE_SIZE != 0)
    {
        end_add = ((end_add + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    }

    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;

    while (curr != NULL)
    {
        struct vm_area *next = curr->vm_next;
        // checking which vma lines in the prot change range
        // if (curr->vm_start < end_add && curr->vm_end > start_add)
        if (ranges_overlap(curr->vm_start, curr->vm_end, start_add, end_add))
        {
            // if this curr is in the prot change, we need to change it is access_flags to prot
            // Finding the range in the vma where we need to change access_flags
            u64 new_start = start_add;
            if (curr->vm_start > start_add)
            {
                new_start = curr->vm_start;
            }
            u64 new_end = end_add;
            if (curr->vm_end < end_add)
            {
                new_end = curr->vm_end;
            }

            if (new_start >= new_end)
            {

                prev = curr;
                curr = next;
                continue;
            }

            if (curr->access_flags == prot)
            {
                prev = curr;
            }
            else
            {

                for (u64 page_vaddr = new_start; page_vaddr < new_end; page_vaddr += PAGE_SIZE)
                {
                    // using pte_address to get pte
                    // then using pte to find physical address
                    u64 *pte_addr = (u64 *)pte_address(current, page_vaddr);
                    u64 entry_value = *pte_addr;
                    if (pte_addr == NULL)
                    {
                        continue;
                    }

                    if ((entry_value & 0x1))
                    {
                        // storing the physical page number  and  flags present: 0x1, user: 0x10
                        u64 pfn_part = entry_value & (~0xFFFUL);
                        u64 flags = entry_value & ((0x1) | (0x10));

                        // if prot has write permssion, then we add write condition tot he flags
                        if (prot & PROT_WRITE)
                        {
                            flags |= 0x8;
                        }

                        *pte_addr = pfn_part | flags;
                        flush_tlbs();
                    }
                }

                // spliting the curr vma
                // tail_vma indicates lower part of curr vma
                struct vm_area *tail_vma = NULL;

                if (curr->vm_end > new_end)
                {
                    tail_vma = allocate_vm_area();
                    if (!tail_vma)
                    {
                        return -1;
                    }

                    tail_vma->vm_start = new_end;
                    tail_vma->vm_end = curr->vm_end;
                    tail_vma->access_flags = curr->access_flags;
                    tail_vma->vm_next = next;
                }

                // in this case 1 vma becomes 3 vma
                // middle vma indicate the middle part that form from splitting in curr vma
                if (curr->vm_start < new_start)
                {

                    curr->vm_end = new_start;

                    struct vm_area *middle_vma = allocate_vm_area();
                    if (!middle_vma)
                    {
                        if (tail_vma)
                        {
                            free_vm_area(tail_vma);
                        }
                        return -1;
                    }

                    middle_vma->vm_start = new_start;
                    middle_vma->vm_end = new_end;
                    middle_vma->access_flags = prot;

                    curr->vm_next = middle_vma;
                    middle_vma->vm_next = next;
                    if (tail_vma)
                    {
                        middle_vma->vm_next = tail_vma;
                    }

                    prev = middle_vma;
                    if (tail_vma)
                    {
                        prev = tail_vma;
                    }
                }
                else
                {
                    curr->vm_start = new_start;
                    curr->vm_end = new_end;
                    curr->access_flags = prot;

                    curr->vm_next = next;
                    if (tail_vma)
                    {
                        curr->vm_next = tail_vma;
                    }

                    prev = curr;
                    if (tail_vma)
                    {
                        prev = tail_vma;
                    }
                }
            }
        }
        else
        {
            prev = curr;
        }

        curr = next;
    }

    // merging vma if they have same access_flags
    prev = current->vm_area;
    curr = prev->vm_next;
    while (curr != NULL && curr->vm_next != NULL)
    {
        struct vm_area *next_vma = curr->vm_next;

        if (curr->vm_end == next_vma->vm_start && curr->access_flags == next_vma->access_flags)
        {

            curr->vm_end = next_vma->vm_end;
            curr->vm_next = next_vma->vm_next;
            free_vm_area(next_vma);
        }
        else
        {

            curr = curr->vm_next;
        }
    }
    return 0;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{

    if (!current->vm_area)
    {
        struct vm_area *dummy = allocate_vm_area();
        if (!dummy)
        {
            return -1;
        }
        dummy->vm_start = MMAP_AREA_START;
        dummy->vm_end = MMAP_AREA_START + PAGE_SIZE;
        dummy->access_flags = 0;
        dummy->vm_next = NULL;
        current->vm_area = dummy;
    }

    if (!(prot == PROT_READ || prot == (PROT_READ | PROT_WRITE)))
    {
        return -1;
    }

    if (flags != 0 && flags != MAP_FIXED)
    {
        return -1;
    }

    if (flags == MAP_FIXED && addr == 0)
    {
        return -1;
    }

    if (addr != 0 && (addr % PAGE_SIZE != 0))
    {
        return -1;
    }

    // addr should be in between MMAP_START and MMAP_END
    if (flags == MAP_FIXED && (addr < MMAP_AREA_START || addr >= MMAP_AREA_END))
    {
        return -1;
    }

    u64 map_length = (length + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;

    if (map_length == 0)
    {
        map_length = PAGE_SIZE;
    }

    u64 map_start = 0;
    u64 map_end;
    struct vm_area *prev = current->vm_area;
    struct vm_area *curr;

    if (flags == MAP_FIXED)
    {
        map_start = addr;
        map_end = map_start + map_length;

        if (map_end > MMAP_AREA_END || map_start < MMAP_AREA_START)
        {
            return -1;
        }

        curr = current->vm_area->vm_next;
        while (curr != NULL)
        {
            // checking for overlap
            if (ranges_overlap(map_start, map_end, curr->vm_start, curr->vm_end))
            {
                return -1;
            }
            curr = curr->vm_next;
        }

        prev = current->vm_area;
        while (prev->vm_next != NULL && prev->vm_next->vm_start < map_start)
        {
            prev = prev->vm_next;
        }
        curr = prev->vm_next;
    }
    else
    {
        // used as boolean to check whether if address is not zero and if anything overlapping
        // or for the given address vma cannot be allocated
        int check = 0;

        if (addr != 0)
        {
            map_start = addr;
            map_end = map_start + map_length;
            int overlap = 0;

            if (map_start < MMAP_AREA_START || map_end > MMAP_AREA_END)
            {
                check = 1;
            }
            else
            {
                curr = current->vm_area->vm_next;
                while (curr != NULL)
                {
                    // checking for overlap
                    if (ranges_overlap(map_start, map_end, curr->vm_start, curr->vm_end))
                    {
                        overlap = 1;
                        break;
                    }
                    curr = curr->vm_next;
                }
                if (overlap)
                {
                    check = 1;
                }
                else
                {
                    prev = current->vm_area;
                    while (prev->vm_next != NULL && prev->vm_next->vm_start < map_start)
                    {
                        prev = prev->vm_next;
                    }
                    curr = prev->vm_next;
                }
            }
        }
        // search for a free gap, as addr has overlaps or addr is ot of MMAP_START and MMAP_END region
        if (addr == 0 || check)
        {
            map_start = 0;
            prev = current->vm_area;
            curr = prev->vm_next;

            // boolean to store whether we found any gap in the memory sapce
            u64 check2 = 0;
            while (1)
            {
                // searching for gap in the memory
                u64 gap_start, gap_end;

                gap_start = prev->vm_end;
                if (curr == NULL)
                {
                    gap_end = MMAP_AREA_END;
                }
                else
                {
                    gap_end = curr->vm_start;
                }
                // if we found a gap, we break out of loop
                if (gap_end > gap_start && (gap_end - gap_start) >= map_length)
                {
                    check2 = 1;
                    map_start = gap_start;
                    map_end = map_start + map_length;
                    break;
                }

                // if curr == NULL, means no gaps found
                if (curr == NULL)
                {
                    break;
                }

                prev = curr;
                curr = curr->vm_next;
            }

            if (check2 == 0)
            {
                return -1;
            }

            // finding the vm_area that comes before the newly allocated vma
            // so we can check whether we can merge the vm_areas
            prev = current->vm_area;
            while (prev->vm_next != NULL && prev->vm_next->vm_start < map_start)
            {
                prev = prev->vm_next;
            }
            curr = prev->vm_next;
        }
    }

    // merging vmas
    struct vm_area *new_vma = NULL;
    int merged_backward = 0;
    int merged_forward = 0;
    long return_addr = map_start;

    // here we are merging backward if prot of both vm_areas are same
    if (prev != current->vm_area && prev->vm_end == map_start && prev->access_flags == prot)
    {

        prev->vm_end = map_end;
        merged_backward = 1;

        new_vma = prev;
        return_addr = map_start;
    }

    // merging forward
    if (curr != NULL && curr->vm_start == map_end && curr->access_flags == prot)
    {

        if (merged_backward)
        {
            // already backward is merged, now we need to extend the vm_area from prev to next
            new_vma->vm_end = curr->vm_end;
            new_vma->vm_next = curr->vm_next;
            // Free the old curr VMA.
            free_vm_area(curr);
            merged_forward = 1;
        }
        else
        {

            curr->vm_start = map_start;
            merged_forward = 1;
            new_vma = curr;
            return_addr = map_start;
        }
    }
    // if no merges happened, we are making a new vm_area
    if (!merged_backward && !merged_forward)
    {

        new_vma = allocate_vm_area();
        if (!new_vma)
        {
            return -1;
        }
        new_vma->vm_start = map_start;
        new_vma->vm_end = map_end;
        new_vma->access_flags = prot;

        new_vma->vm_next = curr;
        prev->vm_next = new_vma;
        return_addr = map_start;
    }

    return return_addr;
}

/**
 * munmap system call implemenations
 */

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (addr % PAGE_SIZE != 0)
    {
        return -1;
    }

    u64 start = addr;
    u64 end = addr + length;
    if (end > MMAP_AREA_END)
    {
        end = MMAP_AREA_END;
    }

    if (end % PAGE_SIZE != 0)
    {
        end = ((end + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    }

    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;

    // loop through memeory to find vm_area that overlap with our unmap range .
    while (curr != NULL)
    {
        struct vm_area *next = curr->vm_next;
        // checking whther this curr vma is overlapping with the memory area that needed to be unmapped
        if (ranges_overlap(curr->vm_start, curr->vm_end, start, end))
        {
            u64 overlap_start = (curr->vm_start > start) ? curr->vm_start : start;
            u64 overlap_end = (curr->vm_end < end) ? curr->vm_end : end;

            for (u64 page_vaddr = overlap_start; page_vaddr < overlap_end; page_vaddr += PAGE_SIZE)
            {
                // getiing the virual address
                u64 *pte_addr = (u64 *)pte_address(current, page_vaddr);
                u64 entry_value = *pte_addr;
                // if pte_addr is NULL, means there is no mapping between VA TO PA
                if (pte_addr == NULL)
                {
                    continue;
                }

                // checking whether va is mapped to pa or not
                if (entry_value & 0x1)
                {
                    u64 user_data_pfn = PFN_FROM_ENTRY(entry_value);
                    *pte_addr = 0;
                    // os_pfn_free(USER_REG, user_data_pfn);
                    put_pfn(user_data_pfn);
                    flush_tlbs();
                }
            }

            // cases, different type of overlaps
            // here is curr is within the overlap
            if (start <= curr->vm_start && end >= curr->vm_end)
            {
                prev->vm_next = next;
                free_vm_area(curr);
            }

            // upperpart of curr is overlapping with memeory that needed to be unmapped
            else if (start > curr->vm_start && end >= curr->vm_end)
            {
                curr->vm_end = start;
                prev = curr;
            }

            // here lowerpart of curr is overlapping
            else if (start <= curr->vm_start && end < curr->vm_end)
            {
                curr->vm_start = end;
                prev = curr;
            }

            // a miiddle portion of curr is overlapping
            else
            {
                // here we are splitting the curr vma into two
                // spliting vma into two
                struct vm_area *tail_vma = allocate_vm_area();
                if (!tail_vma)
                {
                    return -1;
                }

                tail_vma->vm_start = end;
                tail_vma->vm_end = curr->vm_end;
                tail_vma->access_flags = curr->access_flags;
                tail_vma->vm_next = next;

                curr->vm_end = start;
                curr->vm_next = tail_vma;

                prev = tail_vma;
            }
        }

        else
        {

            prev = curr;
        }

        curr = next;
    }

    return 0;
}

/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    struct vm_area *fault_vma = NULL;

    struct vm_area *curr = current->vm_area->vm_next;
    // Align the fault address to the page boundary
    u64 fault_page_addr = addr & ~(PAGE_SIZE - 1);

    // looking for vma that includes the faulting page.
    while (curr != NULL)
    {
        if (fault_page_addr >= curr->vm_start && fault_page_addr < curr->vm_end)
        {
            fault_vma = curr;
            break;
        }
        curr = curr->vm_next;
    }

    if (fault_vma == NULL)
    {
        return -1; // VMA not found error
    }

    if ((error_code & 0x2) && !(fault_vma->access_flags & PROT_WRITE))
    {
        return -1;
    }

    // handling 0x7 error
    if (error_code == (0x7))
    {
        if ((fault_vma->access_flags & PROT_WRITE))
        {
            return handle_cow_fault(current, fault_page_addr, fault_vma->access_flags);
        }
        else
        {
            return -1;
        }
    }

    // handling 0x4 and 0x6 error
    if ((error_code == 0x4) || (error_code == 0x6))
    {
        //pointers to page table entries at all levels
        u64 *pgd_va;
        u64 *pud_va;
        u64 *pmd_va;
        u64 *pte_va;
        // points to the current table entry.
        u64 *page_addr;
        // gives value in that page address
        u64 page_data;
        // used for allocating new page tables.
        u64 new_table_pfn;

        // flags 0x1 - P
        // 0x8 - W
        // 0x10 - U
        // present (0x1), write (0x8), user (0x10).
        u64 table_flags = 0x1 | 0x8 | 0x10;

        u32 pgd_index = (fault_page_addr >> PGD_SHIFT) & 0x1FF;
        u32 pud_index = (fault_page_addr >> PUD_SHIFT) & 0x1FF;
        u32 pmd_index = (fault_page_addr >> PMD_SHIFT) & 0x1FF;
        u32 pte_index = (fault_page_addr >> PTE_SHIFT) & 0x1FF;

        // pgd
        pgd_va = (u64 *)osmap(current->pgd);
        page_addr = pgd_va + pgd_index;
        page_data = *page_addr;

        // checking for present bit, if there is no present bit then we will allocate a new
        // and set the present bit
        if (!(page_data & 0x1))
        {
            new_table_pfn = os_pfn_alloc(OS_PT_REG);
            pud_va = (u64 *)osmap(new_table_pfn);
            page_clear(pud_va);
            *page_addr = (new_table_pfn << 12) | table_flags;
        }
        else
        {
            pud_va = (u64 *)osmap(PFN_FROM_ENTRY(page_data));
        }

        // pud
        page_addr = pud_va + pud_index;
        page_data = *page_addr;

        // checking for present bit, if there is no present bit then we will allocate a new
        if (!(page_data & 0x1))
        {
            new_table_pfn = os_pfn_alloc(OS_PT_REG);
            pmd_va = (u64 *)osmap(new_table_pfn);
            page_clear(pmd_va);
            *page_addr = (new_table_pfn << 12) | table_flags;
        }
        else
        {
            pmd_va = (u64 *)osmap(PFN_FROM_ENTRY(page_data));
        }

        // pmd
        page_addr = pmd_va + pmd_index;
        page_data = *page_addr;

        // checking for present bit, if there is no present bit then we will allocate a new
        if (!(page_data & 0x1))
        {
            new_table_pfn = os_pfn_alloc(OS_PT_REG);
            pte_va = (u64 *)osmap(new_table_pfn);
            page_clear(pte_va);
            *page_addr = (new_table_pfn << 12) | table_flags;
        }
        else
        {
            pte_va = (u64 *)osmap(PFN_FROM_ENTRY(page_data));
        }

        // pte
        page_addr = pte_va + pte_index;
        page_data = *page_addr;

        // This allocates physical page if it's not present
        if (!(page_data & 0x1))
        {
            // Allocate the physical page
            u64 user_data_pfn = os_pfn_alloc(USER_REG);

            u64 pte_flags = (0x1 | 0x10); // set  (0x1)  (0x10)
            if (fault_vma->access_flags & PROT_WRITE)
            {
                pte_flags |= 0x8; // Add write flag if vma has write permisiion
            }

            // update the pte
            *page_addr = (user_data_pfn << 12) | pte_flags;
            flush_tlbs();
        }
        else
        {
            return -1;
        }

        return 1;
    }

    return -1;
}

/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the
 * end of this function (e.g., setup_child_context etc.)
 */

// using this to copy data from parent process to child process
/* struct exec_context{
    u32 pid;
    u32 ppid;
    u8 type;
    u8 state;
    u16 used_mem;
    u32 pgd;
    u32 os_stack_pfn;
    u64 os_rsp;
    struct mm_segment mms[MAX_MM_SEGS];
    struct vm_area * vm_area;
    char name[CNAME_MAX];
    struct user_regs regs;
    u32 pending_signal_bitmap;
    void* sighandlers[MAX_SIGNALS]; /*Signal handler pointers to functions (in user space)
    u32 ticks_to_sleep;
    u32 alarm_config_time;
    u32 ticks_to_alarm;
    struct file* files[MAX_OPEN_FILES];
    struct ctx_thread_info *ctx_threads;
};*/

// function to copy
static int copying_map(struct exec_context *parent, struct exec_context *child, u64 page_vaddr, u64 permission)
{
    // printk("copying_map: %lx\n", page_vaddr);
    u64 *pgd_va_p;
    u64 *pud_va_p;
    u64 *pmd_va_p;
    u64 *pte_va_p;
    u64 *entry_addr_p;

    u64 *pgd_va_c;
    u64 *pud_va_c;
    u64 *pmd_va_c;
    u64 *pte_va_c;
    u64 *entry_addr_c;
    u64 entry_value_p;
    u64 table_pfn_p;
    u64 table_pfn_c;

    u32 pgd_index = (page_vaddr >> PGD_SHIFT) & 0x1FF;
    u32 pud_index = (page_vaddr >> PUD_SHIFT) & 0x1FF;
    u32 pmd_index = (page_vaddr >> PMD_SHIFT) & 0x1FF;
    u32 pte_index = (page_vaddr >> PTE_SHIFT) & 0x1FF;

    // Permission flags: 9 = Read and User bit , 1 = only Read bit
    // here we need to remove write bit,so we are not considering write bit
    u64 flags = ((permission & PROT_WRITE) ? 9 : 1);

    // PGD
    pgd_va_p = (u64 *)osmap(parent->pgd);
    pgd_va_c = (u64 *)osmap(child->pgd);
    if (!pgd_va_p || !pgd_va_c)
    {
        return -1;
    }

    entry_addr_p = pgd_va_p + pgd_index;
    entry_addr_c = pgd_va_c + pgd_index;
    entry_value_p = *entry_addr_p;

    if ((entry_value_p & 0x1) == 0)
    {
        return 0;
    }

    if ((*entry_addr_c & 0x1) == 0)
    {
        table_pfn_c = os_pfn_alloc(OS_PT_REG);
        pud_va_c = (u64 *)osmap(table_pfn_c);
        if (!pud_va_c)
        {
            os_pfn_free(OS_PT_REG, table_pfn_c);
            {
                return -1;
            }
        }
        page_clear(pud_va_c);
        *entry_addr_c = (table_pfn_c << 12) | flags;
        *entry_addr_c = *entry_addr_c | 16;
    }
    else
    {
        table_pfn_c = (*entry_addr_c & (~0xFFFUL)) >> ADDR_SHIFT;
        pud_va_c = (u64 *)osmap(table_pfn_c);
    }

    table_pfn_p = PFN_FROM_ENTRY(entry_value_p);
    pud_va_p = (u64 *)osmap(table_pfn_p);

    // PUD
    entry_addr_p = pud_va_p + pud_index;
    entry_addr_c = pud_va_c + pud_index;
    entry_value_p = *entry_addr_p;

    if ((entry_value_p & 0x1) == 0)
    {
        return 0;
    }

    if ((*entry_addr_c & 0x1) == 0)
    {
        table_pfn_c = os_pfn_alloc(OS_PT_REG);
        pmd_va_c = (u64 *)osmap(table_pfn_c);
        if (!pmd_va_c)
        {
            os_pfn_free(OS_PT_REG, table_pfn_c);
            {
                return -1;
            }
        }
        page_clear(pmd_va_c);
        *entry_addr_c = (table_pfn_c << 12) | flags;
        *entry_addr_c = *entry_addr_c | 16;
    }
    else
    {
        table_pfn_c = (*entry_addr_c & (~0xFFFUL)) >> ADDR_SHIFT;
        pmd_va_c = (u64 *)osmap(table_pfn_c);
    }
    table_pfn_p = (entry_value_p & (~0xFFFUL)) >> ADDR_SHIFT;
    pmd_va_p = (u64 *)osmap(table_pfn_p);

    // PMD
    entry_addr_p = pmd_va_p + pmd_index;
    entry_addr_c = pmd_va_c + pmd_index;
    entry_value_p = *entry_addr_p;

    if (!(entry_value_p & 0x1))
    {
        return 0;
    }

    if (!(*entry_addr_c & 0x1))
    {
        table_pfn_c = os_pfn_alloc(OS_PT_REG);
        pte_va_c = (u64 *)osmap(table_pfn_c);
        if (!pte_va_c)
        {
            os_pfn_free(OS_PT_REG, table_pfn_c);
            {
                return -1;
            }
        }
        page_clear(pte_va_c);
        *entry_addr_c = (table_pfn_c << 12) | flags;
        *entry_addr_c = *entry_addr_c | 16;
    }
    else
    {
        table_pfn_c = PFN_FROM_ENTRY(*entry_addr_c);
        pte_va_c = (u64 *)osmap(table_pfn_c);
    }
    table_pfn_p = (entry_value_p & (~0xFFFUL)) >> ADDR_SHIFT;
    pte_va_p = (u64 *)osmap(table_pfn_p);

    // PTE
    entry_addr_p = pte_va_p + pte_index;
    entry_addr_c = pte_va_c + pte_index;
    entry_value_p = *entry_addr_p;
    if (!(entry_value_p & 0x1))
    {
        return 0;
    }

    u64 data_pfn = PFN_FROM_ENTRY(entry_value_p);
    // removing write access to child and parent
    u64 cow_flags = (entry_value_p | 0x4) & ~0x8UL; // here this make the user bit to 1 and write bit to 0
    *entry_addr_p = (data_pfn << 12) | cow_flags;
    *entry_addr_c = (data_pfn << 12) | cow_flags;

    // Increment reference count since both processes now share the page
    get_pfn(data_pfn);

    flush_tlbs();

    return 0;
}

long do_cfork()
{
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
    /* Do not modify above lines
     *
     * */
    /*--------------------- Your code [start]---------------*/

    // printk("Hey 1.5\n");
    // copying all contents of ctx to child ctx
    pid = new_ctx->pid;
    new_ctx->ppid = ctx->pid;
    new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;
    new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;
    new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;
    new_ctx->alarm_config_time = ctx->alarm_config_time;
    new_ctx->regs = ctx->regs;
    new_ctx->state = ctx->state;
    new_ctx->used_mem = ctx->used_mem;
    new_ctx->type = ctx->type;

    for (int i = 0; i < MAX_OPEN_FILES; i++)
    {
        new_ctx->files[i] = ctx->files[i];
    }
    for (int i = 0; i < MAX_SIGNALS; i++)
    {
        new_ctx->sighandlers[i] = ctx->sighandlers[i];
    }
    for (int i = 0; i < CNAME_MAX; i++)
    {
        new_ctx->name[i] = ctx->name[i];
    }

    // printk("Hey 2\n");
    // coying the vm_area of the parents to the child
    struct vm_area *new_ctx_vm = allocate_vm_area();
    struct vm_area *newhead = new_ctx_vm;
    newhead->vm_start = ctx->vm_area->vm_start;
    newhead->vm_end = ctx->vm_area->vm_end;
    newhead->access_flags = ctx->vm_area->access_flags;
    newhead->vm_next = NULL;
    new_ctx->vm_area = newhead;
    struct vm_area *temp = ctx->vm_area->vm_next;
    struct vm_area *temp2 = new_ctx->vm_area;
    while (temp != NULL)
    {
        struct vm_area *dummy_vma = allocate_vm_area();
        dummy_vma->access_flags = temp->access_flags;
        dummy_vma->vm_start = temp->vm_start;
        dummy_vma->vm_end = temp->vm_end;

        temp2->vm_next = dummy_vma;
        temp = temp->vm_next;
        temp2 = temp2->vm_next;
    }

    temp2->vm_next = NULL;

    // printk("Hey 3\n");
    new_ctx->vm_area = newhead;

    for (int i = 0; i < MAX_MM_SEGS; i++)
    {
        new_ctx->mms[i] = ctx->mms[i];
    }

    // making a PGD table for child
    // we use that table to allocatechild virutual meemory to physical memeory
    new_ctx->pgd = os_pfn_alloc(OS_PT_REG);

    // mapping virtual address to physicla address of child vm_area
    struct vm_area *temp3 = new_ctx->vm_area;
    while (temp3 != NULL)
    {
        u64 start = temp3->vm_start;
        u64 end = temp3->vm_end;
        u64 prot = temp3->access_flags;

        for (u64 i = start; i < end; i += PAGE_SIZE)
        {
            if (copying_map(ctx, new_ctx, i, temp3->access_flags) == -1)
            {
                return -1;
            }
        }
        temp3 = temp3->vm_next;
    }
    // printk("Hey 4\n");

    // now mapping VA to PA of child
    // create the page table entries for the present
    // pages in the following memory segments of the child process—MM SEG CODE, MM SEG RODATA,
    // MM SEG DATA, MM SEG STACK and for the VMAs of the child process.
    u64 start;
    u64 end;

    // printk("Hey 5\n");
    start = ctx->mms[MM_SEG_CODE].start;
    end = ctx->mms[MM_SEG_CODE].next_free;
    // printk("Hey pls\n");
    for (; start < end; start += PAGE_SIZE)
    {
        // printk("Hey 5.5\n");
        if (copying_map(ctx, new_ctx, start, new_ctx->mms[MM_SEG_CODE].access_flags) == -1)
        {
            // printk("Error icopying 1\n");
            return -1;
        }
    }

    // printk("Hey 6\n");
    start = ctx->mms[MM_SEG_RODATA].start;
    end = ctx->mms[MM_SEG_RODATA].next_free;

    for (; start < end; start += PAGE_SIZE)
    {
        if (copying_map(ctx, new_ctx, start, new_ctx->mms[MM_SEG_RODATA].access_flags) == -1)
        {
            // printk("Error icopying 2\n");
            return -1;
        }
    }

    // printk("Hey 7\n");
    start = ctx->mms[MM_SEG_DATA].start;
    end = ctx->mms[MM_SEG_DATA].next_free;
    for (; start < end; start += PAGE_SIZE)
    {
        if (copying_map(ctx, new_ctx, start, new_ctx->mms[MM_SEG_DATA].access_flags) == -1)
        {
            // printk("Error icopying 3\n");
            return -1;
        }
    }

    // printk("Hey 8\n");
    start = ctx->mms[MM_SEG_STACK].next_free - PAGE_SIZE;
    end = ctx->mms[MM_SEG_STACK].end;
    for (; start < end; start += PAGE_SIZE)
    {
        if (copying_map(ctx, new_ctx, start, new_ctx->mms[MM_SEG_STACK].access_flags) == -1)
        {
            // printk("Error icopying 4\n");
            return -1;
        }
    }

    // printk("Hey 9\n");
    flush_tlbs();

    /*--------------------- Your code [end] ----------------*/

    /*
     * The remaining part must not be changed
     */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}

/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data)
 * it is called when there is a CoW violation in these areas.
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    u64 *pgd_virtual = (u64 *)(osmap(current->pgd));

    //pointers to page table entries at all levels
    u64 *pgd_va;
    u64 *pud_va;
    u64 *pmd_va;
    u64 *pte_va;

    u32 pfn_index = PFN_FROM_ENTRY(vaddr);
    u32 pgd_index = (vaddr >> PGD_SHIFT) & 0x1FF;
    u32 pud_index = (vaddr >> PUD_SHIFT) & 0x1FF;
    u32 pmd_index = (vaddr >> PMD_SHIFT) & 0x1FF;
    u32 pte_index = (vaddr >> PTE_SHIFT) & 0x1FF;

    // pgd offset adding
    pgd_va = (osmap(current->pgd));
    pgd_va = pgd_va + pgd_index;

    // present bit is 1
    if ((access_flags & PROT_WRITE) != 0)
    {
        *(pgd_va) = (*pgd_va) | 0x8;
    }

    pud_va = (u64 *)osmap(((*pgd_va) >> ADDR_SHIFT)) + pud_index;

    // present bit is 1
    if ((access_flags & PROT_WRITE) != 0)
    {
        *(pud_va) = (*pud_va) | 0x8;
    }

    // pmd offset adding
    pmd_va = (u64 *)osmap(((*pud_va) >> ADDR_SHIFT)) + pmd_index;

    // present bit is 1
    if ((access_flags & PROT_WRITE) != 0)
    {
        *(pmd_va) = (*pmd_va) | 0x8;
    }

    // pte offset adding
    pte_va = (u64 *)osmap(((*pmd_va) >> ADDR_SHIFT)) + pte_index;

    u64 new_pfn = os_pfn_alloc(USER_REG);
    u64 old_pfn = ((*(pte_va)) >> ADDR_SHIFT);

    // copy the contents of the old page to the new page
    memcpy((char *)osmap(new_pfn), (char *)osmap(old_pfn), PAGE_SIZE);

    // point this process to the new pfn
    *(pte_va) = (new_pfn << ADDR_SHIFT) | 0x11;

    // restore write permission if the VMA allows it
    if ((access_flags & PROT_WRITE) != 0)
    {
        *(pte_va) |= 0x8;
    }
    else
    {
        *pte_va &= ~(0x8);
    }

    // decrease the ref_count of the old pfn
    put_pfn(old_pfn);

    //if reference count is 0, free the physical memeory
    if (get_pfn_refcount(old_pfn) == 0)
    {
        os_pfn_free(USER_REG, old_pfn);
    }
    flush_tlbs();
    return 1;
}
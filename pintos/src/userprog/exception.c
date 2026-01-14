#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "vm/page.h"
#include "userprog/pagedir.h"

/* Number of page faults processed. */
static long long page_fault_cnt;
static bool 
page_exist(struct spt *spte , bool write);
bool stack_growth(void *addr);
static bool
load_page (struct spt *spte,int i);
static 
void page_handler(void *fpage, bool write, bool user, struct intr_frame *f);

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. 
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  */

  page_handler(fault_addr,write, user, f);
  
}

//spt 없을 때(spt_find 활용)->주소 검사 -> valid 할 시 kill
/*static 
void page_handler(void *fpage, bool write, bool user, struct intr_frame *f){
  
  void *fault_addr = pg_round_down (fpage);
  if(is_kernel_vaddr(fault_addr)) kill(f);
  struct spt *spte = spt_find(&thread_current()->spt, fault_addr);
  if(spte != NULL){
     if(!page_exist(spte,write)) kill(f);
     return;
  }
  
   if(fpage>= (f->esp - 32) && (PHYS_BASE - fpage) <= STACK_MAX){
        bool i = stack_growth(fault_addr);
        if(!i) kill(f);
        return;
     }
     kill(f);
  
}*/

static void
page_handler(void *fpage, bool write, bool user, struct intr_frame *f)
{
    void *addr = pg_round_down(fpage);

    if (!user)
        kill(f);
    if (fpage == NULL || !is_user_vaddr(fpage))
        kill(f);


    if (addr == NULL || addr >= PHYS_BASE)
        kill(f);

    struct spt *spte = spt_find(&thread_current()->spt, addr);

    if (spte != NULL) {
        if (!page_exist(spte, write))
            kill(f);
        return;
    }

    if (fpage >= f->esp - 32 &&
        fpage < PHYS_BASE &&
        PHYS_BASE - fpage <= STACK_MAX) {

        if (!stack_growth(addr))
            kill(f);

        spte = spt_find(&thread_current()->spt, addr);

        if (!load_page(spte, 3))   
            kill(f);

        return;
    }

    kill(f);
}


static bool 
page_exist(struct spt *spte , bool write){
   if(write && !spte->writable){
       return false;
     }
   if (spte->page_state == PAGE_FRAME)
     return true;
   int s = 0;
   switch (spte->page_state) {
    case PAGE_FILE:
        s = 1;
        return load_page(spte,s);
    case PAGE_SWAP:
        s=2;
        return load_page(spte,s);
    case PAGE_ZERO:
        s=3;
        return load_page(spte,s);
    case PAGE_FRAME:
        return true;

        return false;
   }
}

bool stack_growth(void *addr){
   struct spt *spte = malloc (sizeof *spte);
   if (!spte) return false;
   spte->vaddr = pg_round_down(addr);
   spte->writable = true;
   spte->page_state = PAGE_ZERO;
   spte->loaded = false;

   spt_insert(&thread_current()->spt, spte);
   return true;
}

static bool
load_page (struct spt *spte,int i)
{
   
    struct thread *t = thread_current ();
    void *kva = frame_alloc (PAL_USER,spte);
    if (!kva) return false;

    bool ok =false;
    switch (i)
    {
    case 1:
        ok = load_file (spte, kva);
        break;
    case 2:
        swap_in (spte->swap_index, kva);
        ok = true;
        break;
    case 3:
        memset (kva, 0, PGSIZE);
        ok = true;
        break;
    default:
        return false;
    }
    if (!ok) {
        free_frame(kva);
        return false;
    }
    if (!pagedir_set_page (t->pagedir, spte->vaddr, kva, spte->writable)){
        free_frame(kva);
        return false;
    }
    lock_acquire(&frame_lock);
    struct frame *f = kva_to_frame (kva);
    f->use_io = false;
    lock_release(&frame_lock);
    spte->page_state = PAGE_FRAME;
    spte->frame= kva;
    spte->loaded = true;
    return true;
}

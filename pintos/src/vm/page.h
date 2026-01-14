#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <stddef.h>
#include "hash.h"

#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

#define STACK_MAX (8 * 1024 * 1024)
enum page_location{
    PAGE_FILE,
    PAGE_SWAP,
    PAGE_ZERO,
    PAGE_FRAME
};
struct frame;

struct spt {
    void *vaddr;
    bool writable;
    bool loaded;
    enum page_location page_state;
    size_t read;
    size_t zero;
    struct file *file;
    off_t offset;
    size_t swap_index;
    struct frame *frame;
    struct hash_elem elem;
    struct thread *t;
};
struct frame {
    void *kva;
    struct spt *page;
    bool use_io;
    struct thread *t;
    struct list_elem elem;
};

extern struct list frame_table;
extern struct lock frame_lock;



bool load_file(struct spt *spte, void *kva);
void free_frame(void *kva_addr);
void *frame_alloc(enum palloc_flags, struct spt *spte);
void *frame_spacing(enum palloc_flags );
void evict_frame(struct frame *victim);
void backlocation_page(struct spt *spte, void *kva,bool is_dirty);
struct frame *frame_victim (void);
bool frame_evi_val(struct frame *f);
void frame_init(void);
struct frame *kva_to_frame (void *kva);
struct hash_elem *spt_va_to_elem(struct hash *spt, void *va);
void page_free (struct spt *spte) ;
unsigned spt_hash (const struct hash_elem *e, void *aux UNUSED) ;
struct spt *spt_find (struct hash *spt, void *va);
bool spt_insert (struct hash *spt, struct spt *spte);
void spt_remove (struct hash *spt, struct spt *spte) ;
bool spt_less (const struct hash_elem *a,const struct hash_elem *b,void *aux UNUSED);
void spt_destroy (struct hash_elem *e, void *aux UNUSED);

#endif
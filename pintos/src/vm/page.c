#include "page.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

struct list_elem *clock_hand;


struct list frame_table;
struct lock frame_lock;

unsigned
spt_hash (const struct hash_elem *e, void *aux UNUSED) {
    const struct spt *spte = hash_entry (e, struct spt, elem);
    return hash_bytes (&spte->vaddr, sizeof spte->vaddr);
}


bool
spt_less (const struct hash_elem *a,const struct hash_elem *b,void *aux UNUSED) {
    const struct spt *spta = hash_entry (a, struct spt, elem);
    const struct spt *sptb = hash_entry (b, struct spt, elem);
    return spta->vaddr < sptb->vaddr;
}

bool spt_insert (struct hash *spt, struct spt *spte) {
    spte->vaddr = pg_round_down(spte->vaddr); 
    return hash_insert (spt, &spte->elem) == NULL; 
}

struct spt *
spt_find (struct hash *spt, void *va) {
    struct hash_elem *e = spt_va_to_elem (spt, va);
    return e != NULL ? hash_entry (e, struct spt, elem) : NULL;
}

void
spt_remove (struct hash *spt, struct spt *spte) {
    hash_delete (spt, &spte->elem);
    page_free(spte);
    free (spte);
}

void
spt_destroy (struct hash_elem *e, void *aux UNUSED) {
    struct spt *spte = hash_entry (e, struct spt, elem);
    page_free(spte);
    free (spte);
}



/*void page_free (struct spt *spte) {
    switch (spte->page_state) {
     case PAGE_FRAME:
       free_frame(spte->frame);
       break;
     case PAGE_SWAP:
       swap_free(spte->swap_index);
       break;
     case PAGE_FILE:
       break;
     case PAGE_ZERO:
       break;
    }
}*/

void page_free (struct spt *spte) {
    if (spte == NULL)
        return;

    if (spte->page_state == PAGE_FRAME) {
        if (spte->loaded && spte->frame != NULL && spte->vaddr != NULL) {
            free_frame(spte->frame);
        }
    }
    else if (spte->page_state == PAGE_SWAP) {
        swap_free(spte->swap_index);
    }
}



struct hash_elem *
spt_va_to_elem(struct hash *spt, void *va){
    struct spt temp;
    temp.vaddr = pg_round_down (va); 
    return hash_find(spt, &temp.elem);
}
struct frame *
kva_to_frame (void *kva){
    struct list_elem *e;
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e)){
        struct frame *fr = list_entry (e, struct frame, elem);
        if (fr->kva == kva) return fr;
    }
    return NULL;
}


void
frame_init(void){
    list_init(&frame_table);
    lock_init(&frame_lock);
    clock_hand = list_begin(&frame_table);
}

/*
bool 
frame_evi_val(struct frame *f) {
    if (f->page == NULL) return true;
    if (f->use_io) return false;
    struct thread *owner = f->t;
    

    if (pagedir_is_accessed(owner->pagedir, f->page->vaddr)) {
        pagedir_set_accessed(owner->pagedir, f->page->vaddr, false);
        return false;
    }
}
    */

    bool frame_evi_val(struct frame *f)
{
    if (f == NULL || f->page == NULL || f->use_io)
        return false;

    if (pagedir_get_page(f->t->pagedir, f->page->vaddr) == NULL)
        return false;

    if (pagedir_is_accessed(f->t->pagedir, f->page->vaddr)) {
        pagedir_set_accessed(f->t->pagedir, f->page->vaddr, false);
        return false;
    }
    return true;
}


struct frame *
frame_victim (void) {
    if (list_empty (&frame_table)) return NULL;
    struct list_elem *e = clock_hand;
    if (e == NULL || e == list_end (&frame_table)) {
        e = list_begin (&frame_table);
    }
    size_t table_size = list_size (&frame_table);
    size_t limit = table_size * 2; 
    for (size_t i = 0; i < limit; i++) {
        if (e == list_end (&frame_table)) {
            e = list_begin (&frame_table);
        }
        struct frame *c = list_entry (e, struct frame, elem);
        e = list_next (e); 
        if (frame_evi_val (c)) {
            clock_hand = e; 
            return c;
        }
    }
    clock_hand = e;
    return NULL;
}


void backlocation_page(struct spt *spte, void *kva,bool is_dirty) {
    if (spte->page_state == PAGE_FILE && !is_dirty) {
        return;
    }
    spte->swap_index = swap_out(kva);
    spte->page_state = PAGE_SWAP;
}
/*
void evict_frame(struct frame *victim) {
    if (victim == NULL || victim->use_io || victim->page == NULL) {
        return;
    }

    struct spt *t_spte = victim->page;
    struct thread *owner = victim->t;
    bool is_dirty = pagedir_is_dirty(owner->pagedir, t_spte->vaddr);
    
    backlocation_page(t_spte, victim->kva, is_dirty);
    pagedir_clear_page(owner->pagedir, t_spte->vaddr);
    t_spte->loaded = false;
    t_spte->frame = NULL;
    victim->page = NULL;
}*/

void evict_frame(struct frame *victim)
{
    if (victim == NULL || victim->use_io || victim->page == NULL)
        return;

    struct spt *spte = victim->page;
    struct thread *owner = victim->t;

    bool dirty = false;

    if (pagedir_get_page(owner->pagedir, spte->vaddr) != NULL)
        dirty = pagedir_is_dirty(owner->pagedir, spte->vaddr);

    backlocation_page(spte, victim->kva, dirty);

    if (pagedir_get_page(owner->pagedir, spte->vaddr) != NULL)
        pagedir_clear_page(owner->pagedir, spte->vaddr);

    spte->loaded = false;
    spte->frame = NULL;
    victim->page = NULL;
}


void *
frame_spacing(enum palloc_flags flags) {
    void *paddr = palloc_get_page(flags);
    
    while (paddr == NULL) {
        struct frame *vic = frame_victim();
        if (vic == NULL) break;
        evict_frame(vic);
        list_remove(&vic->elem);
        void *r_kva = vic->kva;
        free(vic);
        
        palloc_free_page(r_kva);
        
        paddr = palloc_get_page(flags);
    }
    return paddr;
}

void *frame_alloc(enum palloc_flags flags, struct spt *spte) {
    if (!(flags & PAL_USER) || spte == NULL) return NULL;
    lock_acquire(&frame_lock);
    void *kva = frame_spacing(flags);
    if (kva == NULL) {
        lock_release(&frame_lock);
        return NULL;
    }
    struct frame *new_fr = malloc(sizeof(struct frame));
    if (new_fr == NULL) {
        palloc_free_page(kva);
        lock_release(&frame_lock);
        return NULL;
    }

    new_fr->kva = kva;
    new_fr->t = thread_current();
    new_fr->page = spte;
    new_fr->use_io = true;
    list_push_back(&frame_table, &new_fr->elem);
    lock_release(&frame_lock);
    return kva;
}

/*void free_frame(void *kva_addr) {
    if (kva_addr == NULL) return;
    lock_acquire(&frame_lock);
    struct frame *fr = kva_to_frame(kva_addr);
    if (fr) {
        list_remove(&fr->elem);
        palloc_free_page(fr->kva);
        if (fr->page)
          pagedir_clear_page(fr->t->pagedir, fr->page->vaddr);
 
        free(fr);
    }
    lock_release(&frame_lock);
}*/

void free_frame(void *kva_addr) {
    if (kva_addr == NULL) return;

    lock_acquire(&frame_lock);
    struct frame *fr = kva_to_frame(kva_addr);
    if (fr) {
        list_remove(&fr->elem);
        palloc_free_page(fr->kva);
        free(fr);
    }
    lock_release(&frame_lock);
}



bool load_file(struct spt *spte, void *kva) {
    if (file_read_at(spte->file, kva, spte->read, spte->offset) != (int)spte->read)
        return false;
    memset(kva + spte->read, 0, spte->zero);
    return true;
}

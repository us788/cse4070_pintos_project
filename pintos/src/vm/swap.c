#include "swap.h"




struct block *swap_block;
struct bitmap *swap_bitmap;
struct lock swap_lock;

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)
inline bool
valid_vaddr (const void *vaddr) ;
void
swap_init (void);
size_t
swap_out (void *kva);
void swap_free(size_t idx);
void
swap_in (size_t idx, void *kva);

inline bool
valid_vaddr (const void *vaddr) 
{  
    if (vaddr == NULL || vaddr < PHYS_BASE){
       return false;
    }
    return true;
}
void
swap_init (void)
{
    swap_block = block_get_role (BLOCK_SWAP);
    if (swap_block == NULL) PANIC ("swap failed");

    size_t total_sectors = block_size (swap_block);
    size_t page_cnt = total_sectors / SECTORS_PER_PAGE;

    swap_bitmap = bitmap_create (page_cnt);
    if (swap_bitmap == NULL) PANIC ("swap bitmap create failed");

    bitmap_set_all (swap_bitmap, false);
    lock_init (&swap_lock);
}
size_t
swap_out (void *kva)
{
    lock_acquire (&swap_lock);
    size_t idx = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
    if (idx == BITMAP_ERROR) {
        lock_release (&swap_lock);
        PANIC ("Swap space exhausted");
    }
    lock_release (&swap_lock);
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
        block_write (swap_block,idx * SECTORS_PER_PAGE + i,(uint8_t *)kva + i * BLOCK_SECTOR_SIZE);
    }
    return idx;
}
void
swap_in (size_t idx, void *kva)
{
    lock_acquire (&swap_lock);
    ASSERT (bitmap_test (swap_bitmap, idx));
    lock_release (&swap_lock);

    for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
      block_read (swap_block,idx * SECTORS_PER_PAGE + i,(uint8_t *)kva + i * BLOCK_SECTOR_SIZE);
    }

    lock_acquire (&swap_lock);
    bitmap_set (swap_bitmap, idx, false);
    lock_release (&swap_lock);
}


void swap_free(size_t idx) {
    lock_acquire(&swap_lock);
    bitmap_set(swap_bitmap, idx, false);
    lock_release(&swap_lock);
}

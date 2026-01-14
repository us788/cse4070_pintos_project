#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
static void syscall_halt();
static void syscall_exit(int status);
static int syscall_read(int fd, void *buffer, unsigned size);
static int syscall_write(int fd, void *buffer, unsigned size);
static tid_t syscall_exec(const char *cmd);
static void check_vaddr(void *addr, unsigned s);
static int stack_arg(void *f, int index);
static void syscall_seek(int fd, unsigned index);
static int syscall_open(const char *name);
static int syscall_close(int fd);
static int syscall_filesize(int fd);
static void syscall_seek(int fd, unsigned index);
static unsigned syscall_tell(int fd);
bool val_name(const char *name);
struct lock filelock; 
void
syscall_init (void) 
{
  lock_init(&filelock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{ check_vaddr(f->esp,sizeof(void *));

  switch (*(int *)f->esp)
  {
        case SYS_HALT: {
            syscall_halt();
            break;
        }
        case SYS_EXIT: {
            int status = stack_arg(f->esp, 1);
            syscall_exit(status);
            break;
        }

        case SYS_READ: {
            int fd = stack_arg(f->esp, 1);
            void *buffer = (void *)stack_arg(f->esp, 2);
            unsigned size = (unsigned)stack_arg(f->esp, 3);
            lock_acquire(&filelock);
            if(val_fd(fd)==-1) {
              lock_release(&filelock);
              syscall_exit(-1);
            }
            lock_release(&filelock);
            f->eax = syscall_read(fd,buffer,size);
            break;
        }
        case SYS_WRITE: {
            int fd = stack_arg(f->esp, 1);
            void *buffer = (void *)stack_arg(f->esp, 2);
            unsigned size = (unsigned)stack_arg(f->esp, 3);
            lock_acquire(&filelock);
            if(val_fd(fd)==-1) {
              lock_release(&filelock);
              syscall_exit(-1);
            }
            lock_release(&filelock);
            f->eax = syscall_write(fd,buffer,size);
            break;
        }
        case SYS_WAIT: {
            int pid = stack_arg(f->esp,1);
            f->eax = process_wait((tid_t)pid);
            break;
        }
        case SYS_EXEC: {
            const char *cmd = (const char *)stack_arg(f->esp,1);
            tid_t new = syscall_exec(cmd);
            f->eax = ( new!= TID_ERROR) 
             ? (int)new
             : (int)TID_ERROR;
            break;
        }
        case SYS_CREATE: {
            const char *file = (const char *)stack_arg(f->esp,1);
            unsigned initial_size = (unsigned)stack_arg(f->esp,2);
            if (!val_name(file)) syscall_exit(-1);
            lock_acquire(&filelock);
            f->eax = filesys_create(file, initial_size);
            lock_release(&filelock);
          break;
        }
        case SYS_REMOVE: {
            const char *name = (const char *)stack_arg(f->esp,1);
            if (!val_name(name)) syscall_exit(-1);
            lock_acquire(&filelock);
            f->eax = filesys_remove(name);
            lock_release(&filelock);
          break;
        }
        case SYS_OPEN: {
            const char *file = (const char *)stack_arg(f->esp,1);
            if (!val_name(file)) syscall_exit(-1);
            f->eax = syscall_open(file);
          break;
        }
        case SYS_CLOSE: {
            int fd = stack_arg(f->esp,1);
            syscall_close(fd);
          break;
        }
        case SYS_FILESIZE: {
            int fd = stack_arg(f->esp,1);
            f->eax = syscall_filesize(fd);
          break;
        }
        case SYS_SEEK: {
          int fd = stack_arg(f->esp,1);
          unsigned index = (unsigned)stack_arg(f->esp,2);
          syscall_seek(fd,index);
          break;
        }
        case SYS_TELL: {
          int fd = stack_arg(f->esp,1);
          f->eax = syscall_tell(fd);
          break;
        }
        default: {
            syscall_exit(-1);
            break;
        }
  }
}

static tid_t
syscall_exec(const char *cmd){
  check_vaddr(cmd,1);
  check_vaddr(cmd,strlen(cmd)+1);
  return process_execute(cmd);
}

static int 
syscall_open(const char *name){
  if(val_file(name)==-1) return -1;
  lock_acquire(&filelock);
  struct file *f = filesys_open(name);
  if (f == NULL) {
    lock_release(&filelock);
    return -1;
  }
  int fd = put_fd(f);
  if(fd==-1){
    file_close(f);
    lock_release(&filelock);
    return -1;
  }
  lock_release(&filelock);
  return fd;
}

static int 
syscall_close(int fd){
  if(val_fd(fd)==-1) return -1;
  struct file *f = get_fd(fd);
  if(f!=NULL){
    lock_acquire(&filelock);
    file_close(f);
    rid_fd(fd);
    lock_release(&filelock);
    return 1;
  }
  return -1;
}
static int 
syscall_filesize(int fd){
  if(val_fd(fd)==-1||fd==0||fd==1||fd==2) return -1;
  struct file *f = get_fd(fd);
  if(f!=NULL){
    lock_acquire(&filelock);
    int size = file_length(f);
    lock_release(&filelock);
    return size;
  }
  return -1;
}

static void
syscall_seek(int fd, unsigned index){
  if(val_fd(fd)==-1) return;
  struct file *f = get_fd(fd);
  if(f!=NULL){
    lock_acquire(&filelock);
    file_seek(f,index);
    lock_release(&filelock);
  }
}

static unsigned 
syscall_tell(int fd){
  if(val_fd(fd)==-1) return -1;
  struct file *f = get_fd(fd);
  if(f!=NULL){
    lock_acquire(&filelock);
    unsigned index = file_tell(f);
    lock_release(&filelock);
    return index;
  }
  return -1;
}
static void
syscall_halt(void){
  shutdown_power_off();
}

static void
syscall_exit(int status){
  struct thread *t = thread_current();
  t->exit_status= status;
  thread_exit();
}

static int 
stack_arg(void *f, int index){
  const int *base = (const int *)f;
  void *p= (void *)(base + index);
  check_vaddr(p,sizeof(int));
  int r= *(int *)p;
  return r; 
}


/*static void 
check_vaddr(void *addr, unsigned size) {
    const void *end_addr = addr + size;
    if (addr == NULL || end_addr < addr)
        syscall_exit(-1);

    for (const uint8_t *p = pg_round_down(addr);p <= (uint8_t *) end_addr;p += PGSIZE) {

        if (!is_user_vaddr(p) || pagedir_get_page(thread_current()->pagedir, p) == NULL)
            syscall_exit(-1);
    }
}*/
static void 
check_vaddr(void *addr, unsigned size) {
    if (addr == NULL)
        syscall_exit(-1);

    uint8_t *start = addr;
    uint8_t *end = start + size - 1;

    if (end < start)
        syscall_exit(-1);

    for (uint8_t *p = pg_round_down(start);
         p <= pg_round_down(end);
         p += PGSIZE) {

        if (!is_user_vaddr(p))
            syscall_exit(-1);

        if (spt_find(&thread_current()->spt, p) == NULL)
            syscall_exit(-1);
    }
}




bool val_name(const char *name) {
    if (!name) return false;  

    for (const char *ptr = name; ; ptr++) {
        check_vaddr((void *)ptr, 1);  
        if (*ptr == '\0') break;      
    }
    return true;
}


static int
syscall_read(int fd, void *buffer, unsigned size){
    check_vaddr(buffer, size);
    if(size == 0) return 0;
    if (fd < 0 || fd >= MAX_FD) return -1;

    int bytes = 0;

    switch (fd) {
        case 0: {
            uint8_t *ptr = (uint8_t *)buffer;
            for(unsigned i = 0; i < size; i++){
                *ptr++ = input_getc();
            }
            bytes = size;
            break;
        }

        default: {
            lock_acquire(&filelock); 
            struct file *f = get_fd(fd);
            if(!f){
                bytes = -1;
                lock_release(&filelock);
                break;
            }
  
            bytes = file_read(f, buffer, size);
            lock_release(&filelock);
            break;
        }
    }

    return bytes;
}

static int
syscall_write(int fd, void *buffer, unsigned size){
    check_vaddr(buffer, size);
    if(size == 0) return 0;
    if (fd < 0 || fd >= MAX_FD) return -1;

    int bytes = 0;

    switch (fd) {
        case 1: {
            putbuf(buffer, size);
            bytes = size;
            break;
        }

        default: {
           lock_acquire(&filelock);
            struct file *f = get_fd(fd);
            if(!f){
                bytes = -1;
                lock_release(&filelock);
                break;
            }
            
            bytes = file_write(f, buffer, size);
            lock_release(&filelock);
            break;
        }
    }

    return bytes;
}



/*
static int
syscall_read(int fd, void *buffer, unsigned size){
  check_vaddr(buffer, size);
  int bytes=0;
  if(size==0) return 0;
      switch (fd) {
        case 0: { 
            uint8_t *ptr = (uint8_t *)buffer;
            
            for (unsigned i = 0; i < size; i++) {
                *ptr++ = input_getc();
            }
            bytes = size;
            break;
        }

        default: { 
            bytes = -1;
            break;
        }
      }
  return bytes;
}
static int
syscall_write(int fd, void *buffer, unsigned size){
  check_vaddr(buffer, size);
  int bytes=0;
  if(size==0) return 0;
      switch (fd) {
        case 1: { 
            putbuf(buffer, size);
            bytes = size;
            break;
        }

        default: { 
            bytes = -1;
            break;
        }
      }
  return bytes;
}
*/
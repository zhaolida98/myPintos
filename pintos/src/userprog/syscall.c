#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <threads/vaddr.h>
#include <filesys/filesys.h>
#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/palloc.h>
#include <threads/malloc.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"
#include "syscall.h"

// syscall array
syscall_function syscalls[SYSCALL_NUMBER];

static void syscall_handler (struct intr_frame *);
<<<<<<< HEAD
=======
bool is_ptr_valid(void *esp);
void killthread(int status);
void* check_addr(const void*);
void exit_proc(int status);

typedef void (*SYSCALLS)(struct intr_frame*);
SYSCALLS syscall_list[ALLCALL]; //there are 20 in total
//there are 20 in total
/* Projects 2  */
void IHalt(struct intr_frame*); 
void IExit(struct intr_frame*); 
void IExec(struct intr_frame*); 
void IWait(struct intr_frame*); 
void ICreate(struct intr_frame*); 
void IRemove(struct intr_frame*); 
void IOpen(struct intr_frame*); 
void IFilesize(struct intr_frame*); 
void IRead(struct intr_frame*); 
void IWrite(struct intr_frame*); 
void ISeek(struct intr_frame*); 
void ITell(struct intr_frame*); 
void IClose(struct intr_frame*); 

/* Project 3 and optionally project 4. */
// void IMmap(struct intr_frame*); 
// void IMunmap(struct intr_frame*); 
/* Project 4 only. */
// void IChdir(struct intr_frame*); 
// void IMkdir(struct intr_frame*); 
// void IReaddir(struct intr_frame*); 
// void IIsdir(struct intr_frame*); 
// void IInuber(struct intr_frame*); 
struct proc_file* list_search(struct list* files, int fd);
>>>>>>> 87488076e9e7946cb90d58bf05e81b5d0241b156

void exit(int exit_status){
  thread_current()->exit_status = exit_status;
  thread_exit ();
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // initialize the syscalls
  for(int i = 0; i < SYSCALL_NUMBER; i++) syscalls[i] = NULL;
  // bind the syscalls to specific index of the array
  syscalls[SYS_EXIT] = sys_exit;
  syscalls[SYS_HALT] = sys_halt;
  syscalls[SYS_EXEC] = sys_exec;
  syscalls[SYS_WAIT] = sys_wait;
  syscalls[SYS_CREATE] = sys_create;
  syscalls[SYS_REMOVE] = sys_remove;
  syscalls[SYS_OPEN] = sys_open;
  syscalls[SYS_FILESIZE] = sys_filesize;
  syscalls[SYS_READ] = sys_read;
  syscalls[SYS_WRITE] = sys_write;
  syscalls[SYS_SEEK] = sys_seek;
  syscalls[SYS_TELL] = sys_tell;
  syscalls[SYS_CLOSE] = sys_close;
}

<<<<<<< HEAD
// check whether page p and p+3 has been in kernel virtual memory
void check_page(void *p) {
  void *pagedir = pagedir_get_page(thread_current()->pagedir, p);
  if(pagedir == NULL) exit(-1);
  pagedir = pagedir_get_page(thread_current()->pagedir, p + 3);
  if(pagedir == NULL) exit(-1);
}

// check whether page p and p+3 is a user virtual address
void check_addr(void *p) {
  if(!is_user_vaddr(p)) exit(-1);
  if(!is_user_vaddr(p + 3)) exit(-1);
=======
bool is_ptr_valid(void *esp)
{
  // hex_dump((uintptr_t)esp, esp, (int)PHYS_BASE - (int)(esp), 1);
  if (esp >(void*)PHYS_BASE|| esp<(void *)0x08048000)
  {
    // thread_current()->exit_error_code = -1;
    // thread_current()->parent->exit = 1;
    // thread_exit();
    return false;
  }
  return true;
}

void killthread(int status)
{
  if (status<0 && status !=-1)
  {
    status=-1;
  }
  struct thread *t = thread_current();
  t->exit_error_code = status;
  t->parent->exit=1;
  thread_exit();
>>>>>>> 87488076e9e7946cb90d58bf05e81b5d0241b156
}

// make check for page p
void check(void *p) {
  if(p == NULL) exit(-1);
  check_addr(p);
  check_page(p);
}

// make check for every function arguments
void check_func_args(void *p, int argc) {
  for(int i = 0; i < argc; i++) {
    check(p);
    p++;
  }
}

<<<<<<< HEAD
// search the file list of the thread_current()
// to get the file has corresponding fd
struct file_node * find_file(struct list *files, int fd){
  struct list_elem *e;
  struct file_node * fn =NULL;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    fn = list_entry (e, struct file_node, file_elem);
    if (fd == fn->fd)
      return fn;
  }
  return NULL;
=======
void IExit(struct intr_frame* f)
{
  int status = *((int*)f->esp + 1);
  // if (status<0 && status !=-1)
  // {
  //   status=-1;
  // }
  
  // thread_current()->exit_error_code=status;
  // thread_current()->parent->exit = 1;
  // thread_exit();
  killthread(status);


    int * p = f->esp;
  		check_addr(p+1);
		exit_proc(*(p+1));
  // exit_proc(status);
  // exit(status);
  // printf("syscall not implemented yet\n");
>>>>>>> 87488076e9e7946cb90d58bf05e81b5d0241b156
}

static void
syscall_handler (struct intr_frame *f)
{
  check((void *)f->esp);
  check((void *)(f->esp + 4));
  int num=*((int *)(f->esp));
  // check whether the function is implemented
  if(num < 0 || num >= SYSCALL_NUMBER) exit(-1);
  if(syscalls[num] == NULL) exit(-1);
  syscalls[num](f);
}

<<<<<<< HEAD
void sys_exit(struct intr_frame * f) {
  int *p = f->esp;
  // save exit status
  exit(*(p + 1));
}

void sys_halt(struct intr_frame * f UNUSED) {
  shutdown_power_off();
}

void sys_exec(struct intr_frame * f) {
  int * p =f->esp;
  check((void *)(p + 1));
  check((void *)(*(p + 1)));
  f->eax = process_execute((char*)*(p + 1));
=======
void IWait(struct intr_frame* f)
{
  tid_t pid = *((int*)f->esp + 1);
  f->eax = process_wait(pid);
  

  // f->eax = wait(pid);
  // printf("syscall not implemented yet\n");
}

void ICreate(struct intr_frame* f)
{
  char *file = (char*)(*((int*)f->esp + 1));
  unsigned initial_size = *((unsigned*)f->esp + 2);
      if (file==NULL)
      {

        		// exit_proc(-1);
            killthread(-1);
      }
  		acquire_filesys_lock();

      
		f->eax = filesys_create(file,initial_size);
		release_filesys_lock();
  // f->eax = create(file, initial_size);
  // printf("syscall not implemented yet\n");
>>>>>>> 87488076e9e7946cb90d58bf05e81b5d0241b156
}

void sys_wait(struct intr_frame * f) {
  int * p =f->esp;
  check(p + 1);
  f->eax = process_wait(*(p + 1));
}

<<<<<<< HEAD
void sys_create(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 2);
  check((void *)*(p + 1));

  acquire_file_lock();
  // thread_exit ();
  f->eax = filesys_create((const char *)*(p + 1),*(p + 2));
  release_file_lock();
}
=======
void IOpen(struct intr_frame* f)
{
  char *file = (char*)(*((int*)f->esp + 1));
        if (file==NULL)
      {
        		// exit_proc(-1);
            killthread(-1);
      }
  acquire_filesys_lock();
  struct file* fptr = filesys_open(file);
  release_filesys_lock();
		if(fptr==NULL)
			f->eax = -1;
		else
		{
			struct proc_file *pfile = malloc(sizeof(*pfile));
			pfile->ptr = fptr;
			pfile->fd = thread_current()->fd_count;
			thread_current()->fd_count++;
			list_push_back (&thread_current()->files, &pfile->elem);
			f->eax = pfile->fd;
>>>>>>> 87488076e9e7946cb90d58bf05e81b5d0241b156

void sys_remove(struct intr_frame * f) {
  int * p =f->esp;
  
  check_func_args((void *)(p + 1), 1);
  check((void*)*(p + 1));

  acquire_file_lock();
  f->eax = filesys_remove((const char *)*(p + 1));
  release_file_lock();
}

void sys_open(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 1);
  check((void*)*(p + 1));

  struct thread * t = thread_current();
  acquire_file_lock();
  struct file * open_f = filesys_open((const char *)*(p + 1));
  release_file_lock();
  // check whether the open file is valid
  if(open_f){
    struct file_node *fn = malloc(sizeof(struct file_node));
    fn->fd = t->max_fd++;
    fn->file = open_f;
    // put in file list of the corresponding thread
    list_push_back(&t->files, &fn->file_elem);
    f->eax = fn->fd;
  } else
    f->eax = -1;
}

void sys_filesize(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 1);
  struct file_node * open_f = find_file(&thread_current()->files, *(p + 1));
  // check whether the write file is valid
  if (open_f){
    acquire_file_lock();
    f->eax = file_length(open_f->file);
    release_file_lock();
  } else
    f->eax = -1;
}

<<<<<<< HEAD
void sys_read(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 3);
  check((void *)*(p + 2));

  int fd = *(p + 1);
  uint8_t * buffer = (uint8_t*)*(p + 2);
  off_t size = *(p + 3);  
  // read from standard input
  if (fd == 0) {
    for (int i=0; i<size; i++)
      buffer[i] = input_getc();
    f->eax = size;
  }
  else{
    struct file_node * open_f = find_file(&thread_current()->files, *(p + 1));
    // check whether the read file is valid
    if (open_f){
      acquire_file_lock();
      f->eax = file_read(open_f->file, buffer, size);
      release_file_lock();
    } else
      f->eax = -1;
  }
}

void sys_write(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 3);
  check((void *)*(p + 2));
  int fd2 = *(p + 1);
  const char * buffer2 = (const char *)*(p + 2);
  off_t size2 = *(p + 3);
  // write to standard output
  if (fd2==1) {
    putbuf(buffer2,size2);
    f->eax = size2;
  }
  else{
    struct file_node * openf = find_file(&thread_current()->files, *(p + 1));
    // check whether the write file is valid
    if (openf){
      acquire_file_lock();
      f->eax = file_write(openf->file, buffer2, size2);
      release_file_lock();
    } else
      f->eax = 0;
  }
}

void sys_seek(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 2);
  struct file_node * openf = find_file(&thread_current()->files, *(p + 1));
  if (openf){
    acquire_file_lock();
    file_seek(openf->file, *(p + 2));
    release_file_lock();
  }
}
=======
void IWrite(struct intr_frame *f)
{

  int fd = *((int*)f->esp + 1);
  void* buffer = (void*)(*((int*)f->esp + 2));
  unsigned size = *((unsigned*)f->esp + 3);
 		if(fd==1)
		{
			putbuf( buffer,size);
      f->eax = (size);
		}
    else
		{
			struct proc_file* fptr = list_search(&thread_current()->files, fd);
			if(fptr==NULL)
				f->eax=-1;
			else
        // acquire_filesys_lock();
				f->eax = file_write_at (fptr->ptr, buffer, size ,0);
        // release_filesys_lock();

		}
    

}
void ISeek(struct intr_frame* f)
{
  int fd = *((int*)f->esp + 1);
  unsigned position = *((unsigned*)f->esp + 2);
    acquire_filesys_lock();
    // p+4???
		// file_seek(list_search(&thread_current()->files, *(p+4))->ptr,fd);
		file_seek(list_search(&thread_current()->files, fd)->ptr,fd);
		release_filesys_lock();
  // seek(fd, position);
  // printf("syscall not implemented yet\n");
}
void ITell(struct intr_frame* f)
{
  int fd = *((int*)f->esp + 1);
  // printf("syscall not implemented yet\n");
  // f->eax = tell(fd);
    acquire_filesys_lock();
		f->eax = file_tell(list_search(&thread_current()->files, fd)->ptr);
		release_filesys_lock();
} 
void IClose(struct intr_frame* f)
{
  int fd = *((int*)f->esp + 1);
  	// 	acquire_filesys_lock();
		// close_file(&thread_current()->files,fd);
		// release_filesys_lock();
  // close(fd);  
  // printf("syscall not implemented yet\n");
}


int exec_proc(char *file_name)
{
	acquire_filesys_lock();
	char * fn_cp = malloc (strlen(file_name)+1);
	  strlcpy(fn_cp, file_name, strlen(file_name)+1);
	  
	  char * save_ptr;
	  fn_cp = strtok_r(fn_cp," ",&save_ptr);

	 struct file* f = filesys_open (fn_cp);

	  if(f==NULL)
	  {
	  	release_filesys_lock();
	  	return -1;
	  }
	  else
	  {
	  	file_close(f);
	  	release_filesys_lock();
	  	return process_execute(file_name);
	  }
}


void exit_proc(int status)
{
	//printf("Exit : %s %d %d\n",thread_current()->name, thread_current()->tid, status);
	struct list_elem *e;

      for (e = list_begin (&thread_current()->parent->child_proc); e != list_end (&thread_current()->parent->child_proc);
           e = list_next (e))
        {
          struct child *f = list_entry (e, struct child, elem);
          if(f->tid == thread_current()->tid)
          {
          	f->used = true;
          	f->exit_error = status;
          }
        }


	thread_current()->exit_error_code = status;

	if(thread_current()->parent->waitingon == thread_current()->tid)
		sema_up(&thread_current()->parent->child_lock);

	thread_exit();
}




void* check_addr(const void *vaddr)
{
	if (!is_user_vaddr(vaddr))
	{
		exit_proc(-1);
		return 0;
	}
	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	if (!ptr)
	{
		exit_proc(-1);
		return 0;
	}
	return ptr;
}

struct proc_file* list_search(struct list* files, int fd)
{
>>>>>>> 87488076e9e7946cb90d58bf05e81b5d0241b156

void sys_tell(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 1);
  struct file_node * open_f = find_file(&thread_current()->files, *(p + 1));
  // check whether the tell file is valid
  if (open_f){
    acquire_file_lock();
    f->eax = file_tell(open_f->file);
    release_file_lock();
  }else
    f->eax = -1;
}

<<<<<<< HEAD
void sys_close(struct intr_frame * f) {
  int *p = f->esp;
  check_func_args((void *)(p + 1), 1);
  struct file_node * openf = find_file(&thread_current()->files, *(p + 1));
  if (openf){
    acquire_file_lock();
    file_close(openf->file);
    release_file_lock();
    // remove file form file list
    list_remove(&openf->file_elem);
    free(openf);
  }
}
=======
void close_file(struct list* files, int fd)
{

	struct list_elem *e;

	struct proc_file *f;

      for (e = list_begin (files); e != list_end (files);
           e = list_next (e))
        {
          f = list_entry (e, struct proc_file, elem);
          if(f->fd == fd)
          {
          	file_close(f->ptr);
          	list_remove(e);
          }
        }

    free(f);
}

void close_all_files(struct list* files)
{

	struct list_elem *e;

	while(!list_empty(files))
	{
		e = list_pop_front(files);

		struct proc_file *f = list_entry (e, struct proc_file, elem);
          
	      	file_close(f->ptr);
	      	list_remove(e);
	      	free(f);
	}
}
>>>>>>> 87488076e9e7946cb90d58bf05e81b5d0241b156

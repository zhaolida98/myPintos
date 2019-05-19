#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
// #include "sys_syscall.h"
#include "pagedir.h"
#include "lib/syscall-nr.h"

#include "list.h"
#include "process.h"


#define ALLCALL 20//there are 20 in total

static void syscall_handler (struct intr_frame *);
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


struct proc_file {
	struct file* ptr;
	int fd;
	struct list_elem elem;
};
//TODO 看清f->eax 的面目，是否是指针，返回值是否需要处理
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  for (size_t i = 0; i < ALLCALL; i++)
  {
    syscall_list[i] = NULL;
  }
  syscall_list[SYS_WRITE] = IWrite;
  syscall_list[SYS_EXIT] = IExit;
  syscall_list[SYS_EXEC] = IExec;
  syscall_list[SYS_WAIT] = IWait;
  syscall_list[SYS_CREATE] = ICreate;
  syscall_list[SYS_REMOVE] = IRemove;
  syscall_list[SYS_OPEN] = IOpen;
  syscall_list[SYS_FILESIZE] = IFilesize;
  syscall_list[SYS_READ] = IRead;
  syscall_list[SYS_WRITE] = IWrite;
  syscall_list[SYS_SEEK] = ISeek;
  syscall_list[SYS_TELL] = ITell;
  syscall_list[SYS_CLOSE] = IClose;
  syscall_list[SYS_HALT] = IHalt;
  /*project 3 or 4*/
  // syscall_list[SYS_MMAP] = IMmap;
  // syscall_list[SYS_MUNMAP] = IMunmap;
  // syscall_list[SYS_CHDIR] = IChdir;
  // syscall_list[SYS_MKDIR] = IMkdir;
  // syscall_list[SYS_READDIR] = IReaddir;
  // syscall_list[SYS_ISDIR] = IIsdir;
  // syscall_list[SYS_INUMBER] = IInuber;

}

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
}
// // TODO is_ptr_valid 方法十分简陋，未考虑完全
static void
syscall_handler (struct intr_frame *f) 
{
  // hex_dump((uintptr_t)f->esp, f->esp, (int)PHYS_BASE - (int)(f->esp), 1);

  // int sys_code = *(int*)f->esp;
  if(!is_ptr_valid(f->esp))
  {
    killthread(-1);
  }
  int sys_code=*(int *)f->esp;

  if(sys_code >= ALLCALL || sys_code < 0)
  {
    printf("No such syscall!\n");
    killthread(-1);
  }
  if(syscall_list[sys_code] == NULL)
  {
    printf("syscall %d not implemented yet\n", sys_code);
    killthread(-1);
  }
  /* every thing looks fine, invoke the syscall*/
  // printf ("\nsystem call: %d\n", sys_code);
  syscall_list[sys_code](f);
  // killthread(-1);
}

void IHalt(struct intr_frame* f UNUSED)
{
  shutdown_power_off();
}

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
}

void IExec(struct intr_frame* f)
{
  char *file = (char*)(*((int*)f->esp + 1));

  f->eax = exec_proc(file);


  // f->eax = exec(file);
  // printf("syscall not implemented yet\n");
}

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
}

void IRemove(struct intr_frame* f)
{
  char *file = (char*)(*((int*)f->esp + 1));
  		acquire_filesys_lock();
		if(filesys_remove(file)==NULL)
			f->eax = false;
		else
			f->eax = true;
		release_filesys_lock();
  // f->eax = remove(file);
  // printf("syscall not implemented yet\n");
}

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

		}

  // f->eax = open(file);
  // printf("syscall not implemented yet\n");
}

void IFilesize(struct intr_frame* f)
{
  int fd = *((int*)f->esp + 1);
  acquire_filesys_lock();
  f->eax = file_length (list_search(&thread_current()->files, fd)->ptr);
  release_filesys_lock();
  // f->eax = filesize(fd);
  // printf("syscall not implemented yet\n");
}

void IRead(struct intr_frame* f)
{
  int fd = *((int*)f->esp + 1);
  uint8_t* buffer = (uint8_t*)(*((int*)f->esp + 2));
  unsigned size = *((unsigned*)f->esp + 3);

  		if(fd==0)
		{
			int i;
			for(i=0;i<size;i++)
				buffer[i] = input_getc();
			f->eax = size;
		}
		else
		{
			struct proc_file* fptr = list_search(&thread_current()->files, fd);
			if(fptr==NULL)
				f->eax=-1;
			else
			{
				acquire_filesys_lock();
				f->eax = file_read (fptr->ptr, buffer, size);
				release_filesys_lock();
			}
		}
  // f->eax = read(fd, buffer, size); 
  // printf("syscall not implemented yet\n");
}

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

 	struct list_elem *e;

       for (e = list_begin (files); e != list_end (files);
           e = list_next (e))
        {
          struct proc_file *f = list_entry (e, struct proc_file, elem);
          if(f->fd == fd)
          	return f;
        }
   return NULL;
}

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
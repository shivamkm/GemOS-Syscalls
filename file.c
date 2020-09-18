// SHIVAM KUMAR     ROLL NO. 170669

#include <context.h>
#include <entry.h>
#include <file.h>
#include <fs.h>
#include <kbd.h>
#include <lib.h>
#include <memory.h>
#include <pipe.h>
#include <serial.h>
#include <types.h>
/************************************************************************************/
/***************************Do Not Modify below
 * Functions****************************/
/************************************************************************************/
void free_file_object(struct file *filep) {
        if (filep) {
                os_page_free(OS_DS_REG, filep);
                stats->file_objects--;
        }
}

struct file *alloc_file() {
        struct file *file = (struct file *)os_page_alloc(OS_DS_REG);
        file->fops = (struct fileops *)(file + sizeof(struct file));
        bzero((char *)file->fops, sizeof(struct fileops));
        stats->file_objects++;
        return file;
}

static int do_read_kbd(struct file *filep, char *buff, u32 count) {
        kbd_read(buff);
        return 1;
}

static int do_write_console(struct file *filep, char *buff, u32 count) {
        struct exec_context *current = get_current_ctx();
        return do_write(current, (u64)buff, (u64)count);
}

struct file *create_standard_IO(int type) {
        struct file *filep = alloc_file();
        filep->type = type;
        if (type == STDIN)
                filep->mode = O_READ;
        else
                filep->mode = O_WRITE;
        if (type == STDIN) {
                filep->fops->read = do_read_kbd;
        } else {
                filep->fops->write = do_write_console;
        }
        filep->fops->close = generic_close;
        return filep;
}

int open_standard_IO(struct exec_context *ctx, int type) {
        int fd = type;
        struct file *filep = ctx->files[type];
        if (!filep) {
                filep = create_standard_IO(type);
        } else {
                filep->ref_count++;
                fd = 3;
                while (ctx->files[fd]) fd++;
        }
        ctx->files[fd] = filep;
        return fd;
}
/**********************************************************************************/
/**********************************************************************************/
/**********************************************************************************/
/**********************************************************************************/

void do_file_fork(struct exec_context *child) {
        /*TODO the child fds are a copy of the parent. Adjust the refcount*/
        // if(child == NULL) return -EINVAL;
        int fd = 3;
        while (fd < MAX_OPEN_FILES) {
                if (child->files[fd])
                        (child->files[fd])->ref_count++;  // Increasing refcount
                                                          // of each file object
                                                          // shared with the
                                                          // parent.
                fd++;
        }
}

void do_file_exit(struct exec_context *ctx) {
        /*TODO the process is exiting. Adjust the ref_count
         of files*/
        // if(ctx == NULL) return -EINVAL;
        int fd = 3;
        struct file *filep;
        while (fd < MAX_OPEN_FILES) {
                if (filep = ctx->files[fd]) {
                        filep->ref_count--;
                        if (!filep->ref_count) {
                                if (filep->type == REGULAR)
                                        free_file_object(filep);
                                else if (filep->type == PIPE) {
                                        free_pipe_info(filep->pipe);
                                        free_file_object(filep);
                                }
                        }
                }
                fd++;
        }
}

long generic_close(struct file *filep) {
        /** TODO Implementation of close (pipe, file) based on the type
         * Adjust the ref_count, free file object
         * Incase of Error return valid Error code
         */
        if (filep == NULL) return -EINVAL;
        if (filep->type == REGULAR) {  // Closing regular file
                filep->ref_count--;
                if (!filep->ref_count) free_file_object(filep);
        } else if (filep->type == PIPE) {  // Closing Pipe
                filep->ref_count--;
                if (!filep->ref_count) {  // Freeing file and pipe object if
                                          // ref_count becomes zero.
                        free_pipe_info(filep->pipe);
                        free_file_object(filep);
                }
        }

        return 0;
        int ret_fd = -EINVAL;
        return ret_fd;
}

static int do_read_regular(struct file *filep, char *buff, u32 count) {
        /** TODO Implementation of File Read,
         *  You should be reading the content from File using file system read
         * function call and fill the buf
         *  Validate the permission, file existence, Max length etc
         *  Incase of Error return valid Error code
         * */

        if (filep == NULL || buff == NULL || count < 0 || count > 4096)
                return -EINVAL;
        if (filep->offp + count > filep->inode->file_size)
                return -EINVAL;  // Error if we try to  read more than data file
                                 // has.
        if ((filep->mode & O_READ) != O_READ) return -EACCES;
        int offp = flat_read(filep->inode, buff, count, &(filep->offp));
        filep->offp += offp;
        return offp;
        int ret_fd = -EINVAL;
        return ret_fd;
}

static int do_write_regular(struct file *filep, char *buff, u32 count) {
        /** TODO Implementation of File write,
         *   You should be writing the content from buff to File by using File
         * system write function
         *   Validate the permission, file existence, Max length etc
         *   Incase of Error return valid Error code
         * */
        if (filep == NULL || buff == NULL || count < 0 || count > 4096)
                return -EINVAL;
        if (count + filep->offp > (filep->inode->e_pos - filep->inode->s_pos))
                return -EINVAL;
        if ((filep->mode & O_WRITE) != O_WRITE) return -EACCES;
        int offp = flat_write(filep->inode, buff, count, &(filep->offp));
        filep->offp += offp;
        return offp;
        int ret_fd = -EINVAL;
        return ret_fd;
}

static long do_lseek_regular(struct file *filep, long offset, int whence) {
        /** TODO Implementation of lseek
         *   Set, Adjust the ofset based on the whence
         *   Incase of Error return valid Error code
         * */
        if (filep == NULL ||
            (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END))
                return -EINVAL;
        int offp = filep->offp;
        if (whence == SEEK_SET) offp = offset;
        if (whence == SEEK_CUR) offp = offp + offset;
        if (whence == SEEK_END) offp = filep->inode->file_size + offset;
        if ((offp > (filep->inode->e_pos - filep->inode->s_pos)) || offp < 0)
                return -EINVAL;
        filep->offp = offp;
        return offp;
        int ret_fd = -EINVAL;
        return ret_fd;
}

extern int do_regular_file_open(struct exec_context *ctx, char *filename,
                                u64 flags, u64 mode) {
        /**  TODO Implementation of file open,
         *  You should be creating file(use the alloc_file function to creat
         * file),
         *  To create or Get inode use File system function calls,
         *  Handle mode and flags
         *  Validate file existence, Max File count is 32, Max Size is 4KB, etc
         *  Incase of Error return valid Error code
         * */
        struct inode *inode = lookup_inode(filename);
        if (inode == NULL) {
                if (flags & O_CREAT == 0) return -EINVAL;
                inode = create_inode(filename, mode);
                if (inode == NULL) return -ENOMEM;
        } else {
                if ((flags & O_CREAT) == O_CREAT) return -EINVAL;
                if (((inode->mode) & (flags & (O_READ | O_WRITE | O_EXEC))) !=
                    (flags & (O_READ | O_WRITE | O_EXEC)))
                        return -EACCES;  // Checking whether flags are in
                                         // compliance with the inode->mode only
                                         // when files exist "apriori" i.e. they
                                         // are not created now.If O_CREAT flag
                                         // is passed and other flags don't
                                         // correspond to the inode->mode, POSIX
                                         // doesn't report any error.
        }

        struct file *myfile = alloc_file();
        if (myfile == NULL) return -ENOMEM;
        myfile->inode = inode;
        myfile->type = REGULAR;
        myfile->offp = 0;
        myfile->pipe = NULL;
        myfile->ref_count = 1;
        myfile->mode = flags & (O_READ | O_WRITE | O_EXEC);

        int fd = 3;
        while (fd < MAX_OPEN_FILES && ctx->files[fd]) fd++;
        if (fd >= MAX_OPEN_FILES) return -EOTHERS;

        ctx->files[fd] = myfile;
        myfile->fops->read = do_read_regular;
        myfile->fops->write = do_write_regular;
        myfile->fops->close = generic_close;
        myfile->fops->lseek = do_lseek_regular;
        return fd;

        int ret_fd = -EINVAL;
        return ret_fd;
}

int fd_dup(struct exec_context *current, int oldfd) {
        /** TODO Implementation of dup
         *  Read the man page of dup and implement accordingly
         *  return the file descriptor,
         *  Incase of Error return valid Error code
         * */
        if (oldfd < 0 || current == NULL || oldfd >= MAX_OPEN_FILES)
                return -EINVAL;
        struct file *file = current->files[oldfd];
        if (file == NULL) return -EINVAL;
        int fd = 3;
        while (fd < MAX_OPEN_FILES && current->files[fd]) fd++;
        if (fd >= MAX_OPEN_FILES) return -EOTHERS;
        current->files[fd] = file;
        file->ref_count++;
        return fd;
        int ret_fd = -EINVAL;
        return ret_fd;
}

int fd_dup2(struct exec_context *current, int oldfd, int newfd) {
        /** TODO Implementation of the dup2
         *  Read the man page of dup2 and implement accordingly
         *  return the file descriptor,
         *  Incase of Error return valid Error code
         * */
        if (current == NULL || oldfd < 0 || newfd < 0 ||
            oldfd >= MAX_OPEN_FILES || newfd >= MAX_OPEN_FILES)
                return -EINVAL;
        struct file *file = current->files[oldfd];
        if (file == NULL) return -EINVAL;
        struct file *oldfile = current->files[newfd];
        if (oldfile) generic_close(oldfile);
        current->files[newfd] = file;
        file->ref_count++;
        return newfd;
        int ret_fd = -EINVAL;
        return ret_fd;
}

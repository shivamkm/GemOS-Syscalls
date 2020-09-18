//SHIVAM KUMAR Roll No. 170669

#include <context.h>
#include <entry.h>
#include <file.h>
#include <file.h>
#include <lib.h>
#include <memory.h>
#include <pipe.h>
/***********************************************************************
 * Use this function to allocate pipe info && Don't Modify below function
 ***********************************************************************/
struct pipe_info *alloc_pipe_info() {
        struct pipe_info *pipe = (struct pipe_info *)os_page_alloc(OS_DS_REG);
        char *buffer = (char *)os_page_alloc(OS_DS_REG);
        pipe->pipe_buff = buffer;
        return pipe;
}

void free_pipe_info(struct pipe_info *p_info) {
        if (p_info) {
                os_page_free(OS_DS_REG, p_info->pipe_buff);
                os_page_free(OS_DS_REG, p_info);
        }
}
/*************************************************************************/
/*************************************************************************/

long pipe_close(struct file *filep) {
        // It is never called as I am calling generic_close for closing pipe as
        // well.
        /**
    * TODO:: Implementation of Close for pipe
    * Free the pipe_info and file object
    * Incase of Error return valid Error code
    */
        //    if(filep == NULL) return -EINVAL;
        //    filep->ref_count--;
        //    if(!filep->ref_count){
        //                free_pipe_info(filep->pipe);
        //                free_file_object(filep);
        //    }
        //    return 0;
        int ret_fd = -EINVAL;
        return ret_fd;
}

int pipe_read(struct file *filep, char *buff, u32 count) {
        /**
        *  TODO:: Implementation of Pipe Read
        *  Read the contect from buff (pipe_info -> pipe_buff) and write to the
        * buff(argument 2);
        *  Validate size of buff, the mode of pipe (pipe_info->mode),etc
        *  Incase of Error return valid Error code
        */
        // return 103;
        // if(filep == NULL) return 404;
        if (filep == NULL || buff == NULL || count < 0 ||
            count > 4096)  // Invalid Input
                return -EINVAL;
        if (count > filep->pipe->buffer_offset)
                return -EINVAL;  // Reading more bytes than pipe has.
        if ((filep->mode & O_READ) != O_READ)
                return -EACCES;  // Invalid access mode

        int i = 0;
        char *pipe_buff = filep->pipe->pipe_buff;
        while (i < count) {
                char c = pipe_buff[filep->pipe->read_pos];
                pipe_buff[filep->pipe->read_pos] = 0;
                filep->pipe->read_pos =
                    (filep->pipe->read_pos + 1) %
                    (4096);  // Cyclically reading data from pipe
                filep->pipe->buffer_offset--;  // Deleting data after read
                buff[i] = c;
                i++;
        }
        return count;
        int ret_fd = -EINVAL;
        return ret_fd;
}

int pipe_write(struct file *filep, char *buff, u32 count) {
        /**
        *  TODO:: Implementation of Pipe Read
        *  Write the contect from   the buff(argument 2);  and write to
        * buff(pipe_info -> pipe_buff)
        *  Validate size of buff, the mode of pipe (pipe_info->mode),etc
        *  Incase of Error return valid Error code
        */
        if (filep == NULL || buff == NULL || count < 0 || count > 4096)
                return -EINVAL;  // Invalid input
        if ((filep->mode & O_WRITE) != O_WRITE) return -EACCES;
        char *pipe_buff = filep->pipe->pipe_buff;
        if (count + filep->pipe->buffer_offset > 4096)
                return -EINVAL;  // Assuming size of pipe buffer is less than 4
                                 // KB, it returns error if we try to write more
                                 // than it.
        int i = 0;
        while (i < count) {
                char c = buff[i];
                pipe_buff[filep->pipe->write_pos] = c;
                filep->pipe->write_pos =
                    (filep->pipe->write_pos + 1) %
                    (4096);  // Cycling writing data in pipe
                filep->pipe->buffer_offset++;
                i++;
        }
        return count;
        int ret_fd = -EINVAL;
        return ret_fd;
}

int create_pipe(struct exec_context *current, int *fd) {
        /**
        *  TODO:: Implementation of Pipe Create
        *  Create file struct by invoking the alloc_file() function,
        *  Create pipe_info struct by invoking the alloc_pipe_info() function
        *  fill the valid file descriptor in *fd param
        *  Incase of Error return valid Error code
        */
        if (fd == NULL || current == NULL) return -EINVAL;
        struct file *file = alloc_file();  // Allocating read input file object
        if (file == NULL) return -ENOMEM;
        file->type = PIPE;
        file->mode = O_READ;
        file->ref_count = 1;
        file->offp = 0;
        file->inode = NULL;
        file->fops->read = pipe_read;
        file->fops->write = pipe_write;
        file->fops->close = generic_close;
        struct file *file1 = alloc_file();  // Allocating write input file
                                            // object
        if (file1 == NULL) return -ENOMEM;
        file1->type = PIPE;
        file1->mode = O_WRITE;
        file1->ref_count = 1;
        file1->offp = 0;
        file1->inode = NULL;
        file1->fops->read = pipe_read;
        file1->fops->write = pipe_write;
        file1->fops->close = generic_close;
        struct pipe_info *pipe =
            alloc_pipe_info();  // Allocating shared pipe buffer
        if (pipe == NULL) return -ENOMEM;
        pipe->read_pos = 0;
        pipe->write_pos = 0;
        pipe->buffer_offset = 0;
        pipe->is_ropen = 0;
        pipe->is_wopen = 0;
        // file->refcount=2;
        file->pipe = pipe;
        file1->pipe = pipe;
        int f = 3;
        while (f < MAX_OPEN_FILES && current->files[f]) f++;
        if (f >= MAX_OPEN_FILES) return -EOTHERS;
        fd[0] = f;
        current->files[f] = file;
        while (f < MAX_OPEN_FILES && current->files[f]) f++;
        if (f >= MAX_OPEN_FILES) return -EOTHERS;
        fd[1] = f;
        current->files[f] = file1;
        return 0;
        int ret_fd = -EINVAL;
        return ret_fd;
}


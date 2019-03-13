/*******************************************************************************
 *
 * log-user-session:
 * - creates a full log of the user session
 *
 * Usage:
 *    log-user-session [command]
 *
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Open Systems AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *
 * Written by Konrad Bucheli (kb@open.ch), January 2014
 *
 *
 * Process Hierarchy
 *
 * sshd -> log-user-session (forward data and merge for log - non-blocking I/O)
 *          \   \
 *           \  |-> bash
 *            \
 *            |-> log-user-session (write log to file - blocking I/O)
 *
 *
 * Data Flow
 *
 * I/O from bash is piped to log-user-session which does I/O to sshd and merges
 * all data and forwards it to another process which is writing the log file.
 * If that second process fails for whatever reason (disk full, etc), the user
 * session still continues without logging.
 *
 *
 * Data Stored
 *
 * For interactive shells we do not store input. Input is echoed by
 * the shell except for passwords and those should not be logged.
 * On non-interactive use first the command to be executed is logged.
 *
 *
 * Data Structure
 *
 * The I/O data is stored in a buffer structure which is in two linked list at the
 * same time: first in the specific I/O channel (stdin, stdout, stderr) and second
 * in a list with all merged I/O to be logged
 *
 *
 * Error Handling
 *
 * If there is a problem,, we print the error on stderr and try to continue with
 * least impact on the user session, even if the session might not be recorded
 * correctly.
 *
 *
 * Login Shell
 *
 * A login shell is only started if log-user-session has been started like a login
 * shell (e.g. because it is configured in /etc/passwd) or if there is no command
 * provided and there is no prompt (PS1 environment variable) defined yet (e.g.
 * started by ForcedCommand via ssh).
 * If it is started on a shell (e.g. for testing purposes) or there is a specific
 * command provided to execute, no login shell should be started.
 *
 *******************************************************************************/

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pty.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/prctl.h>


/* log directory is predefined so that it cannot be change by the user */
#ifndef DEFAULT_LOG_FILE
    #define DEFAULT_LOG_FILE  "/var/log/user-session/%h-%u-%y%m%d-%H%M%S-%c-%p.log"
#endif

#ifndef DEFAULT_SHELL
    #define DEFAULT_SHELL  "/bin/bash"
#endif

#ifndef CONFIG_FILE
    #define CONFIG_FILE       "/etc/log-user-session.conf"
#endif

char *original_command  = NULL;
char *opt_command       = NULL;
char *opt_shell         = NULL;
char *opt_user          = NULL;
char *opt_client        = NULL;
char *opt_logfile       = NULL;
char **opt_argv         = NULL;

int opt_log_remote_command_data = 1;
int opt_log_non_interactive_data = 1;


struct buffer;
struct buffer {
    char data[1024];
    size_t size;
    size_t pos[2];               /* user stream is at index 0 */
    struct buffer *next[2];      /* log stream is at index 1  */
};

struct list {
    struct buffer *head;
    struct buffer *tail;
};

struct fd_pair {
    int write_side;
    int read_side;
};

/* keep the last freed buffer in reserve for the next use */
struct buffer *reserve;

/* window resize signal forwarding */
int original_tty;
int child_tty;


void free_options() {
    if (opt_command) free(opt_command);
    if (opt_shell) free(opt_shell);
    if (opt_user) free(opt_user);
    if (opt_client) free(opt_client);
    if (opt_logfile) free(opt_logfile);
    if (opt_argv) {
        int i;
        for (i = 0; opt_argv[i]; i++) {
            free(opt_argv[i]);
        }
        free(opt_argv);
    }
}

struct buffer *new_buffer() {
    struct buffer *buffer = reserve;
    if (NULL == buffer) {
        buffer = (struct buffer*) malloc(sizeof(struct buffer));
    }
    else {
        reserve = NULL;
    }
    int i;
    for (i = 0; i<=1; i++) {
        buffer->pos[i] = 0;
        buffer->next[i] = NULL;
    }
    buffer->size = 0;

    return buffer;
}

void free_buffer(struct buffer *buffer) {

    if (NULL == reserve) {
        reserve = buffer;
    }
    else {
        free(buffer);
    }
}

struct buffer* next_buffer(struct buffer *buffer, int index) {

    int other = index ? 0 : 1;
    struct buffer* next = buffer;

    if (buffer->pos[index] == buffer->size) {
        next = buffer->next[index];
        /* free buffer if it has been written to other stream too */
        if (buffer->pos[other] == buffer->size) {
            free_buffer(buffer);
        }
    }

    return next;
}

void empty_buffer(struct list *list, int index) {

    struct buffer *buffer = list->head;

    /* consume all buffers */
    while(buffer = next_buffer(buffer, index)) {
        buffer->pos[index] = buffer->size;
    }
    list->head = NULL;
    list->tail = NULL;
}

int read_to_buffer(int fd, struct list *out,  struct list *log) {

    struct buffer *buffer = new_buffer();
    /* read data to buffer */
    ssize_t count = read(fd, &(buffer->data), 1024);

    /* error handling */
    if (count < 0) {
        free_buffer(buffer);
        if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno) {
            return 1; /* try again */
        }
        return 0; /* stop */
    }

     /* stream closed */
    if (0 == count) {
        free_buffer(buffer);
        return 0;
    }

    buffer->size = (size_t) count;

    /* add to output buffer */
    if (NULL == out->head) {
        out->head = buffer;
        out->tail = buffer;
    }
    else {
        out->tail->next[0] = buffer;
        out->tail = buffer;
    }

    /* add to log buffer */
    if (log) {
        if (NULL == log->head) {
            log->head = buffer;
            log->tail = buffer;
        }
        else {
            log->tail->next[1] = buffer;
            log->tail = buffer;
        }
    }
    else {
        /* mark as consumed by log */
        buffer->pos[1] = count;
    }
    return 1;
}

int write_from_buffer(int fd, struct list *list, int log) {

    int index = log ? 1 : 0;

    struct buffer *buffer = list->head;

    /* make sure there is anything to write */
    if (NULL == buffer) return 1;

    size_t pos = buffer->pos[index];
    size_t size = buffer->size;

    ssize_t count = write(fd, buffer->data + pos, size - pos);

    if (count < 0) {
        if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno) {
            return 1; /* try again */
        }
        empty_buffer(list, index);
        return 0;
    }

    /* buffer cleanup */
    buffer->pos[index] = pos + count;
    list->head = next_buffer(buffer, index);
    if (NULL == list->head) list->tail = NULL;
    return 1;
}

void run_log_forwarder(struct fd_pair *internal, struct fd_pair *input, struct fd_pair *output,
                       struct fd_pair *error, int interactive) {

    int i;

    fd_set read_set;
    fd_set write_set;
    struct timeval timeout;

    int stdin_open    = 1;
    int stdout_open   = 1;
    int stderr_open   = 1;
    int internal_open = 1;
    int input_open    = 1;
    int output_open   = 1;
    int error_open    = error ? 1 : 0;

    int max_fd = internal->write_side;
    if (input->write_side > max_fd) max_fd = input->write_side;
    if (output->read_side > max_fd) max_fd = output->read_side;
    if (error_open && error->read_side > max_fd) max_fd = error->read_side;
    max_fd++;

    reserve = NULL;
    struct list internal_buffer = {NULL, NULL};
    struct list input_buffer = {NULL, NULL};
    struct list stdout_buffer = {NULL, NULL};
    struct list stderr_buffer = {NULL, NULL};

    /* non-blocking read/write */
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
    fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(STDERR_FILENO, F_GETFL, 0);
    fcntl(STDERR_FILENO, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(internal->write_side, F_GETFL, 0);
    fcntl(internal->write_side, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(input->write_side, F_GETFL, 0);
    fcntl(input->write_side, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(output->read_side, F_GETFL, 0);
    fcntl(output->read_side, F_SETFL, flags | O_NONBLOCK);
    if (error_open) {
        flags = fcntl(error->read_side, F_GETFL, 0);
        fcntl(error->read_side, F_SETFL, flags | O_NONBLOCK);
    }

    /* as long as there is a parent process and something to read */
    while (getppid() > 1 && (output_open || error_open))  {

        /* prepare read set */
        FD_ZERO(&read_set);
        if (stdin_open)  FD_SET(STDIN_FILENO,      &read_set);
        if (output_open) FD_SET(output->read_side, &read_set);
        if (error_open)  FD_SET(error->read_side,  &read_set);

        /* prepare write set */
        FD_ZERO(&write_set);
        if (internal_buffer.head && internal_open) FD_SET(internal->write_side, &write_set);
        if (input_buffer.head && input_open)       FD_SET(input->write_side,    &write_set);
        if (stdout_buffer.head && stdout_open)     FD_SET(STDOUT_FILENO,        &write_set);
        if (stderr_buffer.head && stderr_open)     FD_SET(STDERR_FILENO,        &write_set);

        /* timeout to avoid hanging processes if PPID changes to 1 between getppid and select */
        timeout.tv_sec = 300;
        timeout.tv_usec = 0;

        /* what to do */
        int result = select(max_fd, &read_set, &write_set, NULL, &timeout);

        /* error handling */
        if (result < 0) {
            if (EINTR == errno) continue;
            perror("select");
            break;
        }
        /* timeout */
        else if (0 == result) {
            continue;
        }

        /* non-blocking write */
        if (FD_ISSET(input->write_side, &write_set)) {
            input_open = write_from_buffer(input->write_side, &input_buffer, 0);
        }
        if (FD_ISSET(STDERR_FILENO, &write_set)) {
            stderr_open = write_from_buffer(STDERR_FILENO, &stderr_buffer, 0);
        }
        if (FD_ISSET(STDOUT_FILENO, &write_set)) {
            stdout_open = write_from_buffer(STDOUT_FILENO, &stdout_buffer, 0);
        }
        if (FD_ISSET(internal->write_side, &write_set)) {
            internal_open = write_from_buffer(internal->write_side, &internal_buffer, 1);
        }

        /* non-blocking read */
        if (FD_ISSET(STDIN_FILENO, &read_set)) {
            stdin_open = read_to_buffer(STDIN_FILENO, &input_buffer,
                                        (internal_open && !interactive) ? &internal_buffer : NULL);
        }
        if (error_open && FD_ISSET(error->read_side, &read_set)) {
            error_open = read_to_buffer(error->read_side, &stderr_buffer,
                                        internal_open ? &internal_buffer : NULL);
        }
        if (FD_ISSET(output->read_side, &read_set)) {
            output_open = read_to_buffer(output->read_side, &stdout_buffer,
                                         internal_open ? &internal_buffer : NULL);
        }

        /* propagate closed input */
        if (!stdin_open && !input_buffer.head && input_open) {
            close(input->write_side);
            input_open = 0;
        }

    }

    /* do we have something left out for writing? (reset to blocking mode before writing) */
    flags = fcntl(STDERR_FILENO, F_GETFL, 0);
    fcntl(STDERR_FILENO, F_SETFL, flags & (~O_NONBLOCK));
    flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
    fcntl(STDOUT_FILENO, F_SETFL, flags & (~O_NONBLOCK));
    flags = fcntl(internal->write_side, F_GETFL, 0);
    fcntl(internal->write_side, F_SETFL, flags & (~O_NONBLOCK));

    while (stderr_buffer.head) {
        write_from_buffer(STDERR_FILENO, &stderr_buffer, 0);
    }
    while (stdout_buffer.head) {
        write_from_buffer(STDOUT_FILENO, &stdout_buffer, 0);
    }
    while (internal_open && internal_buffer.head) {
        internal_open = write_from_buffer(internal->write_side, &internal_buffer, 1);
    }

    /* still some input? Write it out immediately 1:1, but bail out if there was nothing read
       (we seam to get EAGAIN for ever if parent is killed) */
    if (internal_open) {
        while (error_open && read_to_buffer(error->read_side, &stderr_buffer, &internal_buffer)) {
            if (NULL == stderr_buffer.head) break;
            write_from_buffer(STDERR_FILENO, &stderr_buffer, 0);
            write_from_buffer(internal->write_side, &internal_buffer, 1);
        }
        while (read_to_buffer(output->read_side, &stdout_buffer, &internal_buffer)) {
            if (NULL == stdout_buffer.head) break;
            write_from_buffer(STDOUT_FILENO, &stdout_buffer, 0);
            write_from_buffer(internal->write_side, &internal_buffer, 1);
        }
    }
    else {
        while (error_open && read_to_buffer(error->read_side, &stderr_buffer, NULL)) {
            if (NULL == stderr_buffer.head) break;
            write_from_buffer(STDERR_FILENO, &stderr_buffer, 0);
        }
        while (read_to_buffer(output->read_side, &stdout_buffer, NULL)) {
            if (NULL == stdout_buffer.head) break;
            write_from_buffer(STDOUT_FILENO, &stdout_buffer, 0);
        }
    }

    /* final cleanup */
    if (NULL != reserve) {
        free(reserve);
    }
}

void write_log(int fd_input, int fd_log, char *buffer, size_t size) {

    for (;;) {
        ssize_t r_count = read(fd_input, buffer, size);
        if (0 == r_count) return; /* done */
        if (r_count < 0 ) {      /* error handling */
            if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno) {
                continue; /* try again */
            }
            return;
        }
        int pos = 0;
        while(pos < r_count) {
            ssize_t w_count = write(fd_log, buffer + pos, r_count - pos);
            if (0 == w_count) return; /* done!? */
            if (w_count < 0 ) {      /* error handling */
                if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno) {
                    continue; /* try again */
                }
                return;
            }
            pos += w_count;
        }
    }
}

int should_log_data(int interactive, const char *original_command) {
    if (!interactive && !opt_log_non_interactive_data) return 0;
    if (original_command && !opt_log_remote_command_data) return 0;
    return 1;
}

void run_log_writer(int fd_read, int fd_log) {
    char *buffer = (char*) malloc(1024*sizeof(char));
    write_log(fd_read, fd_log, buffer, 1024);
    free(buffer);
}

struct fd_pair new_pipe() {

    int fd[2];
    if (pipe(fd) != 0) perror("creating pipes failed");
    struct fd_pair ret = {fd[1], fd[0]};
    return ret;
}

struct fd_pair clone_pseudo_terminal(int fd_original) {

    struct termios term;
    struct winsize ts;
    int master_fd, slave_fd;

    /* create new pseudo terminal */
    tcgetattr(fd_original, &term);
    ioctl(fd_original, TIOCGWINSZ, &ts);
    openpty(&master_fd, &slave_fd, NULL, &term, &ts);

    struct fd_pair ret = {master_fd, slave_fd};
    return ret;
}

void set_raw_input(int fd, struct termios *old_term) {

    /* put input into raw mode */
    struct termios tnew;
    tcgetattr(STDIN_FILENO, &tnew);

    if (old_term) *old_term = tnew;

    /* Noncanonical mode, disable signals, extended input processing, and echoing */
    tnew.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO);
    /* Disable special handling of CR, NL, and BREAK.
     *       No 8th-bit stripping or parity error handling.
     *       Disable START/STOP output flow control. */
    tnew.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR | INPCK | ISTRIP | IXON | PARMRK);

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tnew);
}

void debug_process_state(const char *hint) {
    fprintf(stderr, "%s: id: %d, session leader: %d, process group leader: %d\n",
            hint, getpid(), getsid(0), getpgid(0));
}

void resize_handler(int signal) {

    if (SIGWINCH == signal) {
        struct winsize ts;
        ioctl(original_tty, TIOCGWINSZ, &ts);
        ioctl(child_tty, TIOCSWINSZ, &ts);
    }
}

void prepare_dir(const char *dir) {

    struct stat st;
    if (0 == stat(dir, &st)) return;

    char* parent = dirname(strdup(dir));
    prepare_dir(parent);
    free(parent);

    if (0 != mkdir(dir, 0700)) perror(dir);
}

void print_config_file_warning(const char *config_file, const char *log_dir) {
    /* print a warning if there is no config file and no directory -- this is the very first startup */

    struct stat st;
    if (0 == stat(log_dir, &st)) return;
    if (0 == stat(config_file, &st)) return;

    fprintf(stderr, "using default configuration\n");
    return;
}

int prepare_log_file(const char *log_file, const char *original_command) {

    char* dir = dirname(strdup(log_file));

    print_config_file_warning(CONFIG_FILE, dir);

    prepare_dir(dir);
    free(dir);

    int fd_log = open(log_file, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR);
    if (fd_log < 0) {
        perror(log_file);
    }
    else {
        if (original_command) {
            size_t s = write(fd_log, original_command, strlen(original_command));
            s = write(fd_log, "\n", 1);
        }
    }
    return fd_log;
}

void start_logger(const char *log_file, const char *original_command, uid_t uid) {

    struct fd_pair input;
    struct fd_pair output[2];
    int output_count;
    int i;
    int has_tty = isatty(STDIN_FILENO);
    int do_log_data = should_log_data(has_tty, original_command);
    pid_t child_pid;


    if (!do_log_data) {
        /* we just log the command in child process and return, no remaining logging process at the end */
        child_pid = fork();
        if (child_pid == 0) {
            int fd_log = prepare_log_file(log_file, original_command);
            if (fd_log < 0) {
                exit(1);
            }
            close(fd_log);
            exit(0);
        }
        return;
    }

    if (has_tty) {
        /* use psedo terminal for communication */
        input = clone_pseudo_terminal(STDIN_FILENO);
        if (uid && fchown(input.read_side, uid, -1) < 0) perror("change owner of tty to user");
        output[0].write_side = dup(input.read_side);
        output[0].read_side =  dup(input.write_side);
        output_count = 1;
    }
    else {
        /* use pipes for communication */
        input = new_pipe();
        output[0] = new_pipe();
        output[1] = new_pipe();
        output_count = 2;
    }

    /* child will return and execute the command */
    child_pid = fork();
    if (child_pid == 0) {
        if (has_tty) {
            /* need to be session leader to be able to set the controlling terminal later on */
            if (setsid() < 0) perror("create new session");

            /* the controlling terminal is required by the shell for job control */
            if (ioctl(input.read_side, TIOCSCTTY, NULL) != 0) perror("set controlling terminal");
        }
        /* parent process runs session and redirects I/O to the pipes or pseudterminal */
        dup2(input.read_side, STDIN_FILENO);
        dup2(output[0].write_side, STDOUT_FILENO);
        dup2(output[output_count-1].write_side, STDERR_FILENO);

        close(input.read_side);
        close(input.write_side);
        for (i = 0; i < output_count; i++) {
            close(output[i].write_side);
            close(output[i].read_side);
        }

        return;
    }
    /* parent will collect and forward the session content */

    close(input.read_side);
    for (i = 0; i < output_count; i++) {
        close(output[i].write_side);
    }

    /* signal handling */
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    /* child will do blocking writes on file */
    struct fd_pair internal = new_pipe();
    if (fork() == 0) {

        close(input.write_side);
        for (i = 0; i < output_count; i++) {
            close(output[i].read_side);
        }
        close(internal.write_side);

        int fd_log = prepare_log_file(log_file, original_command);
        free_options();
        if (fd_log < 0) {
            exit(1);
        }

        /* setup parent-death signal to SIGTERM, this prevents stale log childrens */
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        run_log_writer(internal.read_side, fd_log);

        exit(0);
    }
    free_options();
    close(internal.read_side);

    struct termios original_term;

    if (has_tty) {
        original_tty = dup(STDIN_FILENO); /* trick from bash */
        set_raw_input(original_tty, &original_term);
        child_tty = input.write_side;
        signal(SIGWINCH, resize_handler);
    }

    /* setup parent-death signal to SIGTERM, this prevents stale log childrens */
    prctl(PR_SET_PDEATHSIG, SIGTERM);

    /* do the logging */
    run_log_forwarder(&internal, &input, output,
                      2 == output_count ? output + 1 : NULL,
                      has_tty
                     );

    /* reset terminal */
    if (has_tty) {
        if (tcsetattr(original_tty, TCSAFLUSH, &original_term) != 0) {
            perror("reseting terminal");
        }
    }

    /* forward exit value of child -- if there is still anyone that might be interested */
    if (getppid() > 1) {
        int status;
        waitpid(child_pid, &status, 0);
        exit(WEXITSTATUS(status));
    }
    exit(0);
}

void debug_uid(const char *hint) {
    fprintf(stderr, "%s: ruid=%d, euid=%d\n", hint, getuid(), geteuid());
}


char *prepare_log_file_name(const char *template) {

    time_t current_time = time(NULL);
    struct tm local_time;
    localtime_r(&current_time, &local_time);
    local_time.tm_mon++;
    local_time.tm_year += 1900;

    size_t len = strlen(template);
    char *logfile = NULL;


    for(;;) {
        /* if we were too small, we just try again bigger */
        len += 100;
        if (logfile) free(logfile);
        logfile = (char*) malloc(len * sizeof(char));

        const char *pos_t = template;
        char *pos_l = logfile;

        for (;;) {
            /* check if there is still some space left over */
            int remaining = len - (pos_l - logfile);
            if (0 >= remaining) break;

            if ('%' == *pos_t) {
                pos_t++;
                /* add just one % sign */
                if ('%' == *pos_t) {
                    *pos_l = *pos_t;
                    pos_l++;
                }
                /* add user name */
                else if ('u' == *pos_t) {
                    int r = snprintf(pos_l, remaining, "%s", opt_user);
                    if (r >= remaining) break;
                    while('\0' != *pos_l) pos_l++;
                }
                /* add client host */
                else if ('c' == *pos_t) {
                    if (opt_client) {
                        int r = snprintf(pos_l, remaining, "%s", opt_client);
                        if (r >= remaining) break;
                        while('\0' != *pos_l) pos_l++;
                    }
                }
                /* add hostname */
                else if ('h' == *pos_t) {
                    int r = gethostname(pos_l, remaining);
                    if (r < 0 && ENAMETOOLONG == errno) break;
                    while(*pos_l != '\0') pos_l++;
                }
                /* add process ID */
                else if ('p' == *pos_t) {
                    int r = snprintf(pos_l, remaining, "%d", (int) getpid());
                    if (r >= remaining) break;
                    while('\0' != *pos_l) pos_l++;
                }
                /* add unix timestamp */
                else if ('s' == *pos_t) {
                    int r = snprintf(pos_l, remaining, "%lld", (long long)current_time);
                    if (r >= remaining) break;
                    while('\0' != *pos_l) pos_l++;
                }
                /* add year */
                else if ('y' == *pos_t) {
                    int r = snprintf(pos_l, remaining, "%d", (int)local_time.tm_year);
                    if (r >= remaining) break;
                    while('\0' != *pos_l) pos_l++;
                }
                /* add month */
                else if ('m' == *pos_t) {
                    int r = snprintf(pos_l, remaining, "%02d", (int)local_time.tm_mon);
                    if (r >= remaining) break;
                    while('\0' != *pos_l) pos_l++;
                }
                /* add day of month */
                else if ('d' == *pos_t) {
                    int r = snprintf(pos_l, remaining, "%02d", (int)local_time.tm_mday);
                    if (r >= remaining) break;
                    while('\0' != *pos_l) pos_l++;
                }
                /* add hour */
                else if ('H' == *pos_t) {
                    int r = snprintf(pos_l, remaining, "%02d", (int)local_time.tm_hour);
                    if (r >= remaining) break;
                    while('\0' != *pos_l) pos_l++;
                }
                /* add minute */
                else if ('M' == *pos_t) {
                    int r = snprintf(pos_l, remaining, "%02d", (int)local_time.tm_min);
                    if (r >= remaining) break;
                    while('\0' != *pos_l) pos_l++;
                }
                /* add second */
                else if ('S' == *pos_t) {
                    int r = snprintf(pos_l, remaining, "%02d", (int)local_time.tm_sec);
                    if (r >= remaining) break;
                    while('\0' != *pos_l) pos_l++;
                }
            }
            else {
                /* everything else */
                *pos_l = *pos_t;
                if ('\0' == *pos_l) {
                    return logfile;
                }
                pos_l++;
            }
            pos_t++;
        }
    }
}

void parse_configuration_option(const char *start, const char *end) {

    /* look for "text = text " */

    /* trim whitespaces at the end */
    while(isspace(*end)) {
        end--;
    }

    /* find equal sign */
    char *equal = strchrnul(start, '=');

    if (equal < end) {

        /* extract option name */
        char *option_end = equal - 1;
        while(isspace(*option_end)) {
            option_end--;
        }

        /* extract value */
        char *value_start = equal + 1;
        while(isspace(*value_start)) {
            value_start++;
        }

        /* check options*/
        size_t len = strlen("LogFile");
        if (len == option_end - start + 1 && 0 == strncasecmp("LogFile", start, len)) {
            char *path_template = strndup(value_start, end - value_start + 1);
            if (opt_logfile) free(opt_logfile);
            opt_logfile = prepare_log_file_name(path_template);
            free(path_template);
            return;
        }

        len = strlen("LogRemoteCommandData");
        if (len == option_end - start + 1 && 0 == strncasecmp("LogRemoteCommandData", start, len)) {
            if (value_start == end) {
                if ('1' == *value_start) {
                    opt_log_remote_command_data = 1;
                    return;
                }
                else if ('0' == *value_start) {
                    opt_log_remote_command_data = 0;
                    return;
                }
            }
        }

        len = strlen("LogNonInteractiveData");
        if (len == option_end - start + 1 && 0 == strncasecmp("LogNonInteractiveData", start, len)) {
            if (value_start == end) {
                if ('1' == *value_start) {
                    opt_log_non_interactive_data = 1;
                    return;
                }
                else if ('0' == *value_start) {
                    opt_log_non_interactive_data = 0;
                    return;
                }
            }
        }

    }

    /* Noop */
    fprintf(stderr,"error while parsing configuration file %s:\n", CONFIG_FILE);
    fwrite(start, sizeof(char), end - start + 1, stderr);
    fprintf(stderr,"\n");
    return;


}

void read_configuration_file() {

    /* read all file content */
    struct stat st;
    if (0 != stat(CONFIG_FILE, &st)) {
        return;
    }
    size_t filesize = (size_t)st.st_size;

    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) {
        perror(CONFIG_FILE);
        fprintf(stderr, "using default configuration\n");
        return;
    }

    char *data = (char*) malloc(filesize + 1);
    size_t s = fread(data, 1, filesize, f);
    if (0 == s) {
        if (ferror(f)) {
            perror(CONFIG_FILE);
            fprintf(stderr, "using default configuration\n");
        }
        free(data);
        return;
    }
    data[filesize] = '\0';

    fclose(f);

    /* parse it */
    char *pos = data;
    do {
        /* comments */
        if ('#' == *pos) {
            pos = strchrnul(pos, '\n');
        }
        /* parse config option */
        else if (!isspace(*pos)) {
            char *end = strchrnul(pos, '\n');
            parse_configuration_option(pos, end);
            pos = end;
        }
        else {
            pos++;
        }
    } while (*pos != '\0');

    free(data);
}



void process_options(int argc, char **argv) {

    /* get command to execute */
    if (argc > 1) {
        int len = argc; /* enough space for whitespaces and null byte */
        int i;
        for (i = 1; i < argc; i++) {
            len += strlen(argv[i]);
        }
        opt_command = (char *) malloc(len * sizeof(char));
        opt_command[0] = '\0';
        char *pos = opt_command;
        for (i = optind; i < argc; i++) {
            strcat(opt_command, argv[i]);
            strcat(opt_command, " ");
        }
        opt_command[strlen(opt_command) - 1] = '\0';
    }

    /* remote command? */
    original_command = getenv("SSH_ORIGINAL_COMMAND");
    if (original_command && 0 == strcmp("(null)",original_command)) {
        original_command = NULL;
    }

    /* get user name and shell */
    uid_t uid = getuid();
    struct passwd *user = getpwuid(uid);

    if (NULL != user) {
        if (NULL != user->pw_name) {
            opt_user = strdup(user->pw_name);
        }
        else {
            fprintf(stderr, "reading user name failed\n");
        }
        if (NULL != user->pw_shell) {
            opt_shell = strdup(user->pw_shell);
        }
        else {
            fprintf(stderr, "reading user shell failed\n");
        }
    }
    else {
        fprintf(stderr, "reading user information failed\n");
    }
    if (!opt_shell) {
        opt_shell = strdup(DEFAULT_SHELL);
    }

    /* client host */
    char *ssh_client = getenv("SSH_CLIENT");
    if (ssh_client && 0 != strcmp("(null)",ssh_client)) {
        int i;
        for (i = 0; ssh_client[i] && !isspace(ssh_client[i]); i++);
        opt_client = strndup(ssh_client, i);
    }

    /* configured options */
    read_configuration_file();

    if (!opt_logfile) {
        opt_logfile = prepare_log_file_name(DEFAULT_LOG_FILE);
    }

    /* prepare ARGV to execute */

    /* run (command line option/original ssh) command */
    char * command = opt_command ? opt_command : original_command ? original_command : NULL;

    /* have we been started like a login shell? */
    int login_shell = 0;
    if (argv && argv[0] && '-' == *argv[0]) {
        login_shell = 1;
    }
    else {
        if (!command) {
            char *prompt = getenv("PS1");
            if (!prompt || *prompt == '\0') {
                login_shell = 1;
            }
        }
    }

    opt_argv = (char**) malloc((command ? 4 : 2) * sizeof(char*));

    if (login_shell) {
        opt_argv[0] = (char*) malloc((strlen(opt_shell) + 2) * sizeof(char));
        opt_argv[0][0] = '-';
        strcpy(&(opt_argv[0][1]), opt_shell);
    }
    else {
        opt_argv[0] = strdup(opt_shell);
    }

    if (command) {
        opt_argv[1] = strdup("-c");
        opt_argv[2] = strdup(command);
        opt_argv[3] = NULL;
    }
    else {
        opt_argv[1] = NULL;
    }

}



int main(int argc, char **argv) {

    process_options(argc, argv);

    /* setuid */
    uid_t uid = getuid();
    if (uid && setreuid(0, 0) < 0) {
        perror("could not change to root");
    }

    /* fork logger */
    start_logger(opt_logfile, original_command, uid);

    /* back to original user */
    if (uid && setuid(uid) < 0) {
        perror("could not change back to user");
        /* here we cannot continue if there is an error as we did not manage to drop priviledges */
        return 1;
    }

    execv(opt_shell, opt_argv);

    perror("executing shell");
    free_options();
    return 1;
}

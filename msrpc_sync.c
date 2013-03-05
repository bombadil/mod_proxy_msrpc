/**************************************************************************
 *  Copyright (C) 2013 Astaro GmbH & Co. KG  -- a Sophos company
 *  Astaro GmbH & Co. KG licenses this file to You under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  Author: Micha Lenk <micha@lenk.info>  --  2013-03-05
 *
 ***************************************************************************/

#include "msrpc_sync.h"
#include <sys/inotify.h>
#include <string.h>
#include <assert.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#ifdef DEBUG_MSRPC_FIFO
#include <stdio.h>
#endif

#define EVENT_SIZE ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN ( 100 * ( EVENT_SIZE + 16 ) )

int8_t msrpc_sync_wait(const char *key, int timeout)
{
    int sync_fd = open(key, O_RDONLY | O_CLOEXEC);
    if (sync_fd < 0) {
        if (errno == ENOENT) {
            // wait until the file is created, or a timeout happens
            int inotify_fd = inotify_init1(IN_CLOEXEC);
            if (inotify_fd < 0) {
                #ifdef DEBUG_MSRPC_FIFO
                printf("inotify_init1() failed: %m\n");
                #endif
                return -1;
            }

            // trim key to directory name
            char key_dir[PATH_MAX];
            strncpy(key_dir, key, PATH_MAX);
            key_dir[PATH_MAX-1] = 0; // safeguard against overly large key
            char *slash = strrchr(key_dir, '/');
            assert(slash != NULL);
            *slash = 0;
            // get pure filename without directory
            const char *key_without_dir = slash + 1;

            // wait until the file is created and closed after writing
            int watch_fd = inotify_add_watch(inotify_fd, key_dir, IN_CLOSE_WRITE);
            if (watch_fd < 0) {
                int inotify_errno = errno;
                close(inotify_fd);
                errno = inotify_errno;
                #ifdef DEBUG_MSRPC_FIFO
                printf("inotify_add_watch() failed: %m\n");
                #endif
                return -1;
            }

            fd_set wait_fds;
            FD_ZERO(&wait_fds);
            FD_SET(inotify_fd, &wait_fds);

            struct timeval remaining;
            remaining.tv_sec = timeout / 1000;
            remaining.tv_usec = (timeout % 1000) * 1000;

            int rv;
            do {
                rv = select(inotify_fd + 1, &wait_fds, NULL, NULL, &remaining);
                if (rv < 0) {
                    #ifdef DEBUG_MSRPC_FIFO
                    printf("select() failed: %m\n");
                    #endif
                    if (errno == EINTR) {
                        continue;
                    }
                    break;
                } else if (rv == 0) {
                    close(inotify_fd);
                    errno = ETIMEDOUT;
                    return -1;
                } else if (rv > 0) {
                    char event_buf[EVENT_BUF_LEN];
                    int bytes = read(inotify_fd, event_buf, EVENT_BUF_LEN);
                    if (bytes < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        #ifdef DEBUG_MSRPC_FIFO
                        printf("read on inotify fd failed: %m\n");
                        #endif
                        rv = -1;
                        break;
                    }
                    int offset = 0;
                    while (offset < bytes) {
                        struct inotify_event *ie = (struct inotify_event *)&event_buf[offset];
                        if ((ie->wd == watch_fd) && (ie->mask & IN_CLOSE_WRITE)) {
                            #ifdef DEBUG_MSRPC_FIFO
                            printf("Got event for file '%s'\n", ie->name);
                            #endif
                            if (!strcmp(ie->name, key_without_dir)) {
                                #ifdef DEBUG_MSRPC_FIFO
                                printf("Got a match!\n");
                                #endif
                                sync_fd = open(key, O_RDONLY | O_CLOEXEC);
                                if (sync_fd < 0) {
                                    rv = -1;
                                    break;
                                }
                            }
                        #ifdef DEBUG_MSRPC_FIFO
                        } else {
                            printf("Got something else\n");
                        #endif
                        }
                        offset += EVENT_SIZE + ie->len;
                    }
                }
            } while ((rv > 0) && (sync_fd < 0));
            close(inotify_fd);
        } else {
            #ifdef DEBUG_MSRPC_FIFO
            printf("open for sync_fd failed: %m\n");
            #endif
            return -1;
        }
    }

    #ifdef DEBUG_MSRPC_FIFO
    printf("Trying to read from sync_fd %d\n", sync_fd);
    #endif

    int8_t result;
    ssize_t read_count = read(sync_fd, &result, sizeof(result));
    if (read_count <= 0) {
        int read_errno = (read_count == 0) ? ENODATA : errno;
        close(sync_fd);
        errno = read_errno;
        #ifdef DEBUG_MSRPC_FIFO
        printf("read() on sync_fd failed: %m\n");
        #endif
        return -1;
    }

    unlink(key);
    close(sync_fd);
    errno = 0;
    return result;
}

int msrpc_sync_ready(const char *key, int8_t value)
{
    // try to create and open the file
    int sync_fd = open(key, O_WRONLY | O_CLOEXEC | O_CREAT | O_EXCL, 0600);
    if (sync_fd < 0) {
        #ifdef DEBUG_MSRPC_FIFO
        printf("open() on sync_fd for %s failed: %m\n", key);
        #endif
        return -1;
    }

    // write the value to the file and close it
    ssize_t written = write(sync_fd, &value, sizeof(value));
    if (written <= 0) {
        #ifdef DEBUG_MSRPC_FIFO
        printf("write() on sync_fd for %s failed: %m\n", key);
        #endif
        unlink(key);
        close(sync_fd);
        return -1;
    }

    close(sync_fd);
    return 0;
}

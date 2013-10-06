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

#ifndef _MSRPC_FIFO_H_
#define _MSRPC_FIFO_H_

#include <sys/types.h>
#include <sys/time.h>

/**
 * msrpc_sync_wait() waits until its counter part function
 * msrpc_sync_ready() is called for the same key or until the specified
 * timeout is reached. In the first case it returns the value that was
 * used in the call of msrpc_sync_ready() and errno is set to zero. In
 * the latter case it returns -1 and errno is set to ETIMEDOUT.
 *
 * The provided key needs to be a file name of a file created by
 * msrpc_sync_ready. If the operation succeeds (i.e. no timeout happens)
 * the file will get unlinked on return.
 *
 * The timeout is specified in milli seconds.
 *
 * This function can be used to synchronize two processes.
 */
int8_t msrpc_sync_wait(const char *key, int timeout);

/**
 * msrpc_sync_ready() transports the specified value to the counter part
 * function msrpc_sync_wait() that was called for the same key (see
 * above). On success, zero is returned. On error -1 is returned and
 * errno is set appropriately.
 *
 * The provided key will be used to create a file on the file system, so
 * it needs to be a valid file name.
 *
 * This function can be used to synchronize two processes.
 */
int msrpc_sync_ready(const char *key, int8_t value);

#endif

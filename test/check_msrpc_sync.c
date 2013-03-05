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

#include <check.h>
#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include "msrpc_sync.h"

typedef struct {
    const char *key;
    int timeout;
    int8_t exp_value;
    int exp_errno;
} test_msrpc_sync_wait_t;

const static test_msrpc_sync_wait_t testset_msrpc_sync_wait[] = {
    { "/tmp/test_fifo", 1, -1, ETIMEDOUT },
    { "/dev/zero",      1,  0, 0         },
    { "/dev/null",      1, -1, ENODATA   },
};
const static size_t testset_msrpc_sync_wait_size = sizeof(testset_msrpc_sync_wait) / sizeof(test_msrpc_sync_wait_t);

typedef struct {
    const char *key;
    int8_t value;
    int exp_rv;
    int exp_errno;
} test_msrpc_sync_ready_t;

const static test_msrpc_sync_ready_t testset_msrpc_sync_ready[] = {
    { "/tmp/test_fifo", 42,  0, 0      },
    { "/dev/null",      42, -1, EEXIST },
};
const static size_t testset_msrpc_sync_ready_size = sizeof(testset_msrpc_sync_ready) / sizeof(test_msrpc_sync_ready_t);

START_TEST (test_msrpc_sync_wait)
{
    const test_msrpc_sync_wait_t *ts = &testset_msrpc_sync_wait[_i];
    int8_t value = msrpc_sync_wait(ts->key, ts->timeout);
    fail_unless(value == ts->exp_value, " for iteration %u on fifo %s\n"
                "EXPECTED value %d, BUT GOT value %d (%m)", _i, ts->key, ts->exp_value, value);
    if (value != 0) {
        fail_unless(errno == ts->exp_errno, " for iteration %u on fifo %s\n"
                    "EXPECTED errno %d, BUT GOT errno %d", _i, ts->key, ts->exp_errno, errno);
    }
}
END_TEST

START_TEST (test_msrpc_sync_ready)
{
    const test_msrpc_sync_ready_t *ts = &testset_msrpc_sync_ready[_i];
    int rv = msrpc_sync_ready(ts->key, ts->value);
    int rv_errno = errno;
    unlink(ts->key);
    errno = rv_errno;
    fail_unless(rv == ts->exp_rv, " for iteration %u on fifo %s\n"
                "EXPECTED rv %d, BUT GOT rv %d (%m)", _i, ts->key, ts->exp_rv, rv);
    if (rv != 0) {
        fail_unless(errno == ts->exp_errno, " for iteration %u on fifo %s\n"
                    "EXPECTED errno %d, BUT GOT errno %d (%m)", _i, ts->key, ts->exp_errno, errno);
    }
}
END_TEST

Suite *
msrpc_fifo_suite (void)
{
    Suite *s = suite_create("MSRPC synchronization");
  
    /* check MSRPC FIFO wait */
    TCase *tc = tcase_create ("MSRPC sync wait");
    tcase_add_loop_test(tc, test_msrpc_sync_wait, 0, testset_msrpc_sync_wait_size);
    suite_add_tcase(s, tc);

    /* check MSRPC FIFO ready */
    tc = tcase_create ("MSRPC sync ready");
    tcase_add_loop_test(tc, test_msrpc_sync_ready, 0, testset_msrpc_sync_ready_size);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s = msrpc_fifo_suite();
    SRunner *sr = srunner_create(s);
    srunner_set_log (sr, "check.log");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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

#include <stdlib.h>
#include <check.h>
#include <assert.h>
#include <string.h>
#include "msrpc_pdu_parser.h"
#include "msrpc_pdu_private.h"
#include <stdio.h>       // TODO: REMOVE printf() and this line
#include <uuid/uuid.h>

#define TESTDATA_INITIAL_PDU_IN       "\x05\x00\x14\x03\x10\x00\x00\x00" \
      "\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x06\x00\x00\x00" \
      "\x01\x00\x00\x00\x03\x00\x00\x00\x97\x15\xf8\x97\xf6\x6d\x23\x4e" \
      "\x78\xca\x17\x6f\xdd\xe1\xbf\x2d\x03\x00\x00\x00\x25\x0d\x9e\x0d" \
      "\xce\x53\xca\x78\xee\x0c\xa1\x03\xb3\x54\xa1\x07\x04\x00\x00\x00" \
      "\x00\x00\x00\x40\x05\x00\x00\x00\xe0\x93\x04\x00\x0c\x00\x00\x00" \
      "\x1b\x38\x50\x77\x23\xb8\x42\x40\x91\xfe\x8d\x4b\x9e\xe8\xed\x1a"

#define TESTDATA_INITIAL_PDU_OUT      "\x05\x00\x14\x03\x10\x00\x00\x00" \
      "\x4c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x06\x00\x00\x00" \
      "\x01\x00\x00\x00\x03\x00\x00\x00\x97\x15\xf8\x97\xf6\x6d\x23\x4e" \
      "\x78\xca\x17\x6f\xdd\xe1\xbf\x2d\x03\x00\x00\x00\x86\x39\xb6\xd2" \
      "\xc9\x62\xa2\x77\xe4\x7a\x10\xf3\x57\x2d\xe7\xc2\x00\x00\x00\x00" \
      "\x00\x00\x01\x00"

typedef struct {
    const char *data;
    apr_size_t data_length;
    apr_status_t expected_result;
    apr_size_t expected_length;
} test_msrpc_pdu_length_t;

const static test_msrpc_pdu_length_t testset_msrpc_pdu_length[] = {
    { "",                                          0, APR_INCOMPLETE,  0 },
    { "\x00\x01\x02\x03\x04\x05\x06\x07\x08",      9, APR_INCOMPLETE,  9 },
    { "\x05\x00\x14\x03\x10\x00\x00\x00\x2c\x00", 10, APR_SUCCESS,    44 },
    { TESTDATA_INITIAL_PDU_IN,                   104, APR_SUCCESS,   104 },
    { TESTDATA_INITIAL_PDU_OUT,                   76, APR_SUCCESS,    76 },
};
const static size_t testset_msrpc_pdu_length_size = sizeof(testset_msrpc_pdu_length) / sizeof(test_msrpc_pdu_length_t);

typedef struct {
    const char *data;
    const char *expected_error;
    apr_status_t expected_result;
} test_msrpc_pdu_validate_t;

const static test_msrpc_pdu_validate_t testset_msrpc_pdu_validate[] = {
    { "\x05\x00\x14\x03\x10\x00\x00\x00\x04\x00\x00\x00",     "incomplete PDU",      APR_INCOMPLETE             },
    { "\x06\x00\x14\x03\x10\x00\x00\x00\x0c\x00\x00\x00",     "PDU version",         APR_FROM_OS_ERROR(EBADMSG) },
    { "\x05\x01\x14\x03\x10\x00\x00\x00\x0c\x00\x00\x00",     "PDU minor version",   APR_FROM_OS_ERROR(EBADMSG) },
    { "\x05\x00\x15\x03\x10\x00\x00\x00\x0c\x00\x00\x00",     "PDU type",            APR_FROM_OS_ERROR(EBADMSG) },
    { "\x05\x00\x14\x03\x01\x11\x11\x11\x0c\x00\x00\x00",     "data representation", APR_FROM_OS_ERROR(EBADMSG) },
    { "\x05\x00\x14\x03\x10\x00\x00\x00\x0d\x00\x00\x00\x00", "unaligned length",    APR_FROM_OS_ERROR(EBADMSG) },
    { "\x05\x00\x14\x03\x10\x00\x00\x00\x0c\x00\x00\x00",     NULL,                  APR_SUCCESS                },
    // Caution: next is a synthetic test case, big endian data representation has not been seen in the wild:
    { "\x05\x00\x14\x03\x00\x00\x00\x10\x00\x0c\x00\x00",     NULL,                  APR_SUCCESS                },
    { TESTDATA_INITIAL_PDU_IN,                                NULL,                  APR_SUCCESS                },
    { TESTDATA_INITIAL_PDU_OUT,                               NULL,                  APR_SUCCESS                },
};
const static size_t testset_msrpc_pdu_validate_size = sizeof(testset_msrpc_pdu_validate) / sizeof(test_msrpc_pdu_validate_t);

typedef struct {
    const char *data;
    apr_status_t expected_result;
    uint16_t expected_count;
} test_msrpc_pdu_get_rts_pdu_count_t;

const static test_msrpc_pdu_get_rts_pdu_count_t testset_msrpc_pdu_get_rts_pdu_count[] = {
    { TESTDATA_INITIAL_PDU_IN,                            APR_SUCCESS,                          6 },
    { TESTDATA_INITIAL_PDU_OUT,                           APR_SUCCESS,                          4 },
    { "\x05\x00\x13\x03\x10\x00\x00\x00\x0c\x00\x00\x00", APR_FROM_OS_ERROR(EINVAL), (uint16_t)-1 },
};
const static size_t testset_msrpc_pdu_get_rts_pdu_count_size = sizeof(testset_msrpc_pdu_get_rts_pdu_count) / sizeof(test_msrpc_pdu_get_rts_pdu_count_t);

typedef struct {
    const char *data;
    unsigned int expected_size;
} test_msrpc_rts_pdu_len_t;

const static test_msrpc_rts_pdu_len_t testset_msrpc_rts_pdu_len[] = {
    { "\x00\x00\x00\x00",  8 },
    { "\x01\x00\x00\x00", 28 },
    { "\x02\x00\x00\x00",  8 },
    { "\x03\x00\x00\x00", 20 },
    { "\x04\x00\x00\x00",  8 },
    { "\x05\x00\x00\x00",  8 },
    { "\x06\x00\x00\x00",  8 },
    { "\x07\x00\x00\x00",  4 },
    { "\x08\x00\x00\x00\x00\x00\x00\x00",  8 },
    { "\x08\x00\x00\x00\x01\x00\x00\x00",  9 },
    // checking whether all the bits from padding count are evaluated correctly:
    { "\x08\x00\x00\x00\x01\x02\x03\x04",  8 + 0x04030201 },
    { "\x09\x00\x00\x00",  4 },
    { "\x0a\x00\x00\x00",  4 },
    { "\x0b\x00\x00\x00\x00\x00\x00\x00",  8 +  4 + 12 },    // IPv4 address
    { "\x0b\x00\x00\x00\x01\x00\x00\x00",  8 + 16 + 12 },    // IPv6 address
    { "\x0b\x00\x00\x00\x03\x00\x00\x00",  0 },    // neither IPv4 nor IPv6 address
    { "\x0c\x00\x00\x00", 20 },
    { "\x0d\x00\x00\x00",  8 },
    { "\x0e\x00\x00\x00",  8 },
    { "\x0f\x00\x00\x00",  0 },
};
const static size_t testset_msrpc_rts_pdu_len_size = sizeof(testset_msrpc_rts_pdu_len) / sizeof(test_msrpc_rts_pdu_len_t);

typedef struct {
    const char *data;
    unsigned int offset;
    int output_buffer_length;
    apr_status_t expected_rv;
    const char *expected_data;
    unsigned int expected_length;
} test_msrpc_pdu_get_rts_pdu_t;

const static test_msrpc_pdu_get_rts_pdu_t testset_msrpc_pdu_get_rts_pdu[] = {
    { TESTDATA_INITIAL_PDU_IN,   0, -1, APR_SUCCESS, "\x06\x00\x00\x00\x01\x00\x00\x00",   8 },
    { TESTDATA_INITIAL_PDU_IN,   8, -1, APR_SUCCESS,
      "\x03\x00\x00\x00\x97\x15\xF8\x97\xF6\x6D\x23\x4E\x78\xCA\x17\x6F\xDD\xE1\xBF\x2D", 20 },
    { TESTDATA_INITIAL_PDU_IN,  28, -1, APR_SUCCESS,
      "\x03\x00\x00\x00\x25\x0D\x9E\x0D\xCE\x53\xCA\x78\xEE\x0C\xA1\x03\xB3\x54\xA1\x07", 20 },
    { TESTDATA_INITIAL_PDU_IN,  48, -1, APR_SUCCESS, "\x04\x00\x00\x00\x00\x00\x00\x40",   8 },
    { TESTDATA_INITIAL_PDU_IN,  56, -1, APR_SUCCESS, "\x05\x00\x00\x00\xE0\x93\x04\x00",   8 },
    { TESTDATA_INITIAL_PDU_IN,  64, -1, APR_SUCCESS,
      "\x0C\x00\x00\x00\x1B\x38\x50\x77\x23\xB8\x42\x40\x91\xFE\x8D\x4B\x9E\xE8\xED\x1A", 20 },
    { TESTDATA_INITIAL_PDU_OUT,  0, -1, APR_SUCCESS, "\x06\x00\x00\x00\x01\x00\x00\x00",   8 },
    { TESTDATA_INITIAL_PDU_OUT,  8, -1, APR_SUCCESS,
      "\x03\x00\x00\x00\x97\x15\xF8\x97\xF6\x6D\x23\x4E\x78\xCA\x17\x6F\xDD\xE1\xBF\x2D", 20 },
    { TESTDATA_INITIAL_PDU_OUT, 28, -1, APR_SUCCESS,
      "\x03\x00\x00\x00\x86\x39\xB6\xD2\xC9\x62\xA2\x77\xE4\x7A\x10\xF3\x57\x2D\xE7\xC2", 20 },
    { TESTDATA_INITIAL_PDU_OUT, 48, -1, APR_SUCCESS, "\x00\x00\x00\x00\x00\x00\x01\x00",   8 },
    { "\x05\x00\x13\x03\x10\x00\x00\x00\x2c\x00", 0, -1, APR_FROM_OS_ERROR(EINVAL),  NULL, 0 },
    { "\x05\x00\x14\x03\x10\x00\x00\x00\x14\x00", 0, -1, APR_FROM_OS_ERROR(EINVAL),  NULL, 0 },
    { "\x05\x00\x14\x03\x10\x00\x00\x00\x1C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00"
      "\xFF\x00\x00\x00\x01\x00\x00\x00",         0, -1, APR_FROM_OS_ERROR(EBADMSG), NULL, 0 },
    { "\x05\x00\x14\x03\x10\x00\x00\x00\x1B\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00"
      "\x06\x00\x00\x00\x01\x00\x00\x00",         0, -1, APR_FROM_OS_ERROR(EBADMSG), NULL, 0 },
    { "\x05\x00\x14\x03\x10\x00\x00\x00\x1C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00"
      "\x06\x00\x00\x00\x01\x00\x00\x00",         0,  8, APR_SUCCESS, "\x06\x00\x00\x00\x01\x00\x00\x00", 8 },
};
const static size_t testset_msrpc_pdu_get_rts_pdu_size = sizeof(testset_msrpc_pdu_get_rts_pdu) / sizeof(test_msrpc_pdu_get_rts_pdu_t);

typedef struct {
    const char *data;
    const char *name;
} test_msrpc_pdu_get_name_t;

const static test_msrpc_pdu_get_name_t testset_msrpc_pdu_get_name[] = {
    { TESTDATA_INITIAL_PDU_IN,  "RPC RTS" },
    { TESTDATA_INITIAL_PDU_OUT, "RPC RTS" },
};
const static size_t testset_msrpc_pdu_get_name_size = sizeof(testset_msrpc_pdu_get_name) / sizeof(test_msrpc_pdu_get_name_t);

typedef struct {
    const char *data;
    unsigned int rts_command_count;
    const char *name[7];
} test_msrpc_rts_pdu_get_command_name_t;

const static test_msrpc_rts_pdu_get_command_name_t testset_msrpc_rts_pdu_get_command_name[] = {
    { TESTDATA_INITIAL_PDU_IN,  6, { "Version", "Cookie", "Cookie", "ChannelLifetime", "ClientKeepalive",
                                     "AssociationGroupID", NULL } },
    { TESTDATA_INITIAL_PDU_OUT, 4, { "Version", "Cookie", "Cookie", "ReceiveWindowSize", NULL, NULL, NULL } },
};
const static size_t testset_msrpc_rts_pdu_get_command_name_size = sizeof(testset_msrpc_rts_pdu_get_command_name) / sizeof(test_msrpc_rts_pdu_get_command_name_t);

typedef struct {
    const char *data;
    uuid_t cookie;
} test_msrpc_rts_get_virtual_channel_cookie_t;

const static test_msrpc_rts_get_virtual_channel_cookie_t testset_msrpc_rts_get_virtual_channel_cookie[] = {
    { TESTDATA_INITIAL_PDU_IN,  { 0x97, 0x15, 0xf8, 0x97, 0xf6, 0x6d, 0x23, 0x4e, 0x78, 0xca, 0x17, 0x6f, 0xdd, 0xe1, 0xbf, 0x2d } },
    { TESTDATA_INITIAL_PDU_IN,  { 0x97, 0x15, 0xf8, 0x97, 0xf6, 0x6d, 0x23, 0x4e, 0x78, 0xca, 0x17, 0x6f, 0xdd, 0xe1, 0xbf, 0x2d } },
};
const static size_t testset_msrpc_rts_get_virtual_channel_cookie_size = sizeof(testset_msrpc_rts_get_virtual_channel_cookie) / sizeof(test_msrpc_rts_get_virtual_channel_cookie_t);

START_TEST (test_msrpc_pdu_get_length)
{
    char data[10];
    memcpy(data, testset_msrpc_pdu_length[_i].data, sizeof(data));
    apr_size_t data_length = testset_msrpc_pdu_length[_i].data_length;
    apr_status_t rv = msrpc_pdu_get_length(data, &data_length);
    fail_unless(rv == testset_msrpc_pdu_length[_i].expected_result, " for iteration %u\n"
                "EXPECTED rv: %u, BUT GOT rv: %u", _i, testset_msrpc_pdu_length[_i].expected_result, rv);
    fail_unless(data_length == testset_msrpc_pdu_length[_i].expected_length, " for iteration %u\n"
                "EXPECTED length: %lu, BUT GOT length: %lu", _i, testset_msrpc_pdu_length[_i].expected_length, data_length);
}
END_TEST

START_TEST (test_msrpc_pdu_validate)
{
    const char *error = NULL;
    apr_status_t expected_result = testset_msrpc_pdu_validate[_i].expected_result;
    const char *expected_error = testset_msrpc_pdu_validate[_i].expected_error;
    
    apr_status_t rv = msrpc_pdu_validate(testset_msrpc_pdu_validate[_i].data, &error);
    fail_unless(rv == expected_result, " for iteration %u\n"
                "EXPECTED rv: %u, BUT GOT rv: %u (%s)", _i, expected_result, rv, error);

    if (expected_error == NULL) {
        fail_unless(error == NULL, " for iteration %u\n"
                    "EXPECTED error as a NULL pointer, BUT GOT error: %s", _i, error);
    } else {
        fail_unless(error != NULL, " for iteration %u\n"
                    "EXPECTED error: %s, BUT GOT a NULL pointer", _i, expected_error);
        if (error) {
            fail_unless(!strcmp(error, expected_error), " for iteration %u\n"
                        "EXPECTED error: %s, BUT GOT error: %s", _i, expected_error, error);
        }
    }
}
END_TEST

START_TEST (test_msrpc_pdu_get_rts_pdu_count)
{
    const char *data = testset_msrpc_pdu_get_rts_pdu_count[_i].data;
    apr_status_t expected_rv = testset_msrpc_pdu_get_rts_pdu_count[_i].expected_result;
    uint16_t expected_count = testset_msrpc_pdu_get_rts_pdu_count[_i].expected_count;

    uint16_t count = (uint16_t)-1;
    apr_status_t rv = msrpc_pdu_get_rts_pdu_count(data, &count);
    fail_unless(rv == expected_rv, " for iteration %u\n"
                "EXPECTED rv: %u, BUT GOT rv: %u", _i, expected_rv, rv);
    fail_unless(count == expected_count, " for iteration %u\n"
                "EXPECTED count: %u, BUT GOT count: %u", _i, expected_count, count);
}
END_TEST

START_TEST (test_msrpc_rts_pdu_len)
{
    const msrpc_rts_pdu_t *pdu = (const msrpc_rts_pdu_t *)testset_msrpc_rts_pdu_len[_i].data;
    apr_size_t expected_size = testset_msrpc_rts_pdu_len[_i].expected_size;

    apr_size_t size = msrpc_rts_pdu_len(pdu);
    fail_unless(size == expected_size, " for iteration %u\n"
                "EXPECTED size: %lu, BUT GOT size: %lu", _i, expected_size, size);
}
END_TEST

START_TEST (test_msrpc_pdu_get_rts_pdu)
{
    const test_msrpc_pdu_get_rts_pdu_t *testset = &testset_msrpc_pdu_get_rts_pdu[_i];
    msrpc_rts_pdu_t *rtspdu = NULL;
    unsigned int rtspdulen = 0;

    apr_status_t rv = msrpc_pdu_get_rts_pdu(testset->data, testset->offset, &rtspdu, &rtspdulen);
    fail_unless(testset->expected_rv == rv, " for iteration %u\n"
                "EXPECTED rv: %u, BUT GOT rv: %u", _i, testset->expected_rv, rv);
    if (rv == APR_SUCCESS) {
        fail_unless(testset->expected_length == rtspdulen, " for iteration %u\n"
                    "EXPECTED pdu length: %u, BUT GOT pdu length: %u", _i,
                    testset->expected_length, rtspdulen);
        if (memcmp(testset->expected_data, rtspdu, rtspdulen) != 0) {
            unsigned char *received_data = (unsigned char *)rtspdu;
            char expected_str[4096];
            char returned_str[4096];
            int i;
            for (i=0; i < rtspdulen; i++) {
                snprintf(&expected_str[i*3], sizeof(expected_str)-1-i*3, "%02hhX ", (unsigned char)testset->expected_data[i]);
                snprintf(&returned_str[i*3], sizeof(returned_str)-1-i*3, "%02hhX ", received_data[i]);
            }
            expected_str[rtspdulen*3-1] = 0;
            returned_str[rtspdulen*3-1] = 0;
            fail(" for iteration %u\n"
                 "EXPECTED pdu [%s] DOES NOT MATCH\nreturned pdu [%s]", _i,
                 expected_str, returned_str);
        }
    }
}
END_TEST

START_TEST (test_msrpc_pdu_get_name)
{
    const char *pdu  = testset_msrpc_pdu_get_name[_i].data;
    const char *expected_name = testset_msrpc_pdu_get_name[_i].name;

    const char *name = msrpc_pdu_get_name(pdu);
    if (name) {
        if (!expected_name) {
            expected_name = "<NULL pointer>";
        }
        fail_unless(strcmp(name, expected_name) == 0, " for iteration %u\n"
                    "EXPECTED name: %s, BUT GOT name: %s", _i, expected_name, name);
    } else {
        fail(" for iteration %u\nEXPECTED a pdu name, BUT GOT a NULL pointer", _i);
    }
}
END_TEST

START_TEST (test_msrpc_rts_pdu_get_command_name)
{
    const char *pdu  = testset_msrpc_rts_pdu_get_command_name[_i].data;
    unsigned int expected_command_count = testset_msrpc_rts_pdu_get_command_name[_i].rts_command_count;
    msrpc_rts_pdu_t *rtspdu = NULL;
    unsigned int i, rtspdulen;
    unsigned int offset = 0;
    apr_status_t rv;

    for (i = 0; i < expected_command_count; i++) {
        rv = msrpc_pdu_get_rts_pdu(pdu, offset, &rtspdu, &rtspdulen);
        fail_unless(rv == APR_SUCCESS, " for iteration %u\n"
                    "EXPECTED rv 0, BUT GOT rv %u", _i, rv);
        const char *name = msrpc_rts_pdu_get_command_name(rtspdu);
        const char *expected_name = testset_msrpc_rts_pdu_get_command_name[_i].name[i];
        if (name) {
            if (!expected_name) {
                expected_name = "<NULL pointer>";
            }
            fail_unless(strcmp(name, expected_name) == 0, " for iteration %u, RTS command %u\n"
                        "EXPECTED name: %s, BUT GOT name: %s", _i, i, expected_name, name);
        } else {
            fail(" for iteration %u, RTS command %u\nEXPECTED a pdu name, BUT GOT a NULL pointer", _i, i);
        }

        offset += rtspdulen;
    }
}
END_TEST

START_TEST (test_msrpc_rts_get_virtual_channel_cookie)
{
    const char *pdu = testset_msrpc_rts_get_virtual_channel_cookie[_i].data;
    const uuid_t *expected_cookie = &testset_msrpc_rts_get_virtual_channel_cookie[_i].cookie;
    uuid_t *cookie = NULL;
    const char *error = NULL;

    apr_status_t rv = msrpc_rts_get_virtual_channel_cookie(pdu, &cookie, &error);
    fail_unless(rv == APR_SUCCESS, " for iteration %u\n"
                "EXPECTED no error, BUT GOT rv: %u (%s)", _i, rv, error);
    if (uuid_compare(*expected_cookie, *cookie) != 0) {
        char expected_uuid[37];
        uuid_unparse(*expected_cookie, expected_uuid);
        char parsed_uuid[37];
        uuid_unparse(*cookie, parsed_uuid);
        fail(" for iteration %u\nEXPECTED cookie %s, BUT GOT cookie: %s", _i, expected_uuid, parsed_uuid);
    }
}
END_TEST

Suite *
msrpc_pdu_parser_suite (void)
{
    Suite *s = suite_create("MSRPC PDU parser");
  
    /* check MSRPC PDU length retrieval */
    TCase *tc = tcase_create ("MSRPC PDU length retrieval");
    tcase_add_loop_test(tc, test_msrpc_pdu_get_length, 0, testset_msrpc_pdu_length_size);
    suite_add_tcase(s, tc);

    /* check MSRPC PDU validation */
    tc = tcase_create ("MSRPC PDU validation");
    tcase_add_loop_test(tc, test_msrpc_pdu_validate, 0, testset_msrpc_pdu_validate_size);
    suite_add_tcase(s, tc);

    /* check MSRPC RTS PDU count retrieval */
    tc = tcase_create ("MSRPC PDU, RTS PDU count retrieval");
    tcase_add_loop_test(tc, test_msrpc_pdu_get_rts_pdu_count, 0, testset_msrpc_pdu_get_rts_pdu_count_size);
    suite_add_tcase(s, tc);

    /* check MSRPC RTS length parsing */
    tc = tcase_create ("MSRPC RTS PDU length check");
    tcase_add_loop_test(tc, test_msrpc_rts_pdu_len, 0, testset_msrpc_rts_pdu_len_size);
    suite_add_tcase(s, tc);

    /* check MSRPC RTS PDU retrieval */
    tc = tcase_create ("MSRPC PDU, RTS PDU retrieval");
    tcase_add_loop_test(tc, test_msrpc_pdu_get_rts_pdu, 0, testset_msrpc_pdu_get_rts_pdu_size);
    suite_add_tcase(s, tc);

    /* check MSRPC PDU name */
    tc = tcase_create ("MSRPC PDU name detection");
    tcase_add_loop_test(tc, test_msrpc_pdu_get_name, 0, testset_msrpc_pdu_get_name_size);
    suite_add_tcase(s, tc);

    /* check MSRPC RTS command name */
    tc = tcase_create ("MSRPC RTS command name detection");
    tcase_add_loop_test(tc, test_msrpc_rts_pdu_get_command_name, 0, testset_msrpc_rts_pdu_get_command_name_size);
    suite_add_tcase(s, tc);

    /* check virtual channel cookie */
    tc = tcase_create ("MSRPC RTS virtual channel cookie");
    tcase_add_loop_test(tc, test_msrpc_rts_get_virtual_channel_cookie, 0, testset_msrpc_rts_get_virtual_channel_cookie_size);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s = msrpc_pdu_parser_suite();
    SRunner *sr = srunner_create(s);
    srunner_set_log (sr, "check.log");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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

#include "msrpc_pdu_parser.h"
#include "msrpc_pdu_private.h"
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#ifdef DEBUG_MSRPC_PDU_PARSER
#include <stdio.h>
#endif

static const char const *msrpc_pdu_name[] = {
    "RPC REQUEST",
    "RPC PING",
    "RPC RESPONSE",
    "RPC FAULT",
    "RPC WORKING",
    "RPC NOCALL",
    "RPC REJECT",
    "RPC ACK",
    "RPC CL CANCEL",
    "RPC FACK",
    "RPC CANCEL ACK",
    "RPC BIND",
    "RPC BIND ACK",
    "RPC BIND NAK",
    "RPC ALTER CONTEXT",
    "RPC ALTER CONTEXT RESP",
    NULL,
    "RPC SHUTDOWN",
    "RPC CO CANCEL",
    "RPC ORPHANED",
    "RPC RTS",
    NULL,
};

static const char const *msrpc_rts_pdu_command_name[] = {
    "ReceiveWindowSize",
    "FlowControlAck",
    "ConnectionTimeOut",
    "Cookie",
    "ChannelLifetime",
    "ClientKeepalive",
    "Version",
    "Empty",
    "Padding",
    "NegativeANCE",
    "ANCE",
    "ClientAddress",
    "AssociationGroupID",
    "Destination",
    "PingTrafficSentNotify",
    NULL,
};

#define MSRPC_PDU_IS_LITTLE_ENDIAN (pdu->data_representation == MSRPC_PDU_DATA_REPRESENTATION_LITTLE_ENDIAN)

apr_status_t msrpc_pdu_get_length(const char *buf, apr_size_t *length)
{
    msrpc_pdu_t *pdu = (msrpc_pdu_t *)buf;
    assert(length != NULL);

    if (*length < offsetof(msrpc_pdu_t, auth_length)) {
        return APR_INCOMPLETE;
    }

    #ifdef DEBUG_MSRPC_PDU_PARSER
    printf("data representation: 0x%08x\n", (uint32_t)pdu->data_representation);
    #endif
    *length = MSRPC_PDU_IS_LITTLE_ENDIAN ? pdu->frag_length : swap_bytes_uint16_t(pdu->frag_length);
    return APR_SUCCESS;
}

apr_status_t msrpc_pdu_validate(const char *buf, const char **error)
{
    msrpc_pdu_t *pdu = (msrpc_pdu_t *)buf;
    apr_size_t length = offsetof(msrpc_pdu_t, auth_length);
    apr_status_t rv = msrpc_pdu_get_length(buf, &length);
    if (rv != APR_SUCCESS) {
        if (error) *error = "bad length";
        return rv;
    }
    if (length < offsetof(msrpc_pdu_t, auth_length)) {
        if (error) *error = "incomplete PDU";
        return APR_INCOMPLETE;
    }
    if (pdu->version != 5) {
        if (error) *error = "PDU version";
        return APR_FROM_OS_ERROR(EBADMSG);
    }
    if (pdu->version_minor != 0) {
        if (error) *error = "PDU minor version";
        return APR_FROM_OS_ERROR(EBADMSG);
    }
    if (pdu->type > 20) {
        if (error) *error = "PDU type";
        return APR_FROM_OS_ERROR(EBADMSG);
    }
    if ((pdu->data_representation != MSRPC_PDU_DATA_REPRESENTATION_LITTLE_ENDIAN) &&
        (pdu->data_representation != MSRPC_PDU_DATA_REPRESENTATION_BIG_ENDIAN)) {
        if (error) *error = "data representation";
        return APR_FROM_OS_ERROR(EBADMSG);
    }
    uint16_t frag_length = MSRPC_PDU_IS_LITTLE_ENDIAN ? pdu->frag_length : swap_bytes_uint16_t(pdu->frag_length);
    if (frag_length % 4 != 0) {
        if (error) *error = "unaligned length";
        return APR_FROM_OS_ERROR(EBADMSG);
    }
    return APR_SUCCESS;
}

apr_status_t msrpc_pdu_get_rts_pdu_count(const char *buf, uint16_t *count)
{
    assert(buf != NULL);
    assert(count != NULL);

    msrpc_pdu_t *pdu = (msrpc_pdu_t *)buf;
    if (pdu->type != MSRPC_PDU_RTS) {
        return APR_FROM_OS_ERROR(EINVAL);
    }
    *count = MSRPC_PDU_IS_LITTLE_ENDIAN ? pdu->rts_pdu_count : swap_bytes_uint16_t(pdu->rts_pdu_count);
    return APR_SUCCESS;
}

unsigned int msrpc_rts_pdu_len(const msrpc_rts_pdu_t *pdu, uint32_t data_representation)
{
    apr_size_t size = 0;
    uint32_t conformance_count;
    uint32_t addrtype;
    uint32_t command;

    assert(pdu != NULL);
    command = (data_representation == MSRPC_PDU_DATA_REPRESENTATION_LITTLE_ENDIAN) ? pdu->command : swap_bytes_uint32_t(pdu->command);
    #ifdef DEBUG_MSRPC_PDU_PARSER
    printf("msrpc_rts_pdu_len: data representation: 0x%08x, command: 0x%08x\n", data_representation, command);
    #endif

    switch (command) {
        case RTS_CMD_RECEIVE_WINDOW_SIZE:
        case RTS_CMD_CONNECTION_TIMEOUT:
        case RTS_CMD_CHANNEL_LIFETIME:
        case RTS_CMD_CLIENT_KEEPALIVE:
        case RTS_CMD_VERSION:
        case RTS_CMD_DESTINATION:
        case RTS_CMD_PING_TRAFFIC_SENT_NOTIFY:
            size = sizeof(pdu->command) + sizeof(uint32_t);
            break;
        case RTS_CMD_FLOW_CONTROL_ACK:
            size = sizeof(pdu->command) + sizeof(uint32_t)      // bytes received
                                        + sizeof(uint32_t)      // available window
                                        + sizeof(uuid_t);       // channel cookie
            break;
        case RTS_CMD_COOKIE:
        case RTS_CMD_ASSOCIATION_GROUPID:
            size = sizeof(pdu->command) + sizeof(uuid_t);
            break;
        case RTS_CMD_EMPTY:
        case RTS_CMD_NEGATIVE_ANCE:
        case RTS_CMD_ANCE:
            size = sizeof(pdu->command);
            break;
        case RTS_CMD_PADDING:
            // see http://msdn.microsoft.com/en-us/library/cc244015.aspx
            if (data_representation == MSRPC_PDU_DATA_REPRESENTATION_LITTLE_ENDIAN) {
                conformance_count = pdu->u32[0];
            } else {
                conformance_count = swap_bytes_uint32_t(pdu->u32[0]);
            }
            size = sizeof(pdu->command) + sizeof(conformance_count)
                                        + conformance_count;
            break;
        case RTS_CMD_CLIENT_ADDRESS:
            // see http://msdn.microsoft.com/en-us/library/cc244004.aspx
            // and http://msdn.microsoft.com/en-us/library/cc243993.aspx
            if (data_representation == MSRPC_PDU_DATA_REPRESENTATION_LITTLE_ENDIAN) {
                addrtype = pdu->u32[0];
            } else {
                addrtype = swap_bytes_uint32_t(pdu->u32[0]);
            }
            size = sizeof(pdu->command) + sizeof(addrtype);
            switch (addrtype) {
                case RTS_IPV4:
                    size += sizeof(struct in_addr);
                    break;
                case RTS_IPV6:
                    size += sizeof(struct in6_addr);
                    break;
                default:
                    return 0;
            }
            size += 12;         // padding
            break;
        default:
            return 0;
    }
    return size;
}

apr_status_t msrpc_pdu_get_rts_pdu(const char *buf, unsigned int offset, msrpc_rts_pdu_t **rts_pdu, unsigned int *len)
{
    assert(buf != NULL);
    assert(rts_pdu != NULL);

    msrpc_pdu_t *pdu = (msrpc_pdu_t *)buf;
    uint16_t frag_length = MSRPC_PDU_IS_LITTLE_ENDIAN ? pdu->frag_length : swap_bytes_uint16_t(pdu->frag_length);
    if (pdu->type != MSRPC_PDU_RTS) {
        #ifdef DEBUG_MSRPC_PDU_PARSER
        printf("No RTS PDU\n");
        #endif
        return APR_FROM_OS_ERROR(EINVAL);
    }
    if (offsetof(msrpc_pdu_t, rts_pdu_buf) + offset >= frag_length) {
        #ifdef DEBUG_MSRPC_PDU_PARSER
        printf("Frag length shorter than offset\n");
        #endif
        return APR_FROM_OS_ERROR(EINVAL);
    }
    unsigned int pdusize = msrpc_rts_pdu_len((msrpc_rts_pdu_t *)(pdu->rts_pdu_buf + offset), pdu->data_representation);
    if (pdusize == 0) {
        #ifdef DEBUG_MSRPC_PDU_PARSER
        printf("failed to parse RTS PDU\n");
        #endif
        return APR_FROM_OS_ERROR(EBADMSG);
    }
    if (offsetof(msrpc_pdu_t, rts_pdu_buf) + offset + pdusize > frag_length) {
        #ifdef DEBUG_MSRPC_PDU_PARSER
        printf("RTS PDU length doesn't fit into frag length at the given offset\n");
        #endif
        return APR_FROM_OS_ERROR(EBADMSG);
    }
    *len = pdusize;
    *rts_pdu = (msrpc_rts_pdu_t *)(pdu->rts_pdu_buf + offset);
    return APR_SUCCESS;
}

const char *msrpc_pdu_get_name(const char *buf)
{
    assert(buf);
    msrpc_pdu_t *pdu = (msrpc_pdu_t *)buf;
    if (pdu->type <= MSRPC_PDU_RTS) {
        return msrpc_pdu_name[pdu->type];
    }
    return NULL;
}

const char *msrpc_rts_pdu_get_command_name(msrpc_rts_pdu_t *pdu, uint32_t data_representation)
{
    uint32_t command;

    assert(pdu);
    command = (data_representation == MSRPC_PDU_DATA_REPRESENTATION_LITTLE_ENDIAN) ? pdu->command : swap_bytes_uint32_t(pdu->command);
    if (command <= RTS_CMD_PING_TRAFFIC_SENT_NOTIFY) {
        return msrpc_rts_pdu_command_name[command];
    }
    return NULL;
}

apr_status_t msrpc_rts_get_virtual_channel_cookie(const char *buf, uuid_t **cookie, const char **error)
{
    msrpc_pdu_t *pdu = (msrpc_pdu_t *)buf;
    uint16_t rts_pdu_count;
    apr_status_t rv;

    assert(buf);
    assert(cookie);

    if (pdu->type != MSRPC_PDU_RTS) {
        if (error) *error = "not a RTS pdu";
        return APR_FROM_OS_ERROR(EINVAL);
    }

    if (pdu->rts_flags != RTS_FLAG_NONE) {
        if (error) *error = "unexpected flags on RTS pdu";
        return APR_FROM_OS_ERROR(EBADMSG);
    }

    rv = msrpc_pdu_get_rts_pdu_count(buf, &rts_pdu_count);
    if (rv != APR_SUCCESS) {
        if (error) *error = "unexpected error from msrpc_pdu_get_rts_pdu_count()";
        return rv;
    }

    if ((rts_pdu_count != 4) &&
        (rts_pdu_count != 6)) {
        if (error) *error = "unexpected RTS command count";
        return APR_FROM_OS_ERROR(EBADMSG);
    }

    unsigned int offset = 0;
    msrpc_rts_pdu_t *rtspdu = NULL;
    unsigned int rtspdulen = 0;
    rv = msrpc_pdu_get_rts_pdu(buf, offset, &rtspdu, &rtspdulen);
    if (rv != APR_SUCCESS) {
        if (error) *error = "failed to get first RTS command";
        return rv;
    }
    uint32_t command = MSRPC_PDU_IS_LITTLE_ENDIAN ? rtspdu->command : swap_bytes_uint32_t(rtspdu->command);
    uint32_t rts_version = MSRPC_PDU_IS_LITTLE_ENDIAN ? rtspdu->u32[0] : swap_bytes_uint32_t(rtspdu->u32[0]);
    if ((command != RTS_CMD_VERSION) &&
        (rts_version != 1)) {
        if (error) *error = "unexpected first RTS command or RTS version";
        return APR_FROM_OS_ERROR(EBADMSG);
    }
    offset += rtspdulen;

    rv = msrpc_pdu_get_rts_pdu(buf, offset, &rtspdu, &rtspdulen);
    if (rv != APR_SUCCESS) {
        if (error) *error = "failed to get second RTS command";
        return rv;
    }
    command = MSRPC_PDU_IS_LITTLE_ENDIAN ? rtspdu->command : swap_bytes_uint32_t(rtspdu->command);
    if (command != RTS_CMD_COOKIE) {
        if (error) *error = "unexpected second RTS command";
        return APR_FROM_OS_ERROR(EBADMSG);
    }

    *cookie = &rtspdu->uuid;
    return APR_SUCCESS;
}

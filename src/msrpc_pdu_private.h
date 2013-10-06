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

#ifndef _MSRPC_PDU_PRIVATE_H_
#define _MSRPC_PDU_PRIVATE_H_

#include <netinet/in.h>
#include <uuid/uuid.h>

/* interpretation of such PDUs, see Microsoft's documentation:
 * http://msdn.microsoft.com/en-us/library/cc244017.aspx (RTS PDU header)
 * http://msdn.microsoft.com/en-us/library/cc244018.aspx (RTS PDU body)
 */
struct msrpc_rts_pdu {
    uint32_t command;
    union {
        uint8_t  u8[16];
        uint16_t u16[8];
        uint32_t u32[4];
        uint64_t u64[2];
        uuid_t uuid;
        struct in_addr ipv4_addr;
        struct in6_addr ipv6_addr;        
    };
}__attribute__ ((packed));

typedef struct _msrpc_pdu {
    uint8_t version;
    uint8_t version_minor;
    uint8_t type;
    uint8_t flags;
    uint32_t data_representation;
    uint16_t frag_length;
    uint16_t auth_length;
    uint32_t call_id;
    union {
        uint8_t data[112];
        struct {
            uint16_t rts_flags;
            uint16_t rts_pdu_count;
            uint8_t  rts_pdu_buf[108];
        };
    };
} __attribute__ ((packed)) msrpc_pdu_t;

/* MSRPC PDU types 
 * see also http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagtcjh_28
 */
#define MSRPC_PDU_REQUEST             0
#define MSRPC_PDU_PING                1
#define MSRPC_PDU_RESPONSE            2
#define MSRPC_PDU_FAULT               3
#define MSRPC_PDU_WORKING             4
#define MSRPC_PDU_NOCALL              5
#define MSRPC_PDU_REJECT              6
#define MSRPC_PDU_ACK                 7
#define MSRPC_PDU_CL_CANCEL           8
#define MSRPC_PDU_FACK                9
#define MSRPC_PDU_CANCEL_ACK         10
#define MSRPC_PDU_BIND               11
#define MSRPC_PDU_BIND_ACK           12
#define MSRPC_PDU_BIND_NAK           13
#define MSRPC_PDU_ALTER_CONTEXT      14
#define MSRPC_PDU_ALTER_CONTEXT_RESP 15
#define MSRPC_PDU_SHUTDOWN           17
#define MSRPC_PDU_CO_CANCEL          18
#define MSRPC_PDU_ORPHANED           19
#define MSRPC_PDU_RTS                20

/* RTS flags */
#define        RTS_FLAG_NONE                   0x0000
#define        RTS_FLAG_PING                   0x0001
#define        RTS_FLAG_OTHER_CMD              0x0002
#define        RTS_FLAG_RECYCLE_CHANNEL        0x0004
#define        RTS_FLAG_IN_CHANNEL             0x0008
#define        RTS_FLAG_OUT_CHANNEL            0x0010
#define        RTS_FLAG_EOF                    0x0020
#define        RTS_FLAG_ECHO                   0x0040

/* RTS client address type */
#define RTS_IPV4    0
#define RTS_IPV6    1

// See http://msdn.microsoft.com/en-us/library/cc243998.aspx
#define RTS_CMD_RECEIVE_WINDOW_SIZE        0
#define RTS_CMD_FLOW_CONTROL_ACK           1
#define RTS_CMD_CONNECTION_TIMEOUT         2
#define RTS_CMD_COOKIE                     3
#define RTS_CMD_CHANNEL_LIFETIME           4
#define RTS_CMD_CLIENT_KEEPALIVE           5
#define RTS_CMD_VERSION                    6
#define RTS_CMD_EMPTY                      7
#define RTS_CMD_PADDING                    8
#define RTS_CMD_NEGATIVE_ANCE              9
#define RTS_CMD_ANCE                     0xA
#define RTS_CMD_CLIENT_ADDRESS           0xB
#define RTS_CMD_ASSOCIATION_GROUPID      0xC
#define RTS_CMD_DESTINATION              0xD
#define RTS_CMD_PING_TRAFFIC_SENT_NOTIFY 0xE

#endif

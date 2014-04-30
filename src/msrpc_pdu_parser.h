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

#ifndef _MSRPC_PDU_PARSER_H_
#define _MSRPC_PDU_PARSER_H_

#include <apr_errno.h>
#include <uuid/uuid.h>

#define MSRPC_PDU_MINLENGTH  10    // we need at least 10 bytes to read the PDU length
#define MSRPC_PDU_MAXLENGTH 128    // in practice we haven't seen larger initial PDUs yet

typedef struct msrpc_rts_pdu msrpc_rts_pdu_t;

apr_status_t msrpc_pdu_get_length(const char *buf, apr_size_t *length);
apr_status_t msrpc_pdu_validate(const char *buf, const char **error);
apr_status_t msrpc_pdu_get_rts_pdu_count(const char *buf, uint16_t *count);
unsigned int msrpc_rts_pdu_len(const msrpc_rts_pdu_t *pdu, uint32_t data_representation);
apr_status_t msrpc_pdu_get_rts_pdu(const char *buf, unsigned int offset, msrpc_rts_pdu_t **rts_pdu, unsigned int *len);
const char *msrpc_pdu_get_name(const char *buf);
const char *msrpc_rts_pdu_get_command_name(msrpc_rts_pdu_t *pdu);

apr_status_t msrpc_rts_get_virtual_channel_cookie(const char *buf, uuid_t **cookie, const char **error);

#endif

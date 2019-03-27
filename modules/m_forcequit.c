/*
 * SporksIRCD: the ircd for discerning transsexual quilting bees.
 * m_forcequit.c: Forces a user to quit IRC. (debugged and fixed for sIRCd)
 *
 * Copyright (C) 2010 Elizabeth Jennifer Myers. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 4. You agree to use this for good and not evil. If you whine about this
 *    clause in any way, your licence to use this software is revoked.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "stdinc.h"
#include "client.h"
#include "hash.h"		/* for find_client() */
#include "numeric.h"
#include "logger.h"
#include "s_serv.h"
#include "s_conf.h"
#include "modules.h"
#include "s_newconf.h"


static int me_forcequit(struct Client *, struct Client *, int, const char **);
static int mo_forcequit(struct Client *, struct Client *, int, const char **);

struct Message forcequit_msgtab = {
    "FORCEQUIT", 0, 0, 0, MFLG_SLOW,
    {mg_unreg, mg_not_oper, mg_ignore, mg_ignore, {me_forcequit, 2}, {mo_forcequit, 2}}
};

mapi_clist_av1 forcequit_clist[] = { &forcequit_msgtab, NULL };

DECLARE_MODULE_AV1(forcequit, NULL, NULL, forcequit_clist, NULL, NULL, "SporksNet coding committee");

/*
** mo_forcequit
**      parv[1] = forcequit victim
**      parv[2] = forcequit reason
*/
static int
mo_forcequit(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    const char *user;
    const char *reason;
    int chasing = 0;

    user = parv[1];

    if(!IsOperAdmin(source_p)) {
        sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name);
        return 0;
    }

    if(!EmptyString(parv[2])) {
        char *s;
        s = LOCAL_COPY(parv[2]);
        if(strlen(s) > (size_t) REASONLEN)
            s[REASONLEN] = '\0';
        reason = s;
    } else
        reason = "Ping timeout: 245 seconds";

    if((target_p = find_chasing(source_p, user, &chasing)) == NULL)
        return 0;

    if(!MyConnect(target_p) && (!IsOper(source_p))) {
        sendto_one_notice(source_p, ":Nick %s is not on your server and you are not an Admin",
                          target_p->name);
        return 0;
    }

    sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
                           "Received FORCEQUIT message for %s!%s@%s. From %s (Reason: %s)",
                           target_p->name, target_p->username, target_p->orighost,
                           source_p->name, reason);
    /* Log it as a kill (a forcequit is just a kill with the reason hidden) */
    ilog(L_KILL, "FORCEQUIT called for [%s] by %s!%s@%s",
         target_p->name, source_p->name, source_p->username, source_p->host);


    target_p->flags |= FLAGS_NORMALEX;
    exit_client(client_p, target_p, target_p, reason);

    return 0;
}

/*
 * me_forcequit
 *      parv[1] = forcequit victim
 *      parv[2] = forcequit reason
 */
static int
me_forcequit(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    const char *user;
    const char *reason;
    int chasing = 0;

    user = parv[1];

    if(EmptyString(parv[2]))
        reason = "Exiting";
    else {
        char *s;
        s = LOCAL_COPY(parv[2]);
        if(strlen(s) > (size_t) REASONLEN)
            s[REASONLEN] = '\0';
        reason = s;
    }

    if((target_p = find_chasing(source_p, user, &chasing)) == NULL)
        return 0;

    if(IsServer(target_p) || IsMe(target_p))
        return 0;

    /* Log it as a kill (a forcequit is just a kill with the reason hidden) */
    ilog(L_KILL, "FORCEQUIT called for [%s] by %s!%s@%s",
         target_p->name, source_p->name, source_p->username, source_p->host);

    target_p->flags |= FLAGS_NORMALEX;
    exit_client(client_p, target_p, target_p, reason);

    return 0;
}



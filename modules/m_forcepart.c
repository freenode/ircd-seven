/*
 * SIRCd: the ircd for those who like unreal prefixes.
 * m_forcepart.c: Forces a user to part
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


static int mo_forcepart(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_forcepart(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

static void forcepart_channels(struct Client *client_p, struct Client *source_p, struct Client *target_p, const char *channels, const char *reason);


struct Message forcepart_msgtab = {
    "FORCEPART", 0, 0, 0, MFLG_SLOW,
    {mg_unreg, mg_not_oper, mg_ignore, mg_ignore, {me_forcepart, 2}, {mo_forcepart, 2}}
};

mapi_clist_av1 forcepart_clist[] = { &forcepart_msgtab, NULL };

DECLARE_MODULE_AV1(forcepart, NULL, NULL, forcepart_clist, NULL, NULL, "$Revision: 1 $");

/*
 * mo_forcepart
 *	parv[1] = forcepart victim
 *	parv[2] = channels to part
 *	parv[3] = reason
 */
static int
mo_forcepart(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    const char *user, *channels, *reason;
    const char default_reason[] = "Leaving";
    int chasing = 0;

    user = parv[1];
    channels = parv[2];

    if(!IsOper(source_p)) {
        sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name);
        return 0;
    }

    /* if target_p == NULL then let the oper know */
    if((target_p = find_chasing(source_p, user, &chasing)) == NULL) {
        sendto_one(source_p, form_str(ERR_NOSUCHNICK), me.name, source_p->name, user);
        return 0;
    }

    if(EmptyString(channels)) {
        sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "FORCEPART");
        return 0;
    }

    if(EmptyString(parv[3]))
        reason = default_reason;
    else {
        char *s;
        s = LOCAL_COPY(parv[3]);
        if(strlen(s) > (size_t) REASONLEN)
            s[REASONLEN] = '\0';
        reason = s;
    }

    if(!IsClient(target_p))
        return 0;

    if(!MyClient(target_p) && (!IsOperAdmin(source_p))) {
        sendto_one_notice(source_p, ":Nick %s is not on your server and you do not have admin priv",
                          target_p->name);
        return 0;
    }

    sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
                           "Received FORCEPART message for %s!%s@%s. From %s (Channels: %s)",
                           target_p->name, target_p->username, target_p->host, source_p->name, channels);
    ilog(L_MAIN, "FORCEPART called for %s %s by %s!%s@%s (part reason %s)",
         user, channels, source_p->name, source_p->username, source_p->host, reason);

    sendto_one_notice(target_p, ":You have been forced to part %s",
                      channels);

    if(!MyClient(target_p)) {
        struct Client *cptr = target_p->servptr;
        sendto_one(cptr, ":%s ENCAP %s FORCEPART %s :%s",
                   get_id(source_p, cptr), cptr->name, get_id(target_p, cptr), channels);
        return 0;
    }

    forcepart_channels(client_p, source_p, target_p, channels, reason);

    return 0;
}

static int
me_forcepart(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    const char *user, *channels, *reason;
    const char default_reason[] = "Leaving";
    int chasing = 0;

    user = parv[1];
    channels = parv[2];

    if(EmptyString(parv[2]))
        return 0;
    else
        channels = parv[2];

    if(EmptyString(parv[3]))
        reason = default_reason;
    else {
        char *s;
        s = LOCAL_COPY(parv[3]);
        if(strlen(s) > (size_t) REASONLEN)
            s[REASONLEN] = '\0';
        reason = s;
    }

    /* Find the user */
    if((target_p = find_chasing(source_p, user, &chasing)) == NULL)
        return 0;

    if(IsServer(target_p) || IsMe(target_p))
        return 0;

    ilog(L_MAIN, "FORCEPART called for [%s] by %s!%s@%s",
         target_p->name, source_p->name, source_p->username, source_p->host);

    if(!MyClient(target_p)) {
        struct Client *cptr = target_p->servptr;
        sendto_one(cptr, ":%s ENCAP %s FORCEPART %s :%s",
                   get_id(source_p, cptr), cptr->name, get_id(target_p, cptr), channels);
        return 0;
    }

    forcepart_channels(client_p, source_p, target_p, channels, reason);

    return 0;
}

static void
forcepart_channels(struct Client *client_p, struct Client *source_p, struct Client *target_p, const char *channels, const char *reason)
{
    struct Channel *chptr = NULL;
    struct membership *msptr = NULL;
    char *name;
    char *p = NULL;
    char *chanlist;

    chanlist = LOCAL_COPY(channels);
    for(name = rb_strtok_r(chanlist, ",", &p); name; name = rb_strtok_r(NULL, ",", &p)) {
        if((chptr = find_channel(name)) == NULL) {
            sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
                               form_str(ERR_NOSUCHCHANNEL), name);
            continue;
        }

        if((msptr = find_channel_membership(chptr, target_p)) == NULL) {
            sendto_one_numeric(source_p, ERR_USERNOTINCHANNEL,
                               form_str(ERR_USERNOTINCHANNEL),
                               target_p->name, name);
            continue;
        }

        sendto_server(target_p, chptr, NOCAPS, NOCAPS,
                      ":%s PART %s :%s", use_id(target_p), chptr->chname, reason);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s PART %s :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname, reason);

        remove_user_from_channel(msptr);
    }

    return;
}

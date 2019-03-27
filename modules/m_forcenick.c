/*
 * aspIRCd: the ircd for those who like unreal prefixes.
 * m_forcenick.c: Forces a user's nickname to change
 *
 * Copyright (C) 2010 Elizabeth Jennifer Myers. All rights reserved.
 * Copyright (C) 2019 David Franklin
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
#include "monitor.h"
#include "s_newconf.h"
#include "whowas.h"


static int me_forcenick(struct Client *, struct Client *, int, const char **);
static int mo_forcenick(struct Client *, struct Client *, int, const char **);

static int clean_nick(const char *nick);
static int change_nick(struct Client *client_p, const char *newnick);

struct Message forcenick_msgtab = {
    "FORCENICK", 0, 0, 0, MFLG_SLOW,
    {mg_unreg, mg_not_oper, mg_ignore, mg_ignore, {me_forcenick, 2}, {mo_forcenick, 2}}
};

mapi_clist_av1 forcenick_clist[] = { &forcenick_msgtab, NULL };

DECLARE_MODULE_AV1(forcenick, NULL, NULL, forcenick_clist, NULL, NULL, "$Revision: 1 $");

/*
** mo_forcenick
**      parv[1] = forcenick victim
**      parv[2] = new nickname
*/
static int
mo_forcenick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    const char *user;
    const char *newnick;
    int chasing = 0;

    user = parv[1];

    /* You must be this tall to ride the ride */
    if(!IsOper(source_p)) {
        sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name);
        return 0;
    }

    /* Truncate it so clean_nick doesn't spaz out */
    if(!EmptyString(parv[2])) {
        char *s;
        s = LOCAL_COPY(parv[2]);
        if(strlen(s) > (size_t) NICKLEN)
            s[NICKLEN] = '\0';
        newnick = s;
    } else {
        sendto_one_numeric(source_p, ERR_NONICKNAMEGIVEN, form_str(ERR_NONICKNAMEGIVEN),
                           me.name, source_p->name);
        return 0;
    }

    /* Nick has to be clean or we'll have a protocol violation... */
    if(!clean_nick(newnick)) {
        sendto_one(source_p, form_str(ERR_ERRONEUSNICKNAME),
                   me.name, user, newnick);
        return 0;
    }

    /* Find the target... */
    if((target_p = find_chasing(source_p, user, &chasing)) == NULL)
        return 0;

    /* If it's a server, sod it, changing its name is stupid... */
    if(IsServer(target_p) || IsMe(target_p)) {
        sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), user);
        return 0;
    }

    /* Do we have permission to send it globally? */
    if(!MyClient(target_p) && (!IsOperAdmin(source_p))) {
        sendto_one_notice(source_p, ":Nick %s is not on your server and you are not admin",
                          target_p->name);
        return 0;
    }

    /* Check to see if the new nick exists */
    if(find_named_person(newnick) != NULL) {
        int result = irccmp(target_p->name, newnick);

        /* Check for a case shift */
        if(result != 0) {
            sendto_one(source_p, form_str(ERR_NICKNAMEINUSE),
                       me.name, user, newnick);
            return 0;
        }
        /* If it's the same nick, fuck it */
        else if(strcmp(target_p->name, newnick) == 0) {
            sendto_one_notice(source_p, ":I'm not forcenicking %s to the same nick",
                              target_p->name);
            return 0;
        }
    }

    sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
                           "Received FORCENICK message for %s!%s@%s. From %s (Newnick: %s)",
                           target_p->name, target_p->username, target_p->orighost,
                           source_p->name, newnick);
    ilog(L_MAIN, "FORCENICK called for [%s] by %s!%s@%s",
         target_p->name, source_p->name, source_p->username, source_p->host);

    sendto_one_notice(target_p, ":You have been forcenicked from %s to %s",
                      target_p->name, newnick);

    if(!MyClient(target_p)) {
        struct Client *cptr = target_p->servptr;
        sendto_one(cptr, ":%s ENCAP %s FORCENICK %s :%s",
                   get_id(source_p, cptr), cptr->name, get_id(target_p, cptr), newnick);
    } else
        change_nick(target_p, newnick);

    return 0;
}

/*
 * me_forcenick
 *      parv[1] = forcenick victim
 *      parv[2] = new nickname
 */
static int
me_forcenick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    const char *user;
    const char *newnick;
    int chasing = 0;

    user = parv[1];

    /* We're supposed to drop servers over protocol violations, but shit happens... */

    if(EmptyString(parv[2]))
        return 0;
    else {
        char *s;
        s = LOCAL_COPY(parv[2]);
        if(strlen(s) > (size_t) NICKLEN)
            s[NICKLEN] = '\0';
        newnick = s;
    }

    if(!clean_nick(newnick))
        return 0;

    if((target_p = find_person(user)) == NULL)
        return 0;

    if(IsServer(target_p) || IsMe(target_p))
        return 0;

    if(!MyClient(target_p) && !IsOperAdmin(source_p))
        return 0;

    if((target_p = find_chasing(source_p, user, &chasing)) == NULL) {
        int result = irccmp(target_p->name, newnick);

        /* Check for a case shift */
        if(result != 0)
            return 0;
        /* If it's the same nick, fuck it */
        else if(strcmp(target_p->name, newnick) == 0)
            return 0;
    }

    ilog(L_MAIN, "FORCENICK called for [%s] by %s!%s@%s",
         target_p->name, source_p->name, source_p->username, source_p->host);

    if(!MyClient(target_p)) {
        struct Client *cptr = target_p->servptr;
        sendto_one(cptr, ":%s ENCAP %s FORCENICK %s :%s",
                   get_id(source_p, cptr), cptr->name, get_id(target_p, cptr), newnick);
        return 0;
    }

    change_nick(target_p, newnick);

    return 0;
}

static int
clean_nick(const char *nick)
{
    int len = 0;

    if(EmptyString(nick) || *nick == '-' || IsDigit(*nick))
        return 0;

    for(; *nick; nick++) {
        len++;
        if(!IsNickChar(*nick))
            return 0;
    }

    if(len >= NICKLEN)
        return 0;

    return 1;
}


static int
change_nick(struct Client *client_p, const char *newnick)
{
    char note[NICKLEN + 10];

    client_p->tsinfo = rb_current_time();

    monitor_signoff(client_p);

    invalidate_bancache_user(client_p);

    sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
                           "Forced nick change: From %s to %s [%s@%s]",
                           client_p->name, newnick, client_p->username,
                           client_p->host);

    sendto_common_channels_local(client_p, NOCAPS, ":%s!%s@%s NICK :%s",
                                 client_p->name, client_p->username,
                                 client_p->host, newnick);

    add_history(client_p, 1);
    sendto_server(NULL, NULL, CAP_TS6, NOCAPS, ":%s NICK %s :%ld",
                  use_id(client_p), newnick, (long) client_p->tsinfo);

    del_from_client_hash(client_p->name, client_p);
    strcpy(client_p->name, newnick);
    add_to_client_hash(client_p->name, client_p);

    monitor_signon(client_p);

    del_all_accepts(client_p);

    rb_snprintf(note, NICKLEN + 10, "Nick: %s", client_p->name);
    rb_note(client_p->localClient->F, note);
    return 0;
}

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_newconf.h"
#include "numeric.h"
#include "s_serv.h"
#include "s_conf.h"
#include "listener.h"

static int mo_listenoff(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_listenoff(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message listenoff_msgtab = {
  "LISTENOFF", 0, 0, 0, MFLG_SLOW,
  { mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_listenoff, 0}, {mo_listenoff, 0}
  }
};

mapi_clist_av1 listenoff_clist[] = { &listenoff_msgtab, NULL };


DECLARE_MODULE_AV1(listenoff, NULL, NULL, listenoff_clist, NULL, NULL, "Revision 0.42");


static int
mo_listenoff(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    const char *target_server;

    if (!HasPrivilege(source_p, "oper:admin"))
    {
        sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "admin");
        return 0;
    }

    if (parc > 1)
    {
        target_server = parv[1];
        sendto_match_servs(source_p, target_server, CAP_ENCAP, NOCAPS,
                "ENCAP %s LISTENOFF", target_server);

        if (match(target_server, me.name) == 0)
            return 0;
    }
    sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is closing listeners.", get_oper_name(source_p));
    close_listeners();
    sendto_one_notice(source_p, ":*** Listeners have been closed.");

    return 0;
}

static int
me_listenoff(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is closing listeners.", get_oper_name(source_p));
    close_listeners();
    sendto_one_notice(source_p, ":*** Listeners have been closed.");

    return 0;
}


#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "hook.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "hostmask.h"

static int _modinit(void);
static void _moddeinit(void);
static void h_bk_burst_finished(hook_data_client *);

mapi_hfn_list_av1 bk_hfnlist[] = {
	{ "burst_finished", (hookfn) h_bk_burst_finished },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(checkremotekline, _modinit, _moddeinit, NULL, NULL, bk_hfnlist, "$Revision: 1869 $");

static char *fake_oper_uid = NULL;

static int
_modinit(void)
{
	fake_oper_uid = rb_strdup(generate_uid());
	return 0;
}

static void
_moddeinit(void)
{
	rb_free(fake_oper_uid);
	fake_oper_uid = NULL;
}

static void
h_bk_burst_finished(hook_data_client *data)
{
	struct Client *server = data->client;
	struct AddressRec *arec;
	struct ConfItem *aconf = NULL;
	rb_dlink_node *ptr;
	int i;

	sendto_one(server, ":%s UID %s %d %ld %s %s %s %s %s :%s",
		me.id, fake_oper_uid, 1, (long)rb_current_time(), "+o",
		"internal", me.name, "0", fake_oper_uid, "internal");

	for (i = 0; i < ATABLE_SIZE; i++)
	{
		for (arec = atable[i]; arec; arec = arec->next)
		{
			if (arec->type == CONF_KILL)
			{
				aconf = arec->aconf;

				if (aconf->flags & CONF_FLAGS_TEMPORARY)
					continue;

				sendto_one(server, ":%s KLINE * 0 %s %s :%s%s%s",
					fake_oper_uid, aconf->user, aconf->host,
					aconf->passwd, aconf->spasswd ? "|" : "",
					aconf->spasswd ? aconf->spasswd : "");
			}
		}
	}
	for (i = 0; i < LAST_TEMP_TYPE; i++)
	{
		RB_DLINK_FOREACH(ptr, temp_klines[i].head)
		{
			aconf = ptr->data;

			/* Don't burst klines that are about to expire */
			if(aconf->hold < rb_current_time() + 60)
				continue;

			sendto_one(server, ":%s KLINE * %ld %s %s :%s%s%s",
					fake_oper_uid, aconf->hold - rb_current_time(),
					aconf->user, aconf->host,
					aconf->passwd, aconf->spasswd ? "|" : "",
					aconf->spasswd ? aconf->spasswd : "");
		}
	}

	sendto_one(server, ":%s QUIT :", fake_oper_uid);
}


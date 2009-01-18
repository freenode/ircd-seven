#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "hook.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "hostmask.h"
#include "s_newconf.h"
#include "hash.h"

static void _moddeinit(void);
static void h_bk_burst_finished(hook_data_client *);

mapi_hfn_list_av1 bk_hfnlist[] = {
	{ "burst_finished", (hookfn) h_bk_burst_finished },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(checkremotekline, NULL, _moddeinit, NULL, NULL, bk_hfnlist, "$Revision: 1869 $");

static char *fake_oper_uid = NULL;

static void send_klines(struct Client *);
static void send_xlines(struct Client *);
static void send_resvs (struct Client *);

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

	/* This has to be done here and not in _modinit because the latter
	 * might get called before our SID is known.
	 */
	if (fake_oper_uid == NULL)
		fake_oper_uid = rb_strdup(generate_uid());

	sendto_one(server, ":%s UID %s %d %ld %s %s %s %s %s :%s",
		me.id, fake_oper_uid, 1, (long)rb_current_time(), "+o",
		"internal", me.name, "0", fake_oper_uid, "internal");

	send_klines(server);
	send_xlines(server);
	send_resvs(server);

	sendto_one(server, ":%s QUIT :", fake_oper_uid);
}


static void
send_klines(struct Client *server)
{
	struct AddressRec *arec;
	struct ConfItem *aconf = NULL;
	rb_dlink_node *ptr;
	int i;

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
}

static void
send_resvs(struct Client *server)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;
	int i;

	RB_DLINK_FOREACH(ptr, resv_conf_list.head)
	{
		aconf = ptr->data;
		if (aconf->hold)
		{
			if(aconf->hold < rb_current_time() + 60)
				continue;
			
			sendto_one(server, ":%s ENCAP * RESV %ld %s 0 :%s",
					fake_oper_uid, aconf->hold - rb_current_time(),
					aconf->name, aconf->passwd);
		}
		else
			sendto_one(server, ":%s ENCAP * RESV 0 %s 0 :%s",
					fake_oper_uid, aconf->name, aconf->passwd);
	}

	HASH_WALK(i, R_MAX, ptr, resvTable)
	{
		aconf = ptr->data;
		if (aconf->hold)
		{
			if(aconf->hold < rb_current_time() + 60)
				continue;
			
			sendto_one(server, ":%s ENCAP * RESV %ld %s 0 :%s",
					fake_oper_uid, aconf->hold - rb_current_time(),
					aconf->name, aconf->passwd);
		}
		else
			sendto_one(server, ":%s ENCAP * RESV 0 %s 0 :%s",
					fake_oper_uid, aconf->name, aconf->passwd);
	}
	HASH_WALK_END

}

static const char *expand_xline(const char *mask)
{
	static char buf[512];
	const char *p;
	char *q;

	if (!strchr(mask, ' '))
		return mask;
	if (strlen(mask) > 250)
		return NULL;
	p = mask;
	q = buf;
	while (*p != '\0')
	{
		if (*p == ' ')
			*q++ = '\\', *q++ = 's';
		else
			*q++ = *p;
		p++;
	}
	*q = '\0';
	return buf;
}

static void
send_xlines(struct Client *server)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;
	const char *mask2;

	RB_DLINK_FOREACH(ptr, xline_conf_list.head)
	{
		aconf = ptr->data;
		mask2 = expand_xline(aconf->name);
		if (mask2 == NULL)
		{
			sendto_realops_snomask(SNO_DEBUG, L_NETWIDE,
					"Not bursting xline [%s]",
					aconf->name);
			continue;
		}
		if (aconf->hold)
		{
			if(aconf->hold < rb_current_time() + 60)
				continue;
			
			sendto_one(server, ":%s ENCAP * XLINE %ld %s 2 :%s",
					fake_oper_uid, aconf->hold - rb_current_time(),
					mask2, aconf->passwd);
		}
		else
			sendto_one(server, ":%s ENCAP * XLINE 0 %s 2 :%s",
					fake_oper_uid, mask2, aconf->passwd);
	}

}

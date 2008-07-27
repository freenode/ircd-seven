/*
 * Copyright (C) 2006 Jilles Tjoelker
 * Copyright (C) 2006 Stephen Bennett <spb@gentoo.org>
 *
 * $Id$
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_user.h"
#include "s_serv.h"
#include "s_conf.h"
#include "s_newconf.h"

static int mo_grant(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_grant(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

static int do_grant(struct Client *source_p, struct Client *target_p, int addflags, int removeflags,
		int dooper, int dodeoper);

struct Message grant_msgtab = {
  "GRANT", 0, 0, 0, MFLG_SLOW,
  { mg_ignore, mg_not_oper, mg_ignore, mg_ignore, {me_grant, 4}, {mo_grant, 3}}
};

mapi_clist_av1 grant_clist[] = { &grant_msgtab, NULL };

DECLARE_MODULE_AV1(grant, NULL, NULL, grant_clist, NULL, NULL, "$Revision$");

/* copied from src/newconf.c */
struct mode_table
{
	const char *name;
	int mode;
};

extern struct mode_table flag_table[];

static int
mo_grant(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	int addflags = 0, removeflags = 0;
	int dooper = 0, dodeoper = 0;
	int i, j;
	int dir;
	const char *p;
	char *q;
	char oper_flag_changes[32];

	if(!IsOperGrant(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "grant");
		return 0;
	}

	target_p = find_named_person(parv[1]);
	if (target_p == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				form_str(ERR_NOSUCHNICK), parv[1]);
		return 0;
	}

	for (i = 2; i < parc; i++)
	{
		p = parv[i];
		if (*p == '-')
			dir = MODE_DEL, p++;
		else if (*p == '+')
			dir = MODE_ADD, p++;
		else
			dir = MODE_ADD;
		if (!irccmp(p, "oper"))
		{
			if (dir == MODE_ADD)
				dooper = 1, dodeoper = 0;
			else
				dodeoper = 1, dooper = 0;
			continue;
		}

		for (j = 0; flag_table[j].name != NULL; j++)
		{
			if (!irccmp(p, flag_table[j].name))
			{
				if (dir == MODE_ADD)
					addflags |= flag_table[j].mode, removeflags &= ~flag_table[j].mode;
				else
					removeflags |= flag_table[j].mode, addflags &= ~flag_table[j].mode;
				break;
			}
		}
		if (flag_table[j].name == NULL)
		{
			sendto_one_notice(source_p, ":Unknown GRANT keyword '%s'", p);
			return 0;
		}
	}

	if (((addflags | removeflags) & source_p->operflags) != (addflags | removeflags))
	{
		sendto_one_notice(source_p, ":You may not change flags you do not have access to");
		return 0;
	}

	if (addflags & OPER_GRANT)
	{
		sendto_one_notice(source_p, ":You may not grant the grant flag.");
		return 0;
	}

	if (((addflags & OPER_STAFFER && IsHelper(target_p)) ||
	     (removeflags & OPER_STAFFER && IsOper(target_p))) &&
	    !dodeoper)
	{
		/* Change from +O to +o or vice versa -- needs deoper and reoper. */
		dooper = 1;
		dodeoper = 1;
	}

	if (MyClient(target_p))
	{
		do_grant(source_p, target_p, addflags, removeflags, dooper, dodeoper);
	}
	else
	{
		q = oper_flag_changes;

		for (i = 0; oper_flagtable[i].flag; ++i)
		{
			if (addflags & oper_flagtable[i].flag)
				*q++ = oper_flagtable[i].has;
			else if (removeflags & oper_flagtable[i].flag)
				*q++ = oper_flagtable[i].hasnt;
		}
		if(q == oper_flag_changes)
			*q++ = '.';
		*q++ = '\0';

		sendto_one(target_p, ":%s ENCAP %s GRANT %s %s %d %d",
				get_id(source_p, target_p), target_p->servptr->name,
				get_id(target_p, target_p), oper_flag_changes, dooper, dodeoper);
	}

	return 0;
}

static int me_grant(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	int addflags = 0, removeflags = 0, dooper = 0, dodeoper = 0;
	int i = 0;
	const char *p;

	target_p = find_person(parv[1]);
	if (target_p == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				form_str(ERR_NOSUCHNICK), parv[1]);
		return 0;
	}

	if(!find_shared_conf(source_p->username, source_p->host,
				source_p->user->server, SHARED_GRANT))
	{
		sendto_one(source_p, ":%s NOTICE %s :*** You don't have an appropriate shared"
			"block to grant privilege on this server.", me.name, source_p->name);
		return 0;
	}

	p = parv[2];

	for (i = 0; oper_flagtable[i].flag; ++i)
	{
		if (*p == oper_flagtable[i].has)
			addflags |= oper_flagtable[i].flag;
		else if (*p == oper_flagtable[i].hasnt)
			removeflags |= oper_flagtable[i].flag;
		else if (*p == '\0' || *p == '.')
			break;
		else
			continue;
		++p;
	}

	dooper = atoi(parv[3]);
	dodeoper = atoi(parv[4]);

	do_grant(source_p, target_p, addflags, removeflags, dooper, dodeoper);

	return 0;
}


static int do_grant(struct Client *source_p, struct Client *target_p, int addflags, int removeflags,
		int dooper, int dodeoper)
{
	const char *newparv[4];
	struct oper_conf oper;
	int changes = 0;
	/* If we deoper then reoper as part of this, we need to make sure to add in the oper's
	 * original flags. However, the snotes should only notify of actual changes. 
	 */
	int addflags2 = addflags;
	char desc[512];
	int j;
	char oper_name[NICKLEN+1];

	/* If the target is already opered, we should preserve their original opername
	 * instead of clobbering it with <grant> on de/reoper to change between +O/+o
	 */
	if(!EmptyString(target_p->user->opername))
		strlcpy(oper_name, target_p->user->opername, sizeof(oper_name));
	else
		strlcpy(oper_name, "<grant>", sizeof(oper_name));

	if (dodeoper && dooper)
		addflags2 = (addflags | target_p->operflags) & ~removeflags;

	if (dodeoper)
	{
		if (!IsAnyOper(target_p))
			sendto_one_notice(source_p, ":%s is not an oper",
					target_p->name);
		else
		{
			newparv[0] = target_p->name;
			newparv[1] = target_p->name;
			newparv[2] = "-oO";
			newparv[3] = NULL;
			if(!dooper)
			{
				sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
						"%s is deopering %s",
						get_oper_name(source_p),
						get_client_name(target_p, HIDE_IP));
				sendto_one_notice(target_p, ":%s is deopering you",
						source_p->name);
			}

			user_mode(target_p, target_p, 3, newparv);

			if(!dooper)
				sendto_one_notice(source_p, ":Deopered %s", target_p->name);
			changes++;
		}
	}

	if (dooper)
	{
		if (IsAnyOper(target_p))
			sendto_one_notice(source_p, ":%s is already an oper",
					target_p->name);
		else
		{
			desc[0] = '\0';
			for (j = 0; flag_table[j].name != NULL; j++)
			{
				if ((addflags2 & flag_table[j].mode) == flag_table[j].mode)
				{
					if (desc[0] != '\0')
						strlcat(desc, " ", sizeof desc);
					strlcat(desc, "+", sizeof desc);
					strlcat(desc, flag_table[j].name, sizeof desc);
				}
			}
			if (desc[0] == '\0')
				strlcpy(desc, "<none>", sizeof desc);
			oper.name = oper_name;
			oper.username = "";
			oper.host = "";
			oper.passwd = "";
			oper.flags = addflags2;
			oper.umodes = 0;
			oper.snomask = 0;
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
					"%s is opering %s with flags %s",
					get_oper_name(source_p),
					get_client_name(target_p, HIDE_IP),
					desc);

			if(!dodeoper)
				sendto_one_notice(target_p, ":%s is opering you",
						source_p->name);

			oper_up(target_p, &oper);

			if(!dodeoper)
				sendto_one_notice(source_p, ":Opered %s with flags %s",
						target_p->name, desc);
			changes++;
		}
	}
	removeflags &= target_p->operflags;
	addflags &= ~target_p->operflags;
	if ((addflags | removeflags) != 0)
	{
		if (!IsAnyOper(target_p))
		{
			sendto_one_notice(source_p, ":%s is not an oper",
					target_p->name);
		}
		else
		{
			target_p->operflags |= addflags;
			target_p->operflags &= ~removeflags;
			desc[0] = '\0';
			for (j = 0; flag_table[j].name != NULL; j++)
			{
				if ((addflags & flag_table[j].mode) == flag_table[j].mode)
				{
					if (desc[0] != '\0')
						strlcat(desc, " ", sizeof desc);
					strlcat(desc, "+", sizeof desc);
					strlcat(desc, flag_table[j].name, sizeof desc);
				}
				else if ((removeflags & flag_table[j].mode) == flag_table[j].mode)
				{
					if (desc[0] != '\0')
						strlcat(desc, " ", sizeof desc);
					strlcat(desc, "-", sizeof desc);
					strlcat(desc, flag_table[j].name, sizeof desc);
				}
			}
			if(desc[0] == '\0')
				strlcpy(desc, "<none>", sizeof desc);
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
					"%s is changing oper flags on %s (%s)",
					get_oper_name(source_p),
					get_client_name(target_p, HIDE_IP),
					desc);
			sendto_one_notice(target_p, ":%s is changing oper flags on you: %s",
					source_p->name, desc);
			sendto_one_notice(source_p, ":Changed oper flags on %s: %s",
					target_p->name, desc);

			sendto_server(source_p, NULL, NOCAPS, NOCAPS, ":%s ENCAP * OPER %s",
					get_id(target_p, target_p), get_oper_privs(target_p->operflags));

			/* fix up any umodes/snomasks they may not have
			 * anymore */
			newparv[0] = target_p->name;
			newparv[1] = target_p->name;
			newparv[2] = "+";
			newparv[3] = NULL;
			user_mode(target_p, target_p, 3, newparv);
			changes++;
		}
	}
	if (!changes)
		sendto_one_notice(source_p, ":Oper flags on %s unchanged",
				target_p->name);

	return 0;
}

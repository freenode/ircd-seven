/*
 *  ircd-seven: A slightly useful ircd.
 *  identify_msg.c: implements the necessary logic to handle the IDMSG
 *  user flag, used to implement the IDENTIFY-MSG client capability.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2006 ircd-ratbox development team
 *  Copyright (C) 2006 ircd-seven development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *  $Id: $
 */

#include "stdinc.h"
#include "client.h"
#include "modules.h"
#include "send.h"
#include "numeric.h"

static int me_identified(struct Client *, struct Client *, int, const char **);

static void h_im_nick_change(void *vdata);
static void h_im_burst_client(void *vdata);

struct Message identified_msgtab = {
	"IDENTIFIED", 0, 0, 0, MFLG_SLOW,
	{ mg_unreg, mg_ignore, mg_ignore, mg_ignore, {me_identified, 3}, mg_ignore}
};

mapi_hfn_list_av1 im_hfnlist[] = {
	{ "local_nick_change", (hookfn) h_im_nick_change },
	{ "remote_nick_change", (hookfn) h_im_nick_change },
	{ "burst_client", (hookfn) h_im_burst_client },
	{ NULL, NULL }
};

mapi_clist_av1 identified_clist[] = { &identified_msgtab, NULL };

DECLARE_MODULE_AV1(identify_msg, NULL, NULL, identified_clist, NULL, im_hfnlist, "$Revision: $");

static int
me_identified(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p = find_person(parv[1]);
	const char *nick = parv[2];

	if(target_p == NULL)
	{
		return 0;
	}

	if (irccmp(target_p->name, nick))
	{
		sendto_realops_snomask(SNO_DEBUG, L_ALL,
			"Dropping IDENTIFIED for %s due to nickname mismatch (%s)",
			target_p->name, nick);
		return 0;
	}

	if (parc > 3 && !irccmp(parv[3], "OFF"))
		ClearIdentifiedMsg(target_p);
	else
		SetIdentifiedMsg(target_p);

	return 0;
}

static void
h_im_nick_change(void *vdata)
{
	hook_data *data = vdata;
	if(data->client && 0 != irccmp(data->arg1, data->arg2))
		ClearIdentifiedMsg(data->client);
}

static void
h_im_burst_client(void *vdata)
{
	hook_data_client *data = vdata;
	struct Client *server = data->client;
	struct Client *target_p = data->target;

	if(IsIdentifiedMsg(target_p))
	    sendto_one(server, ":%s ENCAP * IDENTIFIED %s %s", me.id, use_id(target_p), target_p->name);
}


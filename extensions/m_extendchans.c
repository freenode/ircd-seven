/*
 *  ircd-seven: A slightly useful ircd.
 *  m_extendchans.c: Allow an oper or service to let a given user join more channels.
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

static int me_extendchans(struct Client *, struct Client *, int, const char **);

struct Message extendchans_msgtab = {
	"EXTENDCHANS", 0, 0, 0, MFLG_SLOW,
	{ mg_unreg, mg_ignore, mg_ignore, mg_ignore, {me_extendchans, 1}, mg_ignore}
};

mapi_clist_av1 extendchans_clist[] = { &extendchans_msgtab, NULL };

DECLARE_MODULE_AV1(extendchans, NULL, NULL, extendchans_clist, NULL, NULL, "$Revision: $");

static int
me_extendchans(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;

	target_p = find_person(parv[1]);
	if(target_p == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), parv[1]);
		return 0;
	}

	if(!MyClient(target_p))
		return 0;

	sendto_one_notice(target_p, ":*** %s is extending your channel limit", source_p->name);
	SetExtendChans(target_p);

	return 0;
}

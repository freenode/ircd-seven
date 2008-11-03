#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "numeric.h"
#include "chmode.h"
#include "s_newconf.h"

static void can_kick(hook_data_channel_approval *);

mapi_hfn_list_av1 nooperkick_hfnlist[] = {
	{ "can_kick", (hookfn) can_kick },
	{ NULL, NULL }
};

static int
_modinit(void)
{
	chmode_table['M'].mode_type = find_cflag_slot();
	chmode_table['M'].set_func = chm_staff;

	construct_noparam_modes();

	return 0;
}

static void
_moddeinit(void)
{
	chmode_table['M'].mode_type = 0;

	construct_noparam_modes();
}

DECLARE_MODULE_AV1(chm_no_oper_kick, _modinit, _moddeinit, NULL, NULL, nooperkick_hfnlist, "$Revision$");

static void
can_kick(hook_data_channel_approval *data)
{
	struct Client *source_p = data->client;
	struct Client *target_p = data->target;
	struct Channel *chptr = data->chptr;

	if ((chptr->mode.mode & chmode_flags['M']) && IsOper(target_p) && data->approved) {
		sendto_one_numeric(source_p, ERR_ISCHANSERVICE,
				"%s %s :Cannot kick IRC operators from this channel.",
				target_p->name, chptr->chname);
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "Overriding KICK from %s on %s in %s (channel is +M)",
			source_p->name, target_p->name, chptr->chname);
		data->approved = 0;
	}

	if (target_p->umodes & UMODE_OVERRIDE && data->approved)
	{
		sendto_one_numeric(source_p, ERR_ISCHANSERVICE,
				"%s %s :User is immune from kick.",
				target_p->name, chptr->chname);
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "Overriding KICK from %s on %s in %s (user is immune)",
			source_p->name, target_p->name, chptr->chname);
		data->approved = 0;
	}
}

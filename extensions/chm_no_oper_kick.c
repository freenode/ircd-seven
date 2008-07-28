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

static void chm_nooperkick(struct Client *source_p, struct Channel *chptr,
		int alevel, int parc, int *parn, const char **parv,
		int *errors, int dir, char c, long mode_type);

mapi_hfn_list_av1 nooperkick_hfnlist[] = {
	{ "can_kick", (hookfn) can_kick },
	{ NULL, NULL }
};

static int
_modinit(void)
{
	chmode_table['M'].mode_type = find_cflag_slot();
	chmode_table['M'].set_func = chm_nooperkick;

	construct_noparam_modes();

	return 0;
}

static void
_moddeinit(void)
{
	chmode_table['M'].mode_type = 0;

	construct_noparam_modes();
}

DECLARE_MODULE_AV1(chm_operonly, _modinit, _moddeinit, NULL, NULL, nooperkick_hfnlist, "$Revision$");

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
		data->approved = 0;
	}
}

/* Fairly ugly. Copied from chmode.c. */
#define SM_ERR_NOPRIVS          0x00000400
#define MAXMODES_SIMPLE 46 /* a-zA-Z except bqeIov */
extern struct ChModeChange mode_changes[BUFSIZE];
extern int mode_count;
extern int mode_limit;
extern int mode_limit_simple;
extern int mask_pos;


static void
chm_nooperkick(struct Client *source_p, struct Channel *chptr,
		int alevel, int parc, int *parn, const char **parv,
		int *errors,int dir, char c, long mode_type)
{
	if(!IsOper(source_p) && !IsServer(source_p))
	{
		if(!(*errors & SM_ERR_NOPRIVS))
			sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		*errors |= SM_ERR_NOPRIVS;
		return;
	}
	if(MyClient(source_p) && !IsOperImmune(source_p))
	{
		if(!(*errors & SM_ERR_NOPRIVS))
			sendto_one(source_p, form_str(ERR_NOPRIVS), me.name,
					source_p->name, "immune");
		*errors |= SM_ERR_NOPRIVS;
		return;
	}

	if(MyClient(source_p) && (++mode_limit_simple > MAXMODES_SIMPLE))
		return;

	/* setting + */
	if((dir == MODE_ADD) && !(chptr->mode.mode & mode_type))
	{
		chptr->mode.mode |= mode_type;

		mode_changes[mode_count].letter = c;
		mode_changes[mode_count].dir = MODE_ADD;
		mode_changes[mode_count].caps = 0;
		mode_changes[mode_count].nocaps = 0;
		mode_changes[mode_count].id = NULL;
		mode_changes[mode_count].mems = ALL_MEMBERS;
		mode_changes[mode_count++].arg = NULL;
	}
	else if((dir == MODE_DEL) && (chptr->mode.mode & mode_type))
	{
		chptr->mode.mode &= ~mode_type;

		mode_changes[mode_count].letter = c;
		mode_changes[mode_count].dir = MODE_DEL;
		mode_changes[mode_count].caps = 0;
		mode_changes[mode_count].nocaps = 0;
		mode_changes[mode_count].mems = ALL_MEMBERS;
		mode_changes[mode_count].id = NULL;
		mode_changes[mode_count++].arg = NULL;
	}
}



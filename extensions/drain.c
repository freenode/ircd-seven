#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"

static void check_new_user(void *data);
mapi_hfn_list_av1 drain_hfnlist[] = {
	{ "new_local_user", (hookfn) check_new_user },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(drain, NULL, NULL, NULL, NULL,
			drain_hfnlist, "1.0.0");


static void
check_new_user(void *vdata)
{
	struct Client *source_p = vdata;

	if(IsExemptKline(source_p))
		return;

	exit_client(source_p, source_p, &me,
			"This server is not accepting new connections. Please connect to \002chat.freenode.net\002 instead.");
}

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "hook.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_newconf.h"

static void h_hints_channel_join(hook_data_channel_activity *);

mapi_hfn_list_av1 hints_hfnlist[] = {
        { "channel_join", (hookfn) h_hints_channel_join },
        { NULL, NULL }
};

DECLARE_MODULE_AV1(hints, NULL, NULL, NULL, NULL, hints_hfnlist, "$Revision: 3219 $");

static int hints_probability = 5; // * 1/100

typedef struct {
    const char *text;
    const char *hostmask;
    int registered;
    int unregistered;
} hint;

static hint hints[] = {
    {
        "[freenode-info] channel flooding and no channel staff around to help? Please check with freenode support: http://freenode.net/faq.shtml#gettinghelp",
        NULL,
        1,
        1
    },
    {
        "[freenode-info] channel trolls and no channel staff around to help? please check with freenode support: http://freenode.net/faq.shtml#gettinghelp",
        NULL,
        1,
        1,
    },
    {
        "[freenode-info] if you're at a conference and other people are having trouble connecting, please mention it to staff: http://freenode.net/faq.shtml#gettinghelp",
        NULL,
        1,
        1
    },
    {
        "[freenode-info] why register and identify? your IRC nick is how people know you. http://freenode.net/faq.shtml#nicksetup",
        NULL,
        0,
        1
    },
    {
        "[freenode-info] please register your nickname...don't forget to auto-identify! http://freenode.net/faq.shtml#nicksetup",
        NULL,
        0,
        1,
    },
    {
        "[freenode-info] help freenode weed out clonebots -- please register your IRC nick and auto-identify: http://freenode.net/faq.shtml#nicksetup",
        NULL,
        0,
        1
    }
};


static void
h_hints_channel_join(hook_data_channel_activity *data)
{
    if (hints_probability < rand() % 100)
        return;

    char nuh[BUFSIZE];
    snprintf(nuh, BUFSIZE, "%s!%s@%s", data->client->name, data->client->username, data->client->host);

    hint* applicable[sizeof(hints)/sizeof(hint)];
    memset(&applicable[0], 0, sizeof(applicable));

    int i = 0, a = 0;

    for (; i < sizeof(hints)/sizeof(hint); ++i)
    {
        if (hints[i].hostmask && 0 != match(hints[i].hostmask, nuh))
            continue;
        int registered = !EmptyString(data->client->user->suser);

        if ( ( registered && !hints[i].registered) ||
             (!registered && !hints[i].unregistered))
            continue;

        applicable[a++] = &hints[i];
    }

    int tosend = rand() % a;

    sendto_one(data->client, ":%s NOTICE %s :%s", me.name, data->chptr->chname, applicable[tosend]->text);
}


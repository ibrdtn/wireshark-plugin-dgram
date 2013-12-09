#include "config.h"
#include "packet-dgram.h"
#include <gmodule.h>

G_MODULE_EXPORT const gchar version[] = PACKAGE_VERSION;

G_MODULE_EXPORT void
plugin_register(void)
{
	proto_register_dgram();
}

G_MODULE_EXPORT void
plugin_reg_handoff(void)
{
	{extern void proto_reg_handoff_dgram (void); proto_reg_handoff_dgram ();}
}

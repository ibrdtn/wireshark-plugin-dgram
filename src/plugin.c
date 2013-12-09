#include "config.h"
#include "packet-dgram.h"
#include <gmodule.h>

G_MODULE_EXPORT const gchar version[] = PACKAGE_VERSION;

G_MODULE_EXPORT
void plugin_register (void)
{
	proto_register_dgram();
}

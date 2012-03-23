#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#include <gmodule.h>

/* Included *after* config.h, in order to re-define these macros */
#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "nfc-wireshark"

#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */
#define VERSION "0.8.0"

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;

G_MODULE_EXPORT void plugin_register(void) {
  extern void proto_register_llcp(void);
  extern void proto_register_snep(void);
  extern void proto_register_ndef(void);
  proto_register_llcp();
  proto_register_ndef();
  proto_register_snep();
}

G_MODULE_EXPORT void plugin_reg_handoff(void) {
  extern void proto_reg_handoff_llcp(void);
  extern void proto_reg_handoff_snep(void);
  extern void proto_reg_handoff_ndep(void);
  proto_reg_handoff_llcp();
  proto_reg_handoff_snep();
  proto_reg_handoff_ndef();
}
#endif

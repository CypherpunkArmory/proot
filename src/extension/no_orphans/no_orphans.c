/*
 * no_orphans extension: calls prctl(PR_SET_CHILD_SUBREAPER) so that when
 * any tracee's parent exits, the kernel reparents that tracee to PRoot
 * rather than to init (PID 1).
 */

#include <sys/prctl.h>

#include "extension/extension.h"

int no_orphans_callback(Extension *extension UNUSED, ExtensionEvent event,
			intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
	if (event == INITIALIZATION)
		(void)prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
	return 0;
}

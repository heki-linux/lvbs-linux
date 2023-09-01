#ifndef _VSM_H
#define _VSM_H

#ifdef CONFIG_HEKI
#include <linux/heki.h>

void hv_vsm_init_heki(void);

#else

void hv_vsm_init_heki(void)
{
}

#endif /* CONFIG_HEKI */

#endif /* _VSM_H */

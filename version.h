#ifndef VERSION_H
# define VERSION_H

# include <linux/ioctl.h>

# define VERSION_MODIFIED _IOW('v', 0, bool *)
# define VERSION_RESET _IO('v', 1)

#endif

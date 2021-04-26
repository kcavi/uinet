/*-
 * Copyright (c) 2008 Ed Schouten <ed@FreeBSD.org>
 * All rights reserved.
 *
 * Portions of this software were developed under sponsorship from Snow
 * B.V., the Netherlands.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: stable/11/sys/dev/pty/pty.c 331722 2018-03-29 02:50:57Z eadler $");

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/eventhandler.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/tty.h>

#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>


/*
 * This driver implements a BSD-style compatibility naming scheme for
 * the pts(4) driver. We just call into pts(4) to create the actual PTY.
 * To make sure we don't use the same PTY multiple times, we abuse
 * si_drv1 inside the cdev to mark whether the PTY is in use.
 *
 * It also implements a /dev/ptmx device node, which is useful for Linux
 * binary emulation.
 */

void
counted_warning(unsigned *counter, const char *msg)
{
	struct thread *td;
	unsigned c;

	for (;;) {
		c = *counter;
		if (c == 0)
			break;
		if (atomic_cmpset_int(counter, c, c - 1)) {
			td = curthread;
			log(LOG_INFO, "pid %d (%s) %s%s\n",
			    td->td_proc->p_pid, td->td_name, msg,
			    c > 1 ? "" : " - not logging anymore");
			break;
		}
	}
}



static unsigned pty_warningcnt = 1;
SYSCTL_UINT(_kern, OID_AUTO, tty_pty_warningcnt, CTLFLAG_RW,
    &pty_warningcnt, 0,
    "Warnings that will be triggered upon legacy PTY allocation");

static int
ptydev_fdopen(struct cdev *dev, int fflags, struct thread *td, struct file *fp)
{
	int error;
	char name[6]; /* "ttyXX" */

	if (!atomic_cmpset_ptr((uintptr_t *)&dev->si_drv1, 0, 1))
		return (EBUSY);

	/* Generate device name and create PTY. */
	strlcpy(name, devtoname(dev), sizeof(name));
	name[0] = 't';

	error = pts_alloc_external(fflags & (FREAD|FWRITE), td, fp, dev, name);
	if (error != 0) {
		destroy_dev_sched(dev);
		return (error);
	}

	/* Raise a warning when a legacy PTY has been allocated. */
	counted_warning(&pty_warningcnt, "is using legacy pty devices");

	return (0);
}

static struct cdevsw ptydev_cdevsw = {
	.d_version	= D_VERSION,
	.d_fdopen	= ptydev_fdopen,
	.d_name		= "ptydev",
};

static void
pty_clone(void *arg, struct ucred *cr, char *name, int namelen,
    struct cdev **dev)
{
	struct make_dev_args mda;
	int error;

	/* Cloning is already satisfied. */
	if (*dev != NULL)
		return;

	/* Only catch /dev/ptyXX. */
	if (namelen != 5 || bcmp(name, "pty", 3) != 0)
		return;

	/* Only catch /dev/pty[l-sL-S]X. */
	if (!(name[3] >= 'l' && name[3] <= 's') &&
	    !(name[3] >= 'L' && name[3] <= 'S'))
		return;

	/* Only catch /dev/pty[l-sL-S][0-9a-v]. */
	if (!(name[4] >= '0' && name[4] <= '9') &&
	    !(name[4] >= 'a' && name[4] <= 'v'))
		return;

	/* Create the controller device node. */
	make_dev_args_init(&mda);
	mda.mda_flags =  MAKEDEV_CHECKNAME | MAKEDEV_REF;
	mda.mda_devsw = &ptydev_cdevsw;
	mda.mda_uid = UID_ROOT;
	mda.mda_gid = GID_WHEEL;
	mda.mda_mode = 0666;
	error = make_dev_s(&mda, dev, "%s", name);
	if (error != 0)
		*dev = NULL;
}

static int
ptmx_fdopen(struct cdev *dev __unused, int fflags, struct thread *td,
    struct file *fp)
{

	return (pts_alloc(fflags & (FREAD|FWRITE), td, fp));
}

static struct cdevsw ptmx_cdevsw = {
	.d_version	= D_VERSION,
	.d_fdopen	= ptmx_fdopen,
	.d_name		= "ptmx",
};

static int
pty_modevent(module_t mod, int type, void *data)
{

	switch(type) {
	case MOD_LOAD:
		EVENTHANDLER_REGISTER(dev_clone, pty_clone, 0, 1000);
		make_dev_credf(MAKEDEV_ETERNAL_KLD, &ptmx_cdevsw, 0, NULL,
		    UID_ROOT, GID_WHEEL, 0666, "ptmx");
		break;
	case MOD_SHUTDOWN:
		break;
	case MOD_UNLOAD:
		/* XXX: No unloading support yet. */
		return (EBUSY);
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

int tpdev_open(struct tty *tp, struct cdev *dev, int oflags);


int usp_openpty(int *amaster, int *aslave, char *name)
{
	int error, fd_master,fd_slave;
	struct file *fp_master,*fp_slave;
	int flags = O_RDWR; 
	struct tty *tp;

	/*
	 * POSIX states it's unspecified when other flags are passed. We
	 * don't allow this.
	 */
	if (flags & ~(O_RDWR|O_NOCTTY|O_CLOEXEC))
		return (EINVAL);

	error = falloc(curthread, &fp_master, &fd_master,flags);
	if (error)
		return (error);

	error = falloc(curthread, &fp_slave, &fd_slave,flags);
	if (error)
		return (error);

	/* Allocate the actual pseudo-TTY. */
	tp = pts_tty_alloc(FFLAGS(flags & O_ACCMODE), curthread, fp_master);
	if (tp == NULL) {
		printf("%s %d\n",__func__,__LINE__);
		fdclose(curthread, fp_master, fd_master);
		fdrop(fp_master, curthread);
		return (error);
	}

	tpdev_open(tp, NULL, flags);


	error = pts_slave_tty_alloc(tp, FFLAGS(flags & O_ACCMODE), curthread, fp_slave);
	if (error != 0) {
		printf("%s %d\n",__func__,__LINE__);
		fdclose(curthread, fp_slave, fd_slave);
		fdrop(fp_slave, curthread);
		return (error);
	}

	//printf("c_lflag=%x c_iflag=%x\n",tp->t_termios.c_lflag,tp->t_termios.c_iflag );
	//tp->t_termios.c_lflag &= ~(ICANON | ECHO | ISIG);
	tp->t_termios.c_lflag &= ~(ICANON  | ISIG |ECHOCTL |ECHO);
	tp->t_termios.c_iflag &= ~(IXON | IXOFF |ICRNL);

	//tp->t_termios.c_iflag |= IGNCR;
	//tp->t_termios.c_iflag |= ICRNL;
#if 0
	error = devpts_open(tp->t_dev, flags, curthread, fp_slave);
	if (error != 0) {
		printf("%s %d\n",__func__,__LINE__);
		fdclose(curthread, fp_slave, fd_slave);
		fdrop(fp_slave, curthread);
		return (error);
	}
#endif

	/* Pass it back to userspace. */
	curthread->td_retval[0] = fd_master;
	fdrop(fp_master, curthread);
	fdrop(fp_slave, curthread);

	*amaster = fd_master;
	*aslave = fd_slave;

	return (0);

}


DEV_MODULE(pty, pty_modevent, NULL);

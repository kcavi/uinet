/*-
 * Copyright (c) 2000-2004
 *	Poul-Henning Kamp.  All rights reserved.
 * Copyright (c) 1989, 1992-1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kernfs_vnops.c	8.15 (Berkeley) 5/21/95
 * From: FreeBSD: src/sys/miscfs/kernfs/kernfs_vnops.c 1.43
 *
 * $FreeBSD: stable/11/sys/fs/devfs/devfs_vnops.c 328298 2018-01-23 20:08:25Z jhb $
 */

/*
 * TODO:
 *	mkdir: want it ?
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ttycom.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

struct fileops devfs_ops_f;

#include <devfs.h>
#include <devfs_int.h>

#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>

static MALLOC_DEFINE(M_CDEVPDATA, "DEVFSP", "Metainfo for cdev-fp data");

struct mtx	devfs_de_interlock;
MTX_SYSINIT(devfs_de_interlock, &devfs_de_interlock, "devfs interlock", MTX_DEF);
struct sx	clone_drain_lock;
SX_SYSINIT(clone_drain_lock, &clone_drain_lock, "clone events drain lock");
struct mtx	cdevpriv_mtx;
MTX_SYSINIT(cdevpriv_mtx, &cdevpriv_mtx, "cdevpriv lock", MTX_DEF);

SYSCTL_DECL(_vfs_devfs);

static int devfs_dotimes;
SYSCTL_INT(_vfs_devfs, OID_AUTO, dotimes, CTLFLAG_RW,
    &devfs_dotimes, 0, "Update timestamps on DEVFS with default precision");

void vfs_timestamp(struct timespec *tsp);
void vgone(struct vnode *vp);
void vput(struct vnode *vp);



void
foffset_lock_uio(struct file *fp, struct uio *uio, int flags)
{

	//printf("%s %d\n",__func__,__LINE__);
}

void
foffset_unlock_uio(struct file *fp, struct uio *uio, int flags)
{

	//printf("%s %d\n",__func__,__LINE__);
}


void
devfs_unmount_final(struct devfs_mount *fmp)
{
	printf("%s %d\n",__func__,__LINE__);
}


/*
 * Update devfs node timestamp.  Note that updates are unlocked and
 * stat(2) could see partially updated times.
 */
static void
devfs_timestamp(struct timespec *tsp)
{
	time_t ts;

	if (devfs_dotimes) {
		vfs_timestamp(tsp);
	} else {
		ts = time_second;
		if (tsp->tv_sec != ts) {
			tsp->tv_sec = ts;
			tsp->tv_nsec = 0;
		}
	}
}

static int
devfs_fp_check(struct file *fp, struct cdev **devp, struct cdevsw **dswp,
    int *ref)
{

	*dswp = devvn_refthread(fp->f_vnode, devp, ref);
	if (*devp != fp->f_data) {
		if (*dswp != NULL)
			dev_relthread(*devp, *ref);
		return (ENXIO);
	}
	KASSERT((*devp)->si_refcount > 0,
	    ("devfs: un-referenced struct cdev *(%s)", devtoname(*devp)));
	if (*dswp == NULL)
		return (ENXIO);
	curthread->td_fpop = fp;
	return (0);
}

int
devfs_get_cdevpriv(void **datap)
{
	struct file *fp;
	struct cdev_privdata *p;
	int error;

	fp = curthread->td_fpop;
	if (fp == NULL)
		return (EBADF);
	p = fp->f_cdevpriv;
	if (p != NULL) {
		error = 0;
		*datap = p->cdpd_data;
	} else
		error = ENOENT;
	return (error);
}

int
devfs_set_cdevpriv(void *priv, d_priv_dtor_t *priv_dtr)
{
	struct file *fp;
	struct cdev_priv *cdp;
	struct cdev_privdata *p;
	int error;

	fp = curthread->td_fpop;
	if (fp == NULL)
		return (ENOENT);
	cdp = cdev2priv((struct cdev *)fp->f_data);
	p = malloc(sizeof(struct cdev_privdata), M_CDEVPDATA, M_WAITOK);
	p->cdpd_data = priv;
	p->cdpd_dtr = priv_dtr;
	p->cdpd_fp = fp;
	mtx_lock(&cdevpriv_mtx);
	if (fp->f_cdevpriv == NULL) {
		LIST_INSERT_HEAD(&cdp->cdp_fdpriv, p, cdpd_list);
		fp->f_cdevpriv = p;
		mtx_unlock(&cdevpriv_mtx);
		error = 0;
	} else {
		mtx_unlock(&cdevpriv_mtx);
		free(p, M_CDEVPDATA);
		error = EBUSY;
	}
	return (error);
}

void
devfs_destroy_cdevpriv(struct cdev_privdata *p)
{

	mtx_assert(&cdevpriv_mtx, MA_OWNED);
	KASSERT(p->cdpd_fp->f_cdevpriv == p,
	    ("devfs_destoy_cdevpriv %p != %p", p->cdpd_fp->f_cdevpriv, p));
	p->cdpd_fp->f_cdevpriv = NULL;
	LIST_REMOVE(p, cdpd_list);
	mtx_unlock(&cdevpriv_mtx);
	(p->cdpd_dtr)(p->cdpd_data);
	free(p, M_CDEVPDATA);
}

static void
devfs_fpdrop(struct file *fp)
{
	struct cdev_privdata *p;

	mtx_lock(&cdevpriv_mtx);
	if ((p = fp->f_cdevpriv) == NULL) {
		mtx_unlock(&cdevpriv_mtx);
		return;
	}
	devfs_destroy_cdevpriv(p);
}

void
devfs_clear_cdevpriv(void)
{
	struct file *fp;

	fp = curthread->td_fpop;
	if (fp == NULL)
		return;
	devfs_fpdrop(fp);
}

/*
 * On success devfs_populate_vp() returns with dmp->dm_lock held.
 */
static int
devfs_populate_vp(struct vnode *vp)
{
	struct devfs_dirent *de;
	struct devfs_mount *dmp;
	int locked;

	//ASSERT_VOP_LOCKED(vp, "devfs_populate_vp");

	dmp = VFSTODEVFS(vp->v_mount);
	//locked = VOP_ISLOCKED(vp);

	sx_xlock(&dmp->dm_lock);
	DEVFS_DMP_HOLD(dmp);

	/* Can't call devfs_populate() with the vnode lock held. */
	VOP_UNLOCK(vp, 0);
	devfs_populate(dmp);

	sx_xunlock(&dmp->dm_lock);
	vn_lock(vp, locked | LK_RETRY);
	sx_xlock(&dmp->dm_lock);
	if (DEVFS_DMP_DROP(dmp)) {
		sx_xunlock(&dmp->dm_lock);
		devfs_unmount_final(dmp);
		return (ERESTART);
	}
	if ((vp->v_iflag & VI_DOOMED) != 0) {
		sx_xunlock(&dmp->dm_lock);
		return (ERESTART);
	}
	de = vp->v_data;
	KASSERT(de != NULL,
	    ("devfs_populate_vp: vp->v_data == NULL but vnode not doomed"));
	if ((de->de_flags & DE_DOOMED) != 0) {
		sx_xunlock(&dmp->dm_lock);
		return (ERESTART);
	}

	return (0);
}

/*
 * Construct the fully qualified path name relative to the mountpoint.
 * If a NULL cnp is provided, no '/' is appended to the resulting path.
 */
char *
devfs_fqpn(char *buf, struct devfs_mount *dmp, struct devfs_dirent *dd,
    struct componentname *cnp)
{
	int i;
	struct devfs_dirent *de;

	sx_assert(&dmp->dm_lock, SA_LOCKED);

	i = SPECNAMELEN;
	buf[i] = '\0';
	if (cnp != NULL)
		i -= cnp->cn_namelen;
	if (i < 0)
		 return (NULL);
	if (cnp != NULL)
		bcopy(cnp->cn_nameptr, buf + i, cnp->cn_namelen);
	de = dd;
	while (de != dmp->dm_rootdir) {
		if (cnp != NULL || i < SPECNAMELEN) {
			i--;
			if (i < 0)
				 return (NULL);
			buf[i] = '/';
		}
		i -= de->de_dirent->d_namlen;
		if (i < 0)
			 return (NULL);
		bcopy(de->de_dirent->d_name, buf + i,
		    de->de_dirent->d_namlen);
		de = devfs_parent_dirent(de);
		if (de == NULL)
			return (NULL);
	}
	return (buf + i);
}

static int
devfs_allocv_drop_refs(int drop_dm_lock, struct devfs_mount *dmp,
	struct devfs_dirent *de)
{
	int not_found;

	not_found = 0;
	if (de->de_flags & DE_DOOMED)
		not_found = 1;
	if (DEVFS_DE_DROP(de)) {
		KASSERT(not_found == 1, ("DEVFS de dropped but not doomed"));
		devfs_dirent_free(de);
	}
	if (DEVFS_DMP_DROP(dmp)) {
		KASSERT(not_found == 1,
			("DEVFS mount struct freed before dirent"));
		not_found = 2;
		sx_xunlock(&dmp->dm_lock);
		devfs_unmount_final(dmp);
	}
	if (not_found == 1 || (drop_dm_lock && not_found != 2))
		sx_unlock(&dmp->dm_lock);
	return (not_found);
}

static void
devfs_insmntque_dtr(struct vnode *vp, void *arg)
{
	struct devfs_dirent *de;

	de = (struct devfs_dirent *)arg;
	mtx_lock(&devfs_de_interlock);
	vp->v_data = NULL;
	de->de_vnode = NULL;
	mtx_unlock(&devfs_de_interlock);
	vgone(vp);
	vput(vp);
}

_Static_assert(((FMASK | FCNTLFLAGS) & (FLASTCLOSE | FREVOKE)) == 0,
    "devfs-only flag reuse failed");

static int
devfs_close_f(struct file *fp, struct thread *td)
{
	int error = 0;
	struct file *fpop;
	
	struct cdev *dev;
	int ioflag, ref;
	ssize_t resid;
	struct cdevsw *dsw;
	ioflag = 0;

	/*
	 * NB: td may be NULL if this descriptor is closed due to
	 * garbage collection from a closed UNIX domain socket.
	 */
	fpop = curthread->td_fpop;
	curthread->td_fpop = fp;
	if(vnops.fo_close != NULL)
		error = vnops.fo_close(fp, td);
	curthread->td_fpop = fpop;

	/*
	 * The f_cdevpriv cannot be assigned non-NULL value while we
	 * are destroying the file.
	 */
	if (fp->f_cdevpriv != NULL)
		devfs_fpdrop(fp);


	error = devfs_fp_check(fp, &dev, &dsw, &ref);
	if (error != 0) {
		return (error);
	}
	error = dsw->d_close(dev, ioflag, DTYPE_DEV,td);
	
	return (error);
}

/* ARGSUSED */
static int
devfs_ioctl_f(struct file *fp, u_long com, void *data, struct ucred *cred, struct thread *td)
{
	struct cdev *dev;
	struct cdevsw *dsw;
	struct vnode *vp;
	struct vnode *vpold;
	int error, i, ref;
	const char *p;
	struct fiodgname_arg *fgn;
	struct file *fpop;

	fpop = td->td_fpop;
	error = devfs_fp_check(fp, &dev, &dsw, &ref);
	if (error != 0) {
		error = vnops.fo_ioctl(fp, com, data, cred, td);
		return (error);
	}

	if (com == FIODTYPE) {
		*(int *)data = dsw->d_flags & D_TYPEMASK;
		td->td_fpop = fpop;
		dev_relthread(dev, ref);
		return (0);
	} else if (com == FIODGNAME) {
		fgn = data;
		p = devtoname(dev);
		i = strlen(p) + 1;
		if (i > fgn->len)
			error = EINVAL;
		else
			error = copyout(p, fgn->buf, i);
		td->td_fpop = fpop;
		dev_relthread(dev, ref);
		return (error);
	}
	error = dsw->d_ioctl(dev, com, data, fp->f_flag, td);
	td->td_fpop = NULL;
	dev_relthread(dev, ref);
	if (error == ENOIOCTL)
		error = ENOTTY;
	if (error == 0 && com == TIOCSCTTY) {
		vp = fp->f_vnode;

		/* Do nothing if reassigning same control tty */
		sx_slock(&proctree_lock);
		if (td->td_proc->p_session->s_ttyvp == vp) {
			sx_sunlock(&proctree_lock);
			return (0);
		}

		vpold = td->td_proc->p_session->s_ttyvp;
		VREF(vp);
		SESS_LOCK(td->td_proc->p_session);
		td->td_proc->p_session->s_ttyvp = vp;
		td->td_proc->p_session->s_ttydp = cdev2priv(dev);
		SESS_UNLOCK(td->td_proc->p_session);

		sx_sunlock(&proctree_lock);

		/* Get rid of reference to old control tty */
		if (vpold)
			vrele(vpold);
	}
	return (error);
}

/* ARGSUSED */
static int
devfs_kqfilter_f(struct file *fp, struct knote *kn)
{
	struct cdev *dev;
	struct cdevsw *dsw;
	int error, ref;
	struct file *fpop;
	struct thread *td;

	td = curthread;
	fpop = td->td_fpop;
	error = devfs_fp_check(fp, &dev, &dsw, &ref);
	if (error)
		return (error);
	error = dsw->d_kqfilter(dev, kn);
	td->td_fpop = fpop;
	dev_relthread(dev, ref);
	return (error);
}

static inline int
devfs_prison_check(struct devfs_dirent *de, struct thread *td)
{
	struct cdev_priv *cdp;
	struct ucred *dcr;
	struct proc *p;
	int error;

	cdp = de->de_cdp;
	if (cdp == NULL)
		return (0);
	dcr = cdp->cdp_c.si_cred;
	if (dcr == NULL)
		return (0);

	error = prison_check(td->td_ucred, dcr);
	if (error == 0)
		return (0);
	/* We do, however, allow access to the controlling terminal */
	p = td->td_proc;
	PROC_LOCK(p);
	if (!(p->p_flag & P_CONTROLT)) {
		PROC_UNLOCK(p);
		return (error);
	}
	if (p->p_session->s_ttydp == cdp)
		error = 0;
	PROC_UNLOCK(p);
	return (error);
}

/* ARGSUSED */
static int
devfs_poll_f(struct file *fp, int events, struct ucred *cred, struct thread *td)
{
	struct cdev *dev;
	struct cdevsw *dsw;
	int error, ref;
	struct file *fpop;

	fpop = td->td_fpop;
	error = devfs_fp_check(fp, &dev, &dsw, &ref);
	if (error != 0) {
		error = vnops.fo_poll(fp, events, cred, td);
		return (error);
	}
	error = dsw->d_poll(dev, events, td);
	td->td_fpop = fpop;
	dev_relthread(dev, ref);
	return(error);
}

static int
devfs_read_f(struct file *fp, struct uio *uio, struct ucred *cred,
    int flags, struct thread *td)
{
	struct cdev *dev;
	int ioflag, error, ref;
	ssize_t resid;
	struct cdevsw *dsw;
	struct file *fpop;

	if (uio->uio_resid > DEVFS_IOSIZE_MAX)
		return (EINVAL);
	fpop = td->td_fpop;
	error = devfs_fp_check(fp, &dev, &dsw, &ref);
	if (error != 0) {
		error = vnops.fo_read(fp, uio, cred, flags, td);
		return (error);
	}
	resid = uio->uio_resid;
	ioflag = fp->f_flag & (O_NONBLOCK | O_DIRECT);
	if (ioflag & O_DIRECT)
		ioflag |= IO_DIRECT;

	foffset_lock_uio(fp, uio, flags | FOF_NOLOCK);
	error = dsw->d_read(dev, uio, ioflag);
	if (uio->uio_resid != resid || (error == 0 && resid != 0))
		devfs_timestamp(&dev->si_atime);
	td->td_fpop = fpop;
	dev_relthread(dev, ref);

	foffset_unlock_uio(fp, uio, flags | FOF_NOLOCK | FOF_NEXTOFF);
	return (error);
}



static int
devfs_stat_f(struct file *fp, struct stat *sb, struct ucred *cred, struct thread *td)
{

	return (vnops.fo_stat(fp, sb, cred, td));
}

static int
devfs_truncate_f(struct file *fp, off_t length, struct ucred *cred, struct thread *td)
{

	return (vnops.fo_truncate(fp, length, cred, td));
}

static int
devfs_write_f(struct file *fp, struct uio *uio, struct ucred *cred,
    int flags, struct thread *td)
{
	struct cdev *dev;
	int error, ioflag, ref;
	ssize_t resid;
	struct cdevsw *dsw;
	struct file *fpop;

	if (uio->uio_resid > DEVFS_IOSIZE_MAX)
		return (EINVAL);
	fpop = td->td_fpop;
	error = devfs_fp_check(fp, &dev, &dsw, &ref);
	if (error != 0) {
		error = vnops.fo_write(fp, uio, cred, flags, td);
		return (error);
	}
	KASSERT(uio->uio_td == td, ("uio_td %p is not td %p", uio->uio_td, td));
	ioflag = fp->f_flag & (O_NONBLOCK | O_DIRECT | O_FSYNC);
	if (ioflag & O_DIRECT)
		ioflag |= IO_DIRECT;
	foffset_lock_uio(fp, uio, flags | FOF_NOLOCK);

	resid = uio->uio_resid;

	error = dsw->d_write(dev, uio, ioflag);
	if (uio->uio_resid != resid || (error == 0 && resid != 0)) {
		devfs_timestamp(&dev->si_ctime);
		dev->si_mtime = dev->si_ctime;
	}
	td->td_fpop = fpop;
	dev_relthread(dev, ref);

	foffset_unlock_uio(fp, uio, flags | FOF_NOLOCK | FOF_NEXTOFF);
	return (error);
}

static int
devfs_mmap_f(struct file *fp, vm_map_t map, vm_offset_t *addr, vm_size_t size,
    vm_prot_t prot, vm_prot_t cap_maxprot, int flags, vm_ooffset_t foff,
    struct thread *td)
{
	printf("%s %d\n",__func__,__LINE__);
	return 0;
}

dev_t
dev2udev(struct cdev *x)
{
	if (x == NULL)
		return (NODEV);
	return (cdev2priv(x)->cdp_inode);
}

struct fileops devfs_ops_f = {
	.fo_read =	devfs_read_f,
	.fo_write =	devfs_write_f,
	.fo_truncate =	devfs_truncate_f,
	.fo_ioctl =	devfs_ioctl_f,
	.fo_poll =	devfs_poll_f,
	.fo_kqfilter =	devfs_kqfilter_f,
	.fo_stat =	devfs_stat_f,
	.fo_close =	devfs_close_f,
	//.fo_chmod =	vn_chmod,
	//.fo_chown =	vn_chown,
	//.fo_sendfile =	vn_sendfile,
	//.fo_seek =	vn_seek,
	//.fo_fill_kinfo = vn_fill_kinfo,
	.fo_mmap =	devfs_mmap_f,
	.fo_flags =	DFLAG_PASSABLE | DFLAG_SEEKABLE
};



/*
 * Our calling convention to the device drivers used to be that we passed
 * vnode.h IO_* flags to read()/write(), but we're moving to fcntl.h O_ 
 * flags instead since that's what open(), close() and ioctl() takes and
 * we don't really want vnode.h in device drivers.
 * We solved the source compatibility by redefining some vnode flags to
 * be the same as the fcntl ones and by sending down the bitwise OR of
 * the respective fcntl/vnode flags.  These CTASSERTS make sure nobody
 * pulls the rug out under this.
 */
CTASSERT(O_NONBLOCK == IO_NDELAY);
CTASSERT(O_FSYNC == IO_SYNC);

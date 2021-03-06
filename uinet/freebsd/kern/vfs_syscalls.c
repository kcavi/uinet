/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
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
 *	@(#)vfs_syscalls.c	8.13 (Berkeley) 4/15/94
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"
#include "opt_compat.h"
#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/capsicum.h>
#include <sys/disk.h>
#include <sys/sysent.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/sysproto.h>
#include <sys/namei.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/rwlock.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/dirent.h>
#include <sys/jail.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif

#include <machine/stdarg.h>

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/uma.h>


MALLOC_DEFINE(M_FADVISE, "fadvise", "posix_fadvise(2) information");

SDT_PROVIDER_DEFINE(vfs);
SDT_PROBE_DEFINE2(vfs, , stat, mode, "char *", "int");
SDT_PROBE_DEFINE2(vfs, , stat, reg, "char *", "int");


struct fileops vnops;

static int kern_chflagsat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, u_long flags, int atflag);
static int setfflags(struct thread *td, struct vnode *, u_long);
static int getutimes(const struct timeval *, enum uio_seg, struct timespec *);
static int getutimens(const struct timespec *, enum uio_seg,
    struct timespec *, int *);
static int setutimes(struct thread *td, struct vnode *,
    const struct timespec *, int, int);
static int vn_access(struct vnode *vp, int user_flags, struct ucred *cred,
    struct thread *td);
int change_dir(struct vnode *vp, struct thread *td);
void	vput(struct vnode *vp);
int	vn_start_write(struct vnode *vp, struct mount **mpp, int flags);
void	vn_finished_write(struct mount *mp);


/*
 * ---------------------------------------------------------------------
 * Various utility functions
 */

void
vfs_ref(struct mount *mp)
{

	CTR2(KTR_VFS, "%s: mp %p", __func__, mp);
	MNT_ILOCK(mp);
	MNT_REF(mp);
	MNT_IUNLOCK(mp);
}

void
vfs_rel(struct mount *mp)
{

	CTR2(KTR_VFS, "%s: mp %p", __func__, mp);
	MNT_ILOCK(mp);
	MNT_REL(mp);
	MNT_IUNLOCK(mp);
}

/* For any iteration/modification of mountlist */
struct mtx mountlist_mtx;
MTX_SYSINIT(mountlist, &mountlist_mtx, "mountlist", MTX_DEF);

/*
 * A Zen vnode attribute structure.
 *
 * Initialized when the first filesystem registers by vfs_register().
 */
struct vattr va_null;


static  int VOP_SETATTR(
		struct vnode *vp,
		struct vattr *vap,
		struct ucred *cred)
{
	printf("%s %d\n",__func__,__LINE__);
	return 0;
}

static  int VOP_MKDIR(
		 struct vnode *dvp,
		 struct vnode **vpp,
		 struct componentname *cnp,
		 struct vattr *vap)
{
	printf("%s %d\n",__func__,__LINE__);
	return 0;
}


static  int VOP_RENAME(
		struct vnode *fdvp,
		struct vnode *fvp,
		struct componentname *fcnp,
		struct vnode *tdvp,
		struct vnode *tvp,
		struct componentname *tcnp)
{
	printf("%s %d\n",__func__,__LINE__);
	return 0;
}

static int VOP_READLINK(
		struct vnode *vp,
		struct uio *uio,
		struct ucred *cred)
{
	printf("%s %d\n",__func__,__LINE__);
	return 0;
}

static int VOP_REMOVE(
		struct vnode *dvp,
		struct vnode *vp,
		struct componentname *cnp)
{
	printf("%s %d\n",__func__,__LINE__);
	return 0;
}

static int VOP_LINK(
		struct vnode *tdvp,
		struct vnode *vp,
		struct componentname *cnp)
{
	printf("%s %d\n",__func__,__LINE__);
	return 0;
}

static int VOP_MKNOD(
		struct vnode *dvp,
		struct vnode **vpp,
		struct componentname *cnp,
		struct vattr *vap)
{
	printf("%s %d\n",__func__,__LINE__);
	return 0;
}


static int VOP_WHITEOUT(
		struct vnode *dvp,
		struct componentname *cnp,
		int flags)
{
	printf("%s %d\n",__func__,__LINE__);
	return 0;
}


/*
 * Sync each mounted filesystem.
 */
#ifndef _SYS_SYSPROTO_H_
struct sync_args {
	int     dummy;
};
#endif
/* ARGSUSED */
int
sys_sync(td, uap)
	struct thread *td;
	struct sync_args *uap;
{
	
	return (0);
}


/*
 * Used by statfs conversion routines to scale the block size up if
 * necessary so that all of the block counts are <= 'max_size'.  Note
 * that 'max_size' should be a bitmask, i.e. 2^n - 1 for some non-zero
 * value of 'n'.
 */
void
statfs_scale_blocks(struct statfs *sf, long max_size)
{
	
}

/*
 * Get filesystem statistics.
 */
#ifndef _SYS_SYSPROTO_H_
struct statfs_args {
	char *path;
	struct statfs *buf;
};
#endif
int
sys_statfs(td, uap)
	struct thread *td;
	register struct statfs_args /* {
		char *path;
		struct statfs *buf;
	} */ *uap;
{
	struct statfs sf;
	int error;

	error = kern_statfs(td, uap->path, UIO_USERSPACE, &sf);
	if (error == 0)
		error = copyout(&sf, uap->buf, sizeof(sf));
	return (error);
}

int
kern_statfs(struct thread *td, char *path, enum uio_seg pathseg,
    struct statfs *buf)
{
	
	int error = 0;

	
	return (error);
}

/*
 * Get filesystem statistics.
 */
#ifndef _SYS_SYSPROTO_H_
struct fstatfs_args {
	int fd;
	struct statfs *buf;
};
#endif
int
sys_fstatfs(td, uap)
	struct thread *td;
	register struct fstatfs_args /* {
		int fd;
		struct statfs *buf;
	} */ *uap;
{
	struct statfs sf;
	int error;

	error = kern_fstatfs(td, uap->fd, &sf);
	if (error == 0)
		error = copyout(&sf, uap->buf, sizeof(sf));
	return (error);
}

int
kern_fstatfs(struct thread *td, int fd, struct statfs *buf)
{
	return 0;
}

/*
 * Get statistics on all filesystems.
 */
#ifndef _SYS_SYSPROTO_H_
struct getfsstat_args {
	struct statfs *buf;
	long bufsize;
	int flags;
};
#endif
int
sys_getfsstat(td, uap)
	struct thread *td;
	register struct getfsstat_args /* {
		struct statfs *buf;
		long bufsize;
		int flags;
	} */ *uap;
{

	int error;
	return (error);
}

/*
 * If (bufsize > 0 && bufseg == UIO_SYSSPACE)
 *	The caller is responsible for freeing memory which will be allocated
 *	in '*buf'.
 */
int
kern_getfsstat(struct thread *td, struct statfs **buf, size_t bufsize,
    size_t *countp, enum uio_seg bufseg, int flags)
{

	return (0);
}




/*
 * Change current working directory (``.'').
 */
#ifndef _SYS_SYSPROTO_H_
struct chdir_args {
	char	*path;
};
#endif
int
sys_chdir(td, uap)
	struct thread *td;
	struct chdir_args /* {
		char *path;
	} */ *uap;
{

	return (kern_chdir(td, uap->path, UIO_USERSPACE));
}

int
kern_chdir(struct thread *td, char *path, enum uio_seg pathseg)
{
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKSHARED | LOCKLEAF | AUDITVNODE1,
	    pathseg, path, td);
	if ((error = namei(&nd)) != 0)
		return (error);
	if ((error = change_dir(nd.ni_vp, td)) != 0) {
		vput(nd.ni_vp);
		NDFREE(&nd, NDF_ONLY_PNBUF);
		return (error);
	}
	VOP_UNLOCK(nd.ni_vp, 0);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	pwd_chdir(td, nd.ni_vp);
	return (0);
}

/*
 * Change notion of root (``/'') directory.
 */
#ifndef _SYS_SYSPROTO_H_
struct chroot_args {
	char	*path;
};
#endif
int
sys_chroot(td, uap)
	struct thread *td;
	struct chroot_args /* {
		char *path;
	} */ *uap;
{
	struct nameidata nd;
	int error;

	error = priv_check(td, PRIV_VFS_CHROOT);
	if (error != 0)
		return (error);
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKSHARED | LOCKLEAF | AUDITVNODE1,
	    UIO_USERSPACE, uap->path, td);
	error = namei(&nd);
	if (error != 0)
		goto error;
	error = change_dir(nd.ni_vp, td);
	if (error != 0)
		goto e_vunlock;
#ifdef MAC
	error = mac_vnode_check_chroot(td->td_ucred, nd.ni_vp);
	if (error != 0)
		goto e_vunlock;
#endif
	VOP_UNLOCK(nd.ni_vp, 0);
	error = pwd_chroot(td, nd.ni_vp);
	vrele(nd.ni_vp);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	return (error);
e_vunlock:
	vput(nd.ni_vp);
error:
	NDFREE(&nd, NDF_ONLY_PNBUF);
	return (error);
}

/*
 * Common routine for chroot and chdir.  Callers must provide a locked vnode
 * instance.
 */
int
change_dir(vp, td)
	struct vnode *vp;
	struct thread *td;
{
	return 0;
}

static __inline void
flags_to_rights(int flags, cap_rights_t *rightsp)
{

	if (flags & O_EXEC) {
		cap_rights_set(rightsp, CAP_FEXECVE);
	} else {
		switch ((flags & O_ACCMODE)) {
		case O_RDONLY:
			cap_rights_set(rightsp, CAP_READ);
			break;
		case O_RDWR:
			cap_rights_set(rightsp, CAP_READ);
			/* FALLTHROUGH */
		case O_WRONLY:
			cap_rights_set(rightsp, CAP_WRITE);
			if (!(flags & (O_APPEND | O_TRUNC)))
				cap_rights_set(rightsp, CAP_SEEK);
			break;
		}
	}

	if (flags & O_CREAT)
		cap_rights_set(rightsp, CAP_CREATE);

	if (flags & O_TRUNC)
		cap_rights_set(rightsp, CAP_FTRUNCATE);

	if (flags & (O_SYNC | O_FSYNC))
		cap_rights_set(rightsp, CAP_FSYNC);

	if (flags & (O_EXLOCK | O_SHLOCK))
		cap_rights_set(rightsp, CAP_FLOCK);
}

/*
 * Check permissions, allocate an open file structure, and call the device
 * open routine if any.
 */
#ifndef _SYS_SYSPROTO_H_
struct open_args {
	char	*path;
	int	flags;
	int	mode;
};
#endif
int
sys_open(td, uap)
	struct thread *td;
	register struct open_args /* {
		char *path;
		int flags;
		int mode;
	} */ *uap;
{

	return (kern_openat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, uap->mode));
}

#ifndef _SYS_SYSPROTO_H_
struct openat_args {
	int	fd;
	char	*path;
	int	flag;
	int	mode;
};
#endif
int
sys_openat(struct thread *td, struct openat_args *uap)
{

	return (kern_openat(td, uap->fd, uap->path, UIO_USERSPACE, uap->flag,
	    uap->mode));
}

int
kern_openat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    int flags, int mode)
{
	struct proc *p = td->td_proc;
	struct filedesc *fdp = p->p_fd;
	struct file *fp;
	struct vnode *vp;
	struct nameidata nd;
	cap_rights_t rights;
	int cmode, error, indx;
	int linux_flags;
	int linux_mode;

	linux_flags = flags;
	linux_mode = mode;

	indx = -1;

	AUDIT_ARG_FFLAGS(flags);
	AUDIT_ARG_MODE(mode);
	/* XXX: audit dirfd */
	cap_rights_init(&rights, CAP_LOOKUP);
	flags_to_rights(flags, &rights);
	/*
	 * Only one of the O_EXEC, O_RDONLY, O_WRONLY and O_RDWR flags
	 * may be specified.
	 */
	if (flags & O_EXEC) {
		if (flags & O_ACCMODE)
			return (EINVAL);
	} else if ((flags & O_ACCMODE) == O_ACCMODE) {
		return (EINVAL);
	} else {
		flags = FFLAGS(flags);
	}

	/*
	 * Allocate a file structure. The descriptor to reference it
	 * is allocated and set by finstall() below.
	 */
	error = falloc_noinstall(td, &fp);
	if (error != 0)
		return (error);
	/*
	 * An extra reference on `fp' has been held for us by
	 * falloc_noinstall().
	 */
	/* Set the flags early so the finit in devfs can pick them up. */
	fp->f_flag = flags & FMASK;
	cmode = ((mode & ~fdp->fd_cmask) & ALLPERMS) & ~S_ISTXT;
	NDINIT_ATRIGHTS(&nd, LOOKUP, FOLLOW | AUDITVNODE1, pathseg, path, fd,
	    &rights, td);
	td->td_dupfd = -1;		/* XXX check for fdopen */
	error = vn_open(&nd, &linux_flags, linux_mode, fp);
	if (error != 0) {
		/*
		 * If the vn_open replaced the method vector, something
		 * wonderous happened deep below and we just pass it up
		 * pretending we know what we do.
		 */
		if (error == ENXIO && fp->f_ops != &badfileops)
			goto success;

		/*
		 * Handle special fdopen() case. bleh.
		 *
		 * Don't do this for relative (capability) lookups; we don't
		 * understand exactly what would happen, and we don't think
		 * that it ever should.
		 */
		if (nd.ni_strictrelative == 0 &&
		    (error == ENODEV || error == ENXIO) &&
		    td->td_dupfd >= 0) {
			error = dupfdopen(td, fdp, td->td_dupfd, flags, error,
			    &indx);
			if (error == 0)
				goto success;
		}

		goto bad;
	}
	td->td_dupfd = 0;
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vp = nd.ni_vp;

	/*
	 * Store the vnode, for any f_type. Typically, the vnode use
	 * count is decremented by direct call to vn_closefile() for
	 * files that switched type in the cdevsw fdopen() method.
	 */
	fp->f_vnode = vp;
	/*
	 * If the file wasn't claimed by devfs bind it to the normal
	 * vnode operations here.
	 */
	if (fp->f_ops == &badfileops) {
		KASSERT(vp->v_type != VFIFO, ("Unexpected fifo."));
		fp->f_seqcount = 1;
		finit(fp, (flags & FMASK) | (fp->f_flag & FHASLOCK),
		    DTYPE_VNODE, vp, &vnops);
	}

	VOP_UNLOCK(vp, 0);
	if (flags & O_TRUNC) {
		error = fo_truncate(fp, 0, td->td_ucred, td);
		if (error != 0)
			goto bad;
	}
success:
	/*
	 * If we haven't already installed the FD (for dupfdopen), do so now.
	 */
	if (indx == -1) {
		struct filecaps *fcaps;

#ifdef CAPABILITIES
		if (nd.ni_strictrelative == 1)
			fcaps = &nd.ni_filecaps;
		else
#endif
			fcaps = NULL;
		error = finstall(td, fp, &indx, flags, fcaps);
		/* On success finstall() consumes fcaps. */
		if (error != 0) {
			filecaps_free(&nd.ni_filecaps);
			goto bad;
		}
	} else {
		filecaps_free(&nd.ni_filecaps);
	}

	/*
	 * Release our private reference, leaving the one associated with
	 * the descriptor table intact.
	 */
	fdrop(fp, td);
	td->td_retval[0] = indx;
	return (0);
bad:
	KASSERT(indx == -1, ("indx=%d, should be -1", indx));
	fdrop(fp, td);
	return (error);
}

/*
 * Create a special file.
 */
#ifndef _SYS_SYSPROTO_H_
struct mknod_args {
	char	*path;
	int	mode;
	int	dev;
};
#endif
int
sys_mknod(td, uap)
	struct thread *td;
	register struct mknod_args /* {
		char *path;
		int mode;
		int dev;
	} */ *uap;
{

	return (kern_mknodat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode, uap->dev));
}

#ifndef _SYS_SYSPROTO_H_
struct mknodat_args {
	int	fd;
	char	*path;
	mode_t	mode;
	dev_t	dev;
};
#endif
int
sys_mknodat(struct thread *td, struct mknodat_args *uap)
{

	return (kern_mknodat(td, uap->fd, uap->path, UIO_USERSPACE, uap->mode,
	    uap->dev));
}

int
kern_mknodat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    int mode, int dev)
{
	struct vnode *vp;
	struct mount *mp;
	struct vattr vattr;
	struct nameidata nd;
	cap_rights_t rights;
	int error, whiteout = 0;

	AUDIT_ARG_MODE(mode);
	AUDIT_ARG_DEV(dev);
	switch (mode & S_IFMT) {
	case S_IFCHR:
	case S_IFBLK:
		error = priv_check(td, PRIV_VFS_MKNOD_DEV);
		if (error == 0 && dev == VNOVAL)
			error = EINVAL;
		break;
	case S_IFMT:
		error = priv_check(td, PRIV_VFS_MKNOD_BAD);
		break;
	case S_IFWHT:
		error = priv_check(td, PRIV_VFS_MKNOD_WHT);
		break;
	case S_IFIFO:
		if (dev == 0)
			return (kern_mkfifoat(td, fd, path, pathseg, mode));
		/* FALLTHROUGH */
	default:
		error = EINVAL;
		break;
	}
	if (error != 0)
		return (error);
restart:
	bwillwrite();
	NDINIT_ATRIGHTS(&nd, CREATE, LOCKPARENT | SAVENAME | AUDITVNODE1 |
	    NOCACHE, pathseg, path, fd, cap_rights_init(&rights, CAP_MKNODAT),
	    td);
	if ((error = namei(&nd)) != 0)
		return (error);
	vp = nd.ni_vp;
	if (vp != NULL) {
		NDFREE(&nd, NDF_ONLY_PNBUF);
		if (vp == nd.ni_dvp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(vp);
		return (EEXIST);
	} else {
		VATTR_NULL(&vattr);
		vattr.va_mode = (mode & ALLPERMS) &
		    ~td->td_proc->p_fd->fd_cmask;
		vattr.va_rdev = dev;
		whiteout = 0;

		switch (mode & S_IFMT) {
		case S_IFMT:	/* used by badsect to flag bad sectors */
			vattr.va_type = VBAD;
			break;
		case S_IFCHR:
			vattr.va_type = VCHR;
			break;
		case S_IFBLK:
			vattr.va_type = VBLK;
			break;
		case S_IFWHT:
			whiteout = 1;
			break;
		default:
			panic("kern_mknod: invalid mode");
		}
	}
	if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE(&nd, NDF_ONLY_PNBUF);
		vput(nd.ni_dvp);
		if ((error = vn_start_write(NULL, &mp, V_XSLEEP | PCATCH)) != 0)
			return (error);
		goto restart;
	}
#ifdef MAC
	if (error == 0 && !whiteout)
		error = mac_vnode_check_create(td->td_ucred, nd.ni_dvp,
		    &nd.ni_cnd, &vattr);
#endif
	if (error == 0) {
		if (whiteout)
			error = VOP_WHITEOUT(nd.ni_dvp, &nd.ni_cnd, CREATE);
		else {
			error = VOP_MKNOD(nd.ni_dvp, &nd.ni_vp,
						&nd.ni_cnd, &vattr);
			if (error == 0)
				vput(nd.ni_vp);
		}
	}
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vput(nd.ni_dvp);
	vn_finished_write(mp);
	return (error);
}

/*
 * Create a named pipe.
 */
#ifndef _SYS_SYSPROTO_H_
struct mkfifo_args {
	char	*path;
	int	mode;
};
#endif
int
sys_mkfifo(td, uap)
	struct thread *td;
	register struct mkfifo_args /* {
		char *path;
		int mode;
	} */ *uap;
{

	return (kern_mkfifoat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode));
}

#ifndef _SYS_SYSPROTO_H_
struct mkfifoat_args {
	int	fd;
	char	*path;
	mode_t	mode;
};
#endif
int
sys_mkfifoat(struct thread *td, struct mkfifoat_args *uap)
{

	return (kern_mkfifoat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->mode));
}

int
kern_mkfifoat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    int mode)
{

	return (0);
}

/*
 * Make a hard file link.
 */
#ifndef _SYS_SYSPROTO_H_
struct link_args {
	char	*path;
	char	*link;
};
#endif
int
sys_link(td, uap)
	struct thread *td;
	register struct link_args /* {
		char *path;
		char *link;
	} */ *uap;
{

	return (kern_linkat(td, AT_FDCWD, AT_FDCWD, uap->path, uap->link,
	    UIO_USERSPACE, FOLLOW));
}

#ifndef _SYS_SYSPROTO_H_
struct linkat_args {
	int	fd1;
	char	*path1;
	int	fd2;
	char	*path2;
	int	flag;
};
#endif
int
sys_linkat(struct thread *td, struct linkat_args *uap)
{
	int flag;

	flag = uap->flag;
	if (flag & ~AT_SYMLINK_FOLLOW)
		return (EINVAL);

	return (kern_linkat(td, uap->fd1, uap->fd2, uap->path1, uap->path2,
	    UIO_USERSPACE, (flag & AT_SYMLINK_FOLLOW) ? FOLLOW : NOFOLLOW));
}

int hardlink_check_uid = 0;
static int hardlink_check_gid = 0;

static int
can_hardlink(struct vnode *vp, struct ucred *cred)
{
	struct vattr va;
	int error;

	if (!hardlink_check_uid && !hardlink_check_gid)
		return (0);

	error = VOP_GETATTR(vp, &va, cred);
	if (error != 0)
		return (error);

	if (hardlink_check_uid && cred->cr_uid != va.va_uid) {
		error = priv_check_cred(cred, PRIV_VFS_LINK, 0);
		if (error != 0)
			return (error);
	}

	if (hardlink_check_gid && !groupmember(va.va_gid, cred)) {
		error = priv_check_cred(cred, PRIV_VFS_LINK, 0);
		if (error != 0)
			return (error);
	}

	return (0);
}

int
kern_linkat(struct thread *td, int fd1, int fd2, char *path1, char *path2,
    enum uio_seg segflg, int follow)
{
	struct vnode *vp;
	struct mount *mp;
	struct nameidata nd;
	cap_rights_t rights;
	int error;

again:
	bwillwrite();
	NDINIT_ATRIGHTS(&nd, LOOKUP, follow | AUDITVNODE1, segflg, path1, fd1,
	    cap_rights_init(&rights, CAP_LINKAT_SOURCE), td);

	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vp = nd.ni_vp;
	if (vp->v_type == VDIR) {
		vrele(vp);
		return (EPERM);		/* POSIX */
	}
	NDINIT_ATRIGHTS(&nd, CREATE,
	    LOCKPARENT | SAVENAME | AUDITVNODE2 | NOCACHE, segflg, path2, fd2,
	    cap_rights_init(&rights, CAP_LINKAT_TARGET), td);
	if ((error = namei(&nd)) == 0) {
		if (nd.ni_vp != NULL) {
			NDFREE(&nd, NDF_ONLY_PNBUF);
			if (nd.ni_dvp == nd.ni_vp)
				vrele(nd.ni_dvp);
			else
				vput(nd.ni_dvp);
			vrele(nd.ni_vp);
			vrele(vp);
			return (EEXIST);
		} else if (nd.ni_dvp->v_mount != vp->v_mount) {
			/*
			 * Cross-device link.  No need to recheck
			 * vp->v_type, since it cannot change, except
			 * to VBAD.
			 */
			NDFREE(&nd, NDF_ONLY_PNBUF);
			vput(nd.ni_dvp);
			vrele(vp);
			return (EXDEV);
		} else if ((error = vn_lock(vp, LK_EXCLUSIVE)) == 0) {
			error = can_hardlink(vp, td->td_ucred);
#ifdef MAC
			if (error == 0)
				error = mac_vnode_check_link(td->td_ucred,
				    nd.ni_dvp, vp, &nd.ni_cnd);
#endif
			if (error != 0) {
				vput(vp);
				vput(nd.ni_dvp);
				NDFREE(&nd, NDF_ONLY_PNBUF);
				return (error);
			}
			error = vn_start_write(vp, &mp, V_NOWAIT);
			if (error != 0) {
				vput(vp);
				vput(nd.ni_dvp);
				NDFREE(&nd, NDF_ONLY_PNBUF);
				error = vn_start_write(NULL, &mp,
				    V_XSLEEP | PCATCH);
				if (error != 0)
					return (error);
				goto again;
			}
			error = VOP_LINK(nd.ni_dvp, vp, &nd.ni_cnd);
			VOP_UNLOCK(vp, 0);
			vput(nd.ni_dvp);
			vn_finished_write(mp);
			NDFREE(&nd, NDF_ONLY_PNBUF);
		} else {
			vput(nd.ni_dvp);
			NDFREE(&nd, NDF_ONLY_PNBUF);
			vrele(vp);
			goto again;
		}
	}
	vrele(vp);
	return (error);
}

/*
 * Make a symbolic link.
 */
#ifndef _SYS_SYSPROTO_H_
struct symlink_args {
	char	*path;
	char	*link;
};
#endif
int
sys_symlink(td, uap)
	struct thread *td;
	register struct symlink_args /* {
		char *path;
		char *link;
	} */ *uap;
{

	return (kern_symlinkat(td, uap->path, AT_FDCWD, uap->link,
	    UIO_USERSPACE));
}

#ifndef _SYS_SYSPROTO_H_
struct symlinkat_args {
	char	*path;
	int	fd;
	char	*path2;
};
#endif
int
sys_symlinkat(struct thread *td, struct symlinkat_args *uap)
{

	return (kern_symlinkat(td, uap->path1, uap->fd, uap->path2,
	    UIO_USERSPACE));
}

int
kern_symlinkat(struct thread *td, char *path1, int fd, char *path2,
    enum uio_seg segflg)
{
	return (0);
}

/*
 * Delete a whiteout from the filesystem.
 */
int
sys_undelete(td, uap)
	struct thread *td;
	register struct undelete_args /* {
		char *path;
	} */ *uap;
{
	struct mount *mp;
	struct nameidata nd;
	int error;

restart:
	bwillwrite();
	NDINIT(&nd, DELETE, LOCKPARENT | DOWHITEOUT | AUDITVNODE1,
	    UIO_USERSPACE, uap->path, td);
	error = namei(&nd);
	if (error != 0)
		return (error);

	if (nd.ni_vp != NULLVP || !(nd.ni_cnd.cn_flags & ISWHITEOUT)) {
		NDFREE(&nd, NDF_ONLY_PNBUF);
		if (nd.ni_vp == nd.ni_dvp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if (nd.ni_vp)
			vrele(nd.ni_vp);
		return (EEXIST);
	}
	if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE(&nd, NDF_ONLY_PNBUF);
		vput(nd.ni_dvp);
		if ((error = vn_start_write(NULL, &mp, V_XSLEEP | PCATCH)) != 0)
			return (error);
		goto restart;
	}
	error = VOP_WHITEOUT(nd.ni_dvp, &nd.ni_cnd, DELETE);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vput(nd.ni_dvp);
	vn_finished_write(mp);
	return (error);
}

/*
 * Delete a name from the filesystem.
 */
#ifndef _SYS_SYSPROTO_H_
struct unlink_args {
	char	*path;
};
#endif
int
sys_unlink(td, uap)
	struct thread *td;
	struct unlink_args /* {
		char *path;
	} */ *uap;
{

	return (kern_unlinkat(td, AT_FDCWD, uap->path, UIO_USERSPACE, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct unlinkat_args {
	int	fd;
	char	*path;
	int	flag;
};
#endif
int
sys_unlinkat(struct thread *td, struct unlinkat_args *uap)
{
	int flag = uap->flag;
	int fd = uap->fd;
	char *path = uap->path;

	if (flag & ~AT_REMOVEDIR)
		return (EINVAL);

	if (flag & AT_REMOVEDIR)
		return (kern_rmdirat(td, fd, path, UIO_USERSPACE));
	else
		return (kern_unlinkat(td, fd, path, UIO_USERSPACE, 0));
}

int
kern_unlinkat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    ino_t oldinum)
{

	return (0);
}

/*
 * Reposition read/write file offset.
 */
#ifndef _SYS_SYSPROTO_H_
struct lseek_args {
	int	fd;
	int	pad;
	off_t	offset;
	int	whence;
};
#endif
int
sys_lseek(td, uap)
	struct thread *td;
	register struct lseek_args /* {
		int fd;
		int pad;
		off_t offset;
		int whence;
	} */ *uap;
{
	struct file *fp;
	cap_rights_t rights;
	int error;

	AUDIT_ARG_FD(uap->fd);
	error = fget(td, uap->fd, cap_rights_init(&rights, CAP_SEEK), &fp);
	if (error != 0)
		return (error);
	error = (fp->f_ops->fo_flags & DFLAG_SEEKABLE) != 0 ?
	    fo_seek(fp, uap->offset, uap->whence, td) : ESPIPE;
	fdrop(fp, td);
	return (error);
}

#if defined(COMPAT_43)
/*
 * Reposition read/write file offset.
 */
#ifndef _SYS_SYSPROTO_H_
struct olseek_args {
	int	fd;
	long	offset;
	int	whence;
};
#endif
int
olseek(td, uap)
	struct thread *td;
	register struct olseek_args /* {
		int fd;
		long offset;
		int whence;
	} */ *uap;
{
	struct lseek_args /* {
		int fd;
		int pad;
		off_t offset;
		int whence;
	} */ nuap;

	nuap.fd = uap->fd;
	nuap.offset = uap->offset;
	nuap.whence = uap->whence;
	return (sys_lseek(td, &nuap));
}
#endif /* COMPAT_43 */


/*
 * Check access permissions using passed credentials.
 */
static int
vn_access(vp, user_flags, cred, td)
	struct vnode	*vp;
	int		user_flags;
	struct ucred	*cred;
	struct thread	*td;
{
	return (0);
}

/*
 * Check access permissions using "real" credentials.
 */
#ifndef _SYS_SYSPROTO_H_
struct access_args {
	char	*path;
	int	amode;
};
#endif
int
sys_access(td, uap)
	struct thread *td;
	register struct access_args /* {
		char *path;
		int amode;
	} */ *uap;
{

	return (kern_accessat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    0, uap->amode));
}

#ifndef _SYS_SYSPROTO_H_
struct faccessat_args {
	int	dirfd;
	char	*path;
	int	amode;
	int	flag;
}
#endif
int
sys_faccessat(struct thread *td, struct faccessat_args *uap)
{

	return (kern_accessat(td, uap->fd, uap->path, UIO_USERSPACE, uap->flag,
	    uap->amode));
}

int
kern_accessat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    int flag, int amode)
{
	return (0);
}

/*
 * Check access permissions using "effective" credentials.
 */
#ifndef _SYS_SYSPROTO_H_
struct eaccess_args {
	char	*path;
	int	amode;
};
#endif
int
sys_eaccess(td, uap)
	struct thread *td;
	register struct eaccess_args /* {
		char *path;
		int amode;
	} */ *uap;
{

	return (kern_accessat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    AT_EACCESS, uap->amode));
}

/*
 * Get file status; this version follows links.
 */
#ifndef _SYS_SYSPROTO_H_
struct stat_args {
	char	*path;
	struct stat *ub;
};
#endif
int
sys_stat(td, uap)
	struct thread *td;
	register struct stat_args /* {
		char *path;
		struct stat *ub;
	} */ *uap;
{
	struct stat sb;
	int error;

	error = kern_statat(td, 0, AT_FDCWD, uap->path, UIO_USERSPACE,
	    &sb, NULL);
	if (error == 0)
		error = copyout(&sb, uap->ub, sizeof (sb));
	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct fstatat_args {
	int	fd;
	char	*path;
	struct stat	*buf;
	int	flag;
}
#endif
int
sys_fstatat(struct thread *td, struct fstatat_args *uap)
{
	struct stat sb;
	int error;

	error = kern_statat(td, uap->flag, uap->fd, uap->path,
	    UIO_USERSPACE, &sb, NULL);
	if (error == 0)
		error = copyout(&sb, uap->buf, sizeof (sb));
	return (error);
}

int
kern_statat(struct thread *td, int flag, int fd, char *path,
    enum uio_seg pathseg, struct stat *sbp,
    void (*hook)(struct vnode *vp, struct stat *sbp))
{

	return (0);
}

/*
 * Get file status; this version does not follow links.
 */
#ifndef _SYS_SYSPROTO_H_
struct lstat_args {
	char	*path;
	struct stat *ub;
};
#endif
int
sys_lstat(td, uap)
	struct thread *td;
	register struct lstat_args /* {
		char *path;
		struct stat *ub;
	} */ *uap;
{
	struct stat sb;
	int error;

	error = kern_statat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD, uap->path,
	    UIO_USERSPACE, &sb, NULL);
	if (error == 0)
		error = copyout(&sb, uap->ub, sizeof (sb));
	return (error);
}

/*
 * Implementation of the NetBSD [l]stat() functions.
 */
void
cvtnstat(sb, nsb)
	struct stat *sb;
	struct nstat *nsb;
{

	bzero(nsb, sizeof *nsb);
	nsb->st_dev = sb->st_dev;
	nsb->st_ino = sb->st_ino;
	nsb->st_mode = sb->st_mode;
	nsb->st_nlink = sb->st_nlink;
	nsb->st_uid = sb->st_uid;
	nsb->st_gid = sb->st_gid;
	nsb->st_rdev = sb->st_rdev;
	nsb->st_atim = sb->st_atim;
	nsb->st_mtim = sb->st_mtim;
	nsb->st_ctim = sb->st_ctim;
	nsb->st_size = sb->st_size;
	nsb->st_blocks = sb->st_blocks;
	nsb->st_blksize = sb->st_blksize;
	nsb->st_flags = sb->st_flags;
	nsb->st_gen = sb->st_gen;
	nsb->st_birthtim = sb->st_birthtim;
}

#ifndef _SYS_SYSPROTO_H_
struct nstat_args {
	char	*path;
	struct nstat *ub;
};
#endif
int
sys_nstat(td, uap)
	struct thread *td;
	register struct nstat_args /* {
		char *path;
		struct nstat *ub;
	} */ *uap;
{
	struct stat sb;
	struct nstat nsb;
	int error;

	error = kern_statat(td, 0, AT_FDCWD, uap->path, UIO_USERSPACE,
	    &sb, NULL);
	if (error != 0)
		return (error);
	cvtnstat(&sb, &nsb);
	return (copyout(&nsb, uap->ub, sizeof (nsb)));
}

/*
 * NetBSD lstat.  Get file status; this version does not follow links.
 */
#ifndef _SYS_SYSPROTO_H_
struct lstat_args {
	char	*path;
	struct stat *ub;
};
#endif
int
sys_nlstat(td, uap)
	struct thread *td;
	register struct nlstat_args /* {
		char *path;
		struct nstat *ub;
	} */ *uap;
{
	struct stat sb;
	struct nstat nsb;
	int error;

	error = kern_statat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD, uap->path,
	    UIO_USERSPACE, &sb, NULL);
	if (error != 0)
		return (error);
	cvtnstat(&sb, &nsb);
	return (copyout(&nsb, uap->ub, sizeof (nsb)));
}

/*
 * Get configurable pathname variables.
 */
#ifndef _SYS_SYSPROTO_H_
struct pathconf_args {
	char	*path;
	int	name;
};
#endif
int
sys_pathconf(td, uap)
	struct thread *td;
	register struct pathconf_args /* {
		char *path;
		int name;
	} */ *uap;
{

	return (kern_pathconf(td, uap->path, UIO_USERSPACE, uap->name, FOLLOW));
}

#ifndef _SYS_SYSPROTO_H_
struct lpathconf_args {
	char	*path;
	int	name;
};
#endif
int
sys_lpathconf(td, uap)
	struct thread *td;
	register struct lpathconf_args /* {
		char *path;
		int name;
	} */ *uap;
{

	return (kern_pathconf(td, uap->path, UIO_USERSPACE, uap->name,
	    NOFOLLOW));
}

int
kern_pathconf(struct thread *td, char *path, enum uio_seg pathseg, int name,
    u_long flags)
{
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, LOCKSHARED | LOCKLEAF | AUDITVNODE1 | flags,
	    pathseg, path, td);
	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);

	error = VOP_PATHCONF(nd.ni_vp, name, td->td_retval);
	vput(nd.ni_vp);
	return (error);
}

/*
 * Return target name of a symbolic link.
 */
#ifndef _SYS_SYSPROTO_H_
struct readlink_args {
	char	*path;
	char	*buf;
	size_t	count;
};
#endif
int
sys_readlink(td, uap)
	struct thread *td;
	register struct readlink_args /* {
		char *path;
		char *buf;
		size_t count;
	} */ *uap;
{

	return (kern_readlinkat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->buf, UIO_USERSPACE, uap->count));
}
#ifndef _SYS_SYSPROTO_H_
struct readlinkat_args {
	int	fd;
	char	*path;
	char	*buf;
	size_t	bufsize;
};
#endif
int
sys_readlinkat(struct thread *td, struct readlinkat_args *uap)
{

	return (kern_readlinkat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->buf, UIO_USERSPACE, uap->bufsize));
}

int
kern_readlinkat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    char *buf, enum uio_seg bufseg, size_t count)
{
	struct vnode *vp;
	struct iovec aiov;
	struct uio auio;
	struct nameidata nd;
	int error;

	if (count > IOSIZE_MAX)
		return (EINVAL);

	NDINIT_AT(&nd, LOOKUP, NOFOLLOW | LOCKSHARED | LOCKLEAF | AUDITVNODE1,
	    pathseg, path, fd, td);

	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vp = nd.ni_vp;
#ifdef MAC
	error = mac_vnode_check_readlink(td->td_ucred, vp);
	if (error != 0) {
		vput(vp);
		return (error);
	}
#endif
	if (vp->v_type != VLNK)
		error = EINVAL;
	else {
		aiov.iov_base = buf;
		aiov.iov_len = count;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = bufseg;
		auio.uio_td = td;
		auio.uio_resid = count;
		error = VOP_READLINK(vp, &auio, td->td_ucred);
		td->td_retval[0] = count - auio.uio_resid;
	}
	vput(vp);
	return (error);
}

/*
 * Common implementation code for chflags() and fchflags().
 */
static int
setfflags(td, vp, flags)
	struct thread *td;
	struct vnode *vp;
	u_long flags;
{
	struct mount *mp;
	struct vattr vattr;
	int error;

	/* We can't support the value matching VNOVAL. */
	if (flags == VNOVAL)
		return (EOPNOTSUPP);

	/*
	 * Prevent non-root users from setting flags on devices.  When
	 * a device is reused, users can retain ownership of the device
	 * if they are allowed to set flags and programs assume that
	 * chown can't fail when done as root.
	 */
	if (vp->v_type == VCHR || vp->v_type == VBLK) {
		error = priv_check(td, PRIV_VFS_CHFLAGS_DEV);
		if (error != 0)
			return (error);
	}

	if ((error = vn_start_write(vp, &mp, V_WAIT | PCATCH)) != 0)
		return (error);
	VATTR_NULL(&vattr);
	vattr.va_flags = flags;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
#ifdef MAC
	error = mac_vnode_check_setflags(td->td_ucred, vp, vattr.va_flags);
	if (error == 0)
#endif
		error = VOP_SETATTR(vp, &vattr, td->td_ucred);
	VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);
	return (error);
}

/*
 * Change flags of a file given a path name.
 */
#ifndef _SYS_SYSPROTO_H_
struct chflags_args {
	const char *path;
	u_long	flags;
};
#endif
int
sys_chflags(td, uap)
	struct thread *td;
	register struct chflags_args /* {
		const char *path;
		u_long flags;
	} */ *uap;
{

	return (kern_chflagsat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct chflagsat_args {
	int	fd;
	const char *path;
	u_long	flags;
	int	atflag;
}
#endif
int
sys_chflagsat(struct thread *td, struct chflagsat_args *uap)
{
	int fd = uap->fd;
	const char *path = uap->path;
	u_long flags = uap->flags;
	int atflag = uap->atflag;

	if (atflag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (kern_chflagsat(td, fd, path, UIO_USERSPACE, flags, atflag));
}

/*
 * Same as chflags() but doesn't follow symlinks.
 */
int
sys_lchflags(td, uap)
	struct thread *td;
	register struct lchflags_args /* {
		const char *path;
		u_long flags;
	} */ *uap;
{

	return (kern_chflagsat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, AT_SYMLINK_NOFOLLOW));
}

static int
kern_chflagsat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, u_long flags, int atflag)
{
	struct nameidata nd;
	cap_rights_t rights;
	int error, follow;

	AUDIT_ARG_FFLAGS(flags);
	follow = (atflag & AT_SYMLINK_NOFOLLOW) ? NOFOLLOW : FOLLOW;
	NDINIT_ATRIGHTS(&nd, LOOKUP, follow | AUDITVNODE1, pathseg, path, fd,
	    cap_rights_init(&rights, CAP_FCHFLAGS), td);
	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	error = setfflags(td, nd.ni_vp, flags);
	vrele(nd.ni_vp);
	return (error);
}

/*
 * Change flags of a file given a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fchflags_args {
	int	fd;
	u_long	flags;
};
#endif
int
sys_fchflags(td, uap)
	struct thread *td;
	register struct fchflags_args /* {
		int fd;
		u_long flags;
	} */ *uap;
{
	struct file *fp;
	cap_rights_t rights;
	int error;

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_FFLAGS(uap->flags);
	error = getvnode(td, uap->fd, cap_rights_init(&rights, CAP_FCHFLAGS),
	    &fp);
	if (error != 0)
		return (error);
#ifdef AUDIT
	vn_lock(fp->f_vnode, LK_SHARED | LK_RETRY);
	AUDIT_ARG_VNODE1(fp->f_vnode);
	VOP_UNLOCK(fp->f_vnode, 0);
#endif
	error = setfflags(td, fp->f_vnode, uap->flags);
	fdrop(fp, td);
	return (error);
}

/*
 * Common implementation code for chmod(), lchmod() and fchmod().
 */
int
setfmode(td, cred, vp, mode)
	struct thread *td;
	struct ucred *cred;
	struct vnode *vp;
	int mode;
{
	struct mount *mp;
	struct vattr vattr;
	int error;

	if ((error = vn_start_write(vp, &mp, V_WAIT | PCATCH)) != 0)
		return (error);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	VATTR_NULL(&vattr);
	vattr.va_mode = mode & ALLPERMS;
#ifdef MAC
	error = mac_vnode_check_setmode(cred, vp, vattr.va_mode);
	if (error == 0)
#endif
		error = VOP_SETATTR(vp, &vattr, cred);
	VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);
	return (error);
}

/*
 * Change mode of a file given path name.
 */
#ifndef _SYS_SYSPROTO_H_
struct chmod_args {
	char	*path;
	int	mode;
};
#endif
int
sys_chmod(td, uap)
	struct thread *td;
	register struct chmod_args /* {
		char *path;
		int mode;
	} */ *uap;
{

	return (kern_fchmodat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct fchmodat_args {
	int	dirfd;
	char	*path;
	mode_t	mode;
	int	flag;
}
#endif
int
sys_fchmodat(struct thread *td, struct fchmodat_args *uap)
{
	int flag = uap->flag;
	int fd = uap->fd;
	char *path = uap->path;
	mode_t mode = uap->mode;

	if (flag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (kern_fchmodat(td, fd, path, UIO_USERSPACE, mode, flag));
}

/*
 * Change mode of a file given path name (don't follow links.)
 */
#ifndef _SYS_SYSPROTO_H_
struct lchmod_args {
	char	*path;
	int	mode;
};
#endif
int
sys_lchmod(td, uap)
	struct thread *td;
	register struct lchmod_args /* {
		char *path;
		int mode;
	} */ *uap;
{

	return (kern_fchmodat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode, AT_SYMLINK_NOFOLLOW));
}

int
kern_fchmodat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    mode_t mode, int flag)
{
	struct nameidata nd;
	cap_rights_t rights;
	int error, follow;

	AUDIT_ARG_MODE(mode);
	follow = (flag & AT_SYMLINK_NOFOLLOW) ? NOFOLLOW : FOLLOW;
	NDINIT_ATRIGHTS(&nd, LOOKUP, follow | AUDITVNODE1, pathseg, path, fd,
	    cap_rights_init(&rights, CAP_FCHMOD), td);
	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	error = setfmode(td, td->td_ucred, nd.ni_vp, mode);
	vrele(nd.ni_vp);
	return (error);
}

/*
 * Change mode of a file given a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fchmod_args {
	int	fd;
	int	mode;
};
#endif
int
sys_fchmod(struct thread *td, struct fchmod_args *uap)
{
	struct file *fp;
	cap_rights_t rights;
	int error;

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_MODE(uap->mode);

	error = fget(td, uap->fd, cap_rights_init(&rights, CAP_FCHMOD), &fp);
	if (error != 0)
		return (error);
	error = fo_chmod(fp, uap->mode, td->td_ucred, td);
	fdrop(fp, td);
	return (error);
}

/*
 * Common implementation for chown(), lchown(), and fchown()
 */
int
setfown(td, cred, vp, uid, gid)
	struct thread *td;
	struct ucred *cred;
	struct vnode *vp;
	uid_t uid;
	gid_t gid;
{
	struct mount *mp;
	struct vattr vattr;
	int error;

	if ((error = vn_start_write(vp, &mp, V_WAIT | PCATCH)) != 0)
		return (error);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	VATTR_NULL(&vattr);
	vattr.va_uid = uid;
	vattr.va_gid = gid;
#ifdef MAC
	error = mac_vnode_check_setowner(cred, vp, vattr.va_uid,
	    vattr.va_gid);
	if (error == 0)
#endif
		error = VOP_SETATTR(vp, &vattr, cred);
	VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);
	return (error);
}

/*
 * Set ownership given a path name.
 */
#ifndef _SYS_SYSPROTO_H_
struct chown_args {
	char	*path;
	int	uid;
	int	gid;
};
#endif
int
sys_chown(td, uap)
	struct thread *td;
	register struct chown_args /* {
		char *path;
		int uid;
		int gid;
	} */ *uap;
{

	return (kern_fchownat(td, AT_FDCWD, uap->path, UIO_USERSPACE, uap->uid,
	    uap->gid, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct fchownat_args {
	int fd;
	const char * path;
	uid_t uid;
	gid_t gid;
	int flag;
};
#endif
int
sys_fchownat(struct thread *td, struct fchownat_args *uap)
{
	int flag;

	flag = uap->flag;
	if (flag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (kern_fchownat(td, uap->fd, uap->path, UIO_USERSPACE, uap->uid,
	    uap->gid, uap->flag));
}

int
kern_fchownat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    int uid, int gid, int flag)
{
	struct nameidata nd;
	cap_rights_t rights;
	int error, follow;

	AUDIT_ARG_OWNER(uid, gid);
	follow = (flag & AT_SYMLINK_NOFOLLOW) ? NOFOLLOW : FOLLOW;
	NDINIT_ATRIGHTS(&nd, LOOKUP, follow | AUDITVNODE1, pathseg, path, fd,
	    cap_rights_init(&rights, CAP_FCHOWN), td);

	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	error = setfown(td, td->td_ucred, nd.ni_vp, uid, gid);
	vrele(nd.ni_vp);
	return (error);
}

/*
 * Set ownership given a path name, do not cross symlinks.
 */
#ifndef _SYS_SYSPROTO_H_
struct lchown_args {
	char	*path;
	int	uid;
	int	gid;
};
#endif
int
sys_lchown(td, uap)
	struct thread *td;
	register struct lchown_args /* {
		char *path;
		int uid;
		int gid;
	} */ *uap;
{

	return (kern_fchownat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->uid, uap->gid, AT_SYMLINK_NOFOLLOW));
}

/*
 * Set ownership given a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fchown_args {
	int	fd;
	int	uid;
	int	gid;
};
#endif
int
sys_fchown(td, uap)
	struct thread *td;
	register struct fchown_args /* {
		int fd;
		int uid;
		int gid;
	} */ *uap;
{
	struct file *fp;
	cap_rights_t rights;
	int error;

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_OWNER(uap->uid, uap->gid);
	error = fget(td, uap->fd, cap_rights_init(&rights, CAP_FCHOWN), &fp);
	if (error != 0)
		return (error);
	error = fo_chown(fp, uap->uid, uap->gid, td->td_ucred, td);
	fdrop(fp, td);
	return (error);
}

/*
 * Common implementation code for utimes(), lutimes(), and futimes().
 */
static int
getutimes(usrtvp, tvpseg, tsp)
	const struct timeval *usrtvp;
	enum uio_seg tvpseg;
	struct timespec *tsp;
{

	return (0);
}

/*
 * Common implementation code for futimens(), utimensat().
 */
#define	UTIMENS_NULL	0x1
#define	UTIMENS_EXIT	0x2
static int
getutimens(const struct timespec *usrtsp, enum uio_seg tspseg,
    struct timespec *tsp, int *retflags)
{
	return (0);
}

/*
 * Common implementation code for utimes(), lutimes(), futimes(), futimens(),
 * and utimensat().
 */
static int
setutimes(td, vp, ts, numtimes, nullflag)
	struct thread *td;
	struct vnode *vp;
	const struct timespec *ts;
	int numtimes;
	int nullflag;
{

	return (0);
}

/*
 * Set the access and modification times of a file.
 */
#ifndef _SYS_SYSPROTO_H_
struct utimes_args {
	char	*path;
	struct	timeval *tptr;
};
#endif
int
sys_utimes(td, uap)
	struct thread *td;
	register struct utimes_args /* {
		char *path;
		struct timeval *tptr;
	} */ *uap;
{

	return (kern_utimesat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->tptr, UIO_USERSPACE));
}

#ifndef _SYS_SYSPROTO_H_
struct futimesat_args {
	int fd;
	const char * path;
	const struct timeval * times;
};
#endif
int
sys_futimesat(struct thread *td, struct futimesat_args *uap)
{

	return (kern_utimesat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->times, UIO_USERSPACE));
}

int
kern_utimesat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    struct timeval *tptr, enum uio_seg tptrseg)
{
	struct nameidata nd;
	struct timespec ts[2];
	cap_rights_t rights;
	int error;

	if ((error = getutimes(tptr, tptrseg, ts)) != 0)
		return (error);
	NDINIT_ATRIGHTS(&nd, LOOKUP, FOLLOW | AUDITVNODE1, pathseg, path, fd,
	    cap_rights_init(&rights, CAP_FUTIMES), td);

	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	error = setutimes(td, nd.ni_vp, ts, 2, tptr == NULL);
	vrele(nd.ni_vp);
	return (error);
}

/*
 * Set the access and modification times of a file.
 */
#ifndef _SYS_SYSPROTO_H_
struct lutimes_args {
	char	*path;
	struct	timeval *tptr;
};
#endif
int
sys_lutimes(td, uap)
	struct thread *td;
	register struct lutimes_args /* {
		char *path;
		struct timeval *tptr;
	} */ *uap;
{

	return (kern_lutimes(td, uap->path, UIO_USERSPACE, uap->tptr,
	    UIO_USERSPACE));
}

int
kern_lutimes(struct thread *td, char *path, enum uio_seg pathseg,
    struct timeval *tptr, enum uio_seg tptrseg)
{
	struct timespec ts[2];
	struct nameidata nd;
	int error;

	if ((error = getutimes(tptr, tptrseg, ts)) != 0)
		return (error);
	NDINIT(&nd, LOOKUP, NOFOLLOW | AUDITVNODE1, pathseg, path, td);
	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	error = setutimes(td, nd.ni_vp, ts, 2, tptr == NULL);
	vrele(nd.ni_vp);
	return (error);
}

/*
 * Set the access and modification times of a file.
 */
#ifndef _SYS_SYSPROTO_H_
struct futimes_args {
	int	fd;
	struct	timeval *tptr;
};
#endif
int
sys_futimes(td, uap)
	struct thread *td;
	register struct futimes_args /* {
		int  fd;
		struct timeval *tptr;
	} */ *uap;
{

	return (kern_futimes(td, uap->fd, uap->tptr, UIO_USERSPACE));
}

int
kern_futimes(struct thread *td, int fd, struct timeval *tptr,
    enum uio_seg tptrseg)
{
	struct timespec ts[2];
	struct file *fp;
	cap_rights_t rights;
	int error;

	AUDIT_ARG_FD(fd);
	error = getutimes(tptr, tptrseg, ts);
	if (error != 0)
		return (error);
	error = getvnode(td, fd, cap_rights_init(&rights, CAP_FUTIMES), &fp);
	if (error != 0)
		return (error);
#ifdef AUDIT
	vn_lock(fp->f_vnode, LK_SHARED | LK_RETRY);
	AUDIT_ARG_VNODE1(fp->f_vnode);
	VOP_UNLOCK(fp->f_vnode, 0);
#endif
	error = setutimes(td, fp->f_vnode, ts, 2, tptr == NULL);
	fdrop(fp, td);
	return (error);
}

int
sys_futimens(struct thread *td, struct futimens_args *uap)
{

	return (kern_futimens(td, uap->fd, uap->times, UIO_USERSPACE));
}

int
kern_futimens(struct thread *td, int fd, struct timespec *tptr,
    enum uio_seg tptrseg)
{
	struct timespec ts[2];
	struct file *fp;
	cap_rights_t rights;
	int error, flags;

	AUDIT_ARG_FD(fd);
	error = getutimens(tptr, tptrseg, ts, &flags);
	if (error != 0)
		return (error);
	if (flags & UTIMENS_EXIT)
		return (0);
	error = getvnode(td, fd, cap_rights_init(&rights, CAP_FUTIMES), &fp);
	if (error != 0)
		return (error);
#ifdef AUDIT
	vn_lock(fp->f_vnode, LK_SHARED | LK_RETRY);
	AUDIT_ARG_VNODE1(fp->f_vnode);
	VOP_UNLOCK(fp->f_vnode, 0);
#endif
	error = setutimes(td, fp->f_vnode, ts, 2, flags & UTIMENS_NULL);
	fdrop(fp, td);
	return (error);
}

int
sys_utimensat(struct thread *td, struct utimensat_args *uap)
{

	return (kern_utimensat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->times, UIO_USERSPACE, uap->flag));
}

int
kern_utimensat(struct thread *td, int fd, char *path, enum uio_seg pathseg,
    struct timespec *tptr, enum uio_seg tptrseg, int flag)
{
	struct nameidata nd;
	struct timespec ts[2];
	cap_rights_t rights;
	int error, flags;

	if (flag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	if ((error = getutimens(tptr, tptrseg, ts, &flags)) != 0)
		return (error);
	NDINIT_ATRIGHTS(&nd, LOOKUP, ((flag & AT_SYMLINK_NOFOLLOW) ? NOFOLLOW :
	    FOLLOW) | AUDITVNODE1, pathseg, path, fd,
	    cap_rights_init(&rights, CAP_FUTIMES), td);
	if ((error = namei(&nd)) != 0)
		return (error);
	/*
	 * We are allowed to call namei() regardless of 2xUTIME_OMIT.
	 * POSIX states:
	 * "If both tv_nsec fields are UTIME_OMIT... EACCESS may be detected."
	 * "Search permission is denied by a component of the path prefix."
	 */
	NDFREE(&nd, NDF_ONLY_PNBUF);
	if ((flags & UTIMENS_EXIT) == 0)
		error = setutimes(td, nd.ni_vp, ts, 2, flags & UTIMENS_NULL);
	vrele(nd.ni_vp);
	return (error);
}

/*
 * Truncate a file given its path name.
 */
#ifndef _SYS_SYSPROTO_H_
struct truncate_args {
	char	*path;
	int	pad;
	off_t	length;
};
#endif
int
sys_truncate(td, uap)
	struct thread *td;
	register struct truncate_args /* {
		char *path;
		int pad;
		off_t length;
	} */ *uap;
{

	return (kern_truncate(td, uap->path, UIO_USERSPACE, uap->length));
}

int
kern_truncate(struct thread *td, char *path, enum uio_seg pathseg, off_t length)
{

	return (0);
}

/*
 * Sync an open file.
 */
#ifndef _SYS_SYSPROTO_H_
struct fsync_args {
	int	fd;
};
#endif
int
sys_fsync(td, uap)
	struct thread *td;
	struct fsync_args /* {
		int fd;
	} */ *uap;
{
	struct vnode *vp;
	struct mount *mp;
	struct file *fp;
	cap_rights_t rights;
	int error = 0, lock_flags;

	return (error);
}

/*
 * Rename files.  Source and destination must either both be directories, or
 * both not be directories.  If target is a directory, it must be empty.
 */
#ifndef _SYS_SYSPROTO_H_
struct rename_args {
	char	*from;
	char	*to;
};
#endif
int
sys_rename(td, uap)
	struct thread *td;
	register struct rename_args /* {
		char *from;
		char *to;
	} */ *uap;
{

	return (kern_renameat(td, AT_FDCWD, uap->from, AT_FDCWD,
	    uap->to, UIO_USERSPACE));
}

#ifndef _SYS_SYSPROTO_H_
struct renameat_args {
	int	oldfd;
	char	*old;
	int	newfd;
	char	*new;
};
#endif
int
sys_renameat(struct thread *td, struct renameat_args *uap)
{

	return (kern_renameat(td, uap->oldfd, uap->old, uap->newfd, uap->new,
	    UIO_USERSPACE));
}

int
kern_renameat(struct thread *td, int oldfd, char *old, int newfd, char *new,
    enum uio_seg pathseg)
{
	struct mount *mp = NULL;
	struct vnode *tvp, *fvp, *tdvp;
	struct nameidata fromnd, tond;
	cap_rights_t rights;
	int error;

again:
	bwillwrite();
#ifdef MAC
	NDINIT_ATRIGHTS(&fromnd, DELETE, LOCKPARENT | LOCKLEAF | SAVESTART |
	    AUDITVNODE1, pathseg, old, oldfd,
	    cap_rights_init(&rights, CAP_RENAMEAT_SOURCE), td);
#else
	NDINIT_ATRIGHTS(&fromnd, DELETE, WANTPARENT | SAVESTART | AUDITVNODE1,
	    pathseg, old, oldfd,
	    cap_rights_init(&rights, CAP_RENAMEAT_SOURCE), td);
#endif

	if ((error = namei(&fromnd)) != 0)
		return (error);
#ifdef MAC
	error = mac_vnode_check_rename_from(td->td_ucred, fromnd.ni_dvp,
	    fromnd.ni_vp, &fromnd.ni_cnd);
	VOP_UNLOCK(fromnd.ni_dvp, 0);
	if (fromnd.ni_dvp != fromnd.ni_vp)
		VOP_UNLOCK(fromnd.ni_vp, 0);
#endif
	fvp = fromnd.ni_vp;
	NDINIT_ATRIGHTS(&tond, RENAME, LOCKPARENT | LOCKLEAF | NOCACHE |
	    SAVESTART | AUDITVNODE2, pathseg, new, newfd,
	    cap_rights_init(&rights, CAP_RENAMEAT_TARGET), td);
	if (fromnd.ni_vp->v_type == VDIR)
		tond.ni_cnd.cn_flags |= WILLBEDIR;
	if ((error = namei(&tond)) != 0) {
		/* Translate error code for rename("dir1", "dir2/."). */
		if (error == EISDIR && fvp->v_type == VDIR)
			error = EINVAL;
		NDFREE(&fromnd, NDF_ONLY_PNBUF);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		goto out1;
	}
	tdvp = tond.ni_dvp;
	tvp = tond.ni_vp;
	error = vn_start_write(fvp, &mp, V_NOWAIT);
	if (error != 0) {
		NDFREE(&fromnd, NDF_ONLY_PNBUF);
		NDFREE(&tond, NDF_ONLY_PNBUF);
		if (tvp != NULL)
			vput(tvp);
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		vrele(tond.ni_startdir);
		if (fromnd.ni_startdir != NULL)
			vrele(fromnd.ni_startdir);
		error = vn_start_write(NULL, &mp, V_XSLEEP | PCATCH);
		if (error != 0)
			return (error);
		goto again;
	}
	if (tvp != NULL) {
		if (fvp->v_type == VDIR && tvp->v_type != VDIR) {
			error = ENOTDIR;
			goto out;
		} else if (fvp->v_type != VDIR && tvp->v_type == VDIR) {
			error = EISDIR;
			goto out;
		}
#ifdef CAPABILITIES
		if (newfd != AT_FDCWD) {
			/*
			 * If the target already exists we require CAP_UNLINKAT
			 * from 'newfd'.
			 */
			error = cap_check(&tond.ni_filecaps.fc_rights,
			    cap_rights_init(&rights, CAP_UNLINKAT));
			if (error != 0)
				goto out;
		}
#endif
	}
	if (fvp == tdvp) {
		error = EINVAL;
		goto out;
	}
	/*
	 * If the source is the same as the destination (that is, if they
	 * are links to the same vnode), then there is nothing to do.
	 */
	if (fvp == tvp)
		error = -1;
#ifdef MAC
	else
		error = mac_vnode_check_rename_to(td->td_ucred, tdvp,
		    tond.ni_vp, fromnd.ni_dvp == tdvp, &tond.ni_cnd);
#endif
out:
	if (error == 0) {
		error = VOP_RENAME(fromnd.ni_dvp, fromnd.ni_vp, &fromnd.ni_cnd,
		    tond.ni_dvp, tond.ni_vp, &tond.ni_cnd);
		NDFREE(&fromnd, NDF_ONLY_PNBUF);
		NDFREE(&tond, NDF_ONLY_PNBUF);
	} else {
		NDFREE(&fromnd, NDF_ONLY_PNBUF);
		NDFREE(&tond, NDF_ONLY_PNBUF);
		if (tvp != NULL)
			vput(tvp);
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
	}
	vrele(tond.ni_startdir);
	vn_finished_write(mp);
out1:
	if (fromnd.ni_startdir)
		vrele(fromnd.ni_startdir);
	if (error == -1)
		return (0);
	return (error);
}

/*
 * Make a directory file.
 */
#ifndef _SYS_SYSPROTO_H_
struct mkdir_args {
	char	*path;
	int	mode;
};
#endif
int
sys_mkdir(td, uap)
	struct thread *td;
	register struct mkdir_args /* {
		char *path;
		int mode;
	} */ *uap;
{

	return (kern_mkdirat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode));
}

#ifndef _SYS_SYSPROTO_H_
struct mkdirat_args {
	int	fd;
	char	*path;
	mode_t	mode;
};
#endif
int
sys_mkdirat(struct thread *td, struct mkdirat_args *uap)
{

	return (kern_mkdirat(td, uap->fd, uap->path, UIO_USERSPACE, uap->mode));
}

int
kern_mkdirat(struct thread *td, int fd, char *path, enum uio_seg segflg,
    int mode)
{
	struct mount *mp;
	struct vnode *vp;
	struct vattr vattr;
	struct nameidata nd;
	cap_rights_t rights;
	int error;

	AUDIT_ARG_MODE(mode);
restart:
	bwillwrite();
	NDINIT_ATRIGHTS(&nd, CREATE, LOCKPARENT | SAVENAME | AUDITVNODE1 |
	    NOCACHE, segflg, path, fd, cap_rights_init(&rights, CAP_MKDIRAT),
	    td);
	nd.ni_cnd.cn_flags |= WILLBEDIR;
	if ((error = namei(&nd)) != 0)
		return (error);
	vp = nd.ni_vp;
	if (vp != NULL) {
		NDFREE(&nd, NDF_ONLY_PNBUF);
		/*
		 * XXX namei called with LOCKPARENT but not LOCKLEAF has
		 * the strange behaviour of leaving the vnode unlocked
		 * if the target is the same vnode as the parent.
		 */
		if (vp == nd.ni_dvp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(vp);
		return (EEXIST);
	}
	if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE(&nd, NDF_ONLY_PNBUF);
		vput(nd.ni_dvp);
		if ((error = vn_start_write(NULL, &mp, V_XSLEEP | PCATCH)) != 0)
			return (error);
		goto restart;
	}
	VATTR_NULL(&vattr);
	vattr.va_type = VDIR;
	vattr.va_mode = (mode & ACCESSPERMS) &~ td->td_proc->p_fd->fd_cmask;
#ifdef MAC
	error = mac_vnode_check_create(td->td_ucred, nd.ni_dvp, &nd.ni_cnd,
	    &vattr);
	if (error != 0)
		goto out;
#endif
	error = VOP_MKDIR(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
#ifdef MAC
out:
#endif
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vput(nd.ni_dvp);
	if (error == 0)
		vput(nd.ni_vp);
	vn_finished_write(mp);
	return (error);
}

/*
 * Remove a directory file.
 */
#ifndef _SYS_SYSPROTO_H_
struct rmdir_args {
	char	*path;
};
#endif
int
sys_rmdir(td, uap)
	struct thread *td;
	struct rmdir_args /* {
		char *path;
	} */ *uap;
{

	return (kern_rmdirat(td, AT_FDCWD, uap->path, UIO_USERSPACE));
}

int
kern_rmdirat(struct thread *td, int fd, char *path, enum uio_seg pathseg)
{

	return (0);
}




/*
 * Set the mode mask for creation of filesystem nodes.
 */
#ifndef _SYS_SYSPROTO_H_
struct umask_args {
	int	newmask;
};
#endif
int
sys_umask(td, uap)
	struct thread *td;
	struct umask_args /* {
		int newmask;
	} */ *uap;
{
	struct filedesc *fdp;

	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);
	td->td_retval[0] = fdp->fd_cmask;
	fdp->fd_cmask = uap->newmask & ALLPERMS;
	FILEDESC_XUNLOCK(fdp);
	return (0);
}

/*
 * Void all references to file by ripping underlying filesystem away from
 * vnode.
 */
#ifndef _SYS_SYSPROTO_H_
struct revoke_args {
	char	*path;
};
#endif
int
sys_revoke(td, uap)
	struct thread *td;
	register struct revoke_args /* {
		char *path;
	} */ *uap;
{

	return (0);
}

/*
 * Convert a user file descriptor to a kernel file entry and check that, if it
 * is a capability, the correct rights are present. A reference on the file
 * entry is held upon returning.
 */
int
getvnode(struct thread *td, int fd, cap_rights_t *rightsp, struct file **fpp)
{
	struct file *fp;
	int error;

	error = fget_unlocked(td->td_proc->p_fd, fd, rightsp, &fp, NULL);
	if (error != 0)
		return (error);

	/*
	 * The file could be not of the vnode type, or it may be not
	 * yet fully initialized, in which case the f_vnode pointer
	 * may be set, but f_ops is still badfileops.  E.g.,
	 * devfs_open() transiently create such situation to
	 * facilitate csw d_fdopen().
	 *
	 * Dupfdopen() handling in kern_openat() installs the
	 * half-baked file into the process descriptor table, allowing
	 * other thread to dereference it. Guard against the race by
	 * checking f_ops.
	 */
	if (fp->f_vnode == NULL || fp->f_ops == &badfileops) {
		fdrop(fp, td);
		return (EINVAL);
	}
	*fpp = fp;
	return (0);
}

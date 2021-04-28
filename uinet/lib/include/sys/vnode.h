/*
 * Copyright (c) 2010 Kip Macy All rights reserved.
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _FSTACK_SYS_VNODE_H_
#define _FSTACK_SYS_VNODE_H_

#include <sys/uio.h>
#include <sys/namei.h>

/*
 * Vnode types.  VNON means no type.
 */
enum vtype {
    VNON, VREG, VDIR, VBLK, VCHR,
    VLNK, VSOCK, VFIFO, VBAD, VMARKER
};

struct nameidata;
struct stat;
struct nstat;
struct vnode {
    enum vtype v_type;
    struct mount *v_mount;  /* u ptr to vfs we are in */
    u_long v_vflag;         /* v vnode flags */
    int v_fd;               /* file descriptor */
	void	*v_data;			/* u private data for fs */

	/*
	 * clustering stuff
	 */
	daddr_t	v_cstart;			/* v start block of cluster */
	daddr_t	v_lasta;			/* v last allocation  */
	daddr_t	v_lastw;			/* v last write  */
	int	v_clen;				/* v length of cur. cluster */

	u_int	v_holdcnt;			/* I prevents recycling. */
	u_int	v_usecount;			/* I ref count of users */
	u_int	v_iflag;			/* i vnode flags (see below) */
	int	v_writecount;			/* v ref count of writers */
	u_int	v_hash;
	
	/*
	 * Type specific fields, only one applies to any given vnode.
	 * See #defines below for renaming to v_* namespace.
	 */
	union {
		struct mount	*vu_mount;	/* v ptr to mountpoint (VDIR) */
		struct socket	*vu_socket; /* v unix domain net (VSOCK) */
		struct cdev *vu_cdev;	/* v device (VCHR, VBLK) */
		struct fifoinfo *vu_fifoinfo;	/* v fifo (VFIFO) */
	} v_un;
};

#define	v_mountedhere	v_un.vu_mount
#define	v_socket	v_un.vu_socket
#define	v_rdev		v_un.vu_cdev
#define	v_fifoinfo	v_un.vu_fifoinfo

/* XXX: These are temporary to avoid a source sweep at this time */
#define v_object	v_bufobj.bo_object

extern	struct uma_zone *namei_zone;
extern	struct vattr va_null;		/* predefined null vattr structure */



/*
 * Vnode flags.
 *	VI flags are protected by interlock and live in v_iflag
 *	VV flags are protected by the vnode lock and live in v_vflag
 *
 *	VI_DOOMED is doubly protected by the interlock and vnode lock.  Both
 *	are required for writing but the status may be checked with either.
 */
#define	VI_MOUNT	0x0020	/* Mount in progress */
#define	VI_DOOMED	0x0080	/* This vnode is being recycled */
#define	VI_FREE		0x0100	/* This vnode is on the freelist */
#define	VI_ACTIVE	0x0200	/* This vnode is on the active list */
#define	VI_DOINGINACT	0x0800	/* VOP_INACTIVE is in progress */
#define	VI_OWEINACT	0x1000	/* Need to call inactive */

#define	VV_ROOT		0x0001	/* root of its filesystem */
#define	VV_ISTTY	0x0002	/* vnode represents a tty */
#define	VV_NOSYNC	0x0004	/* unlinked, stop syncing */
#define	VV_ETERNALDEV	0x0008	/* device that is never destroyed */
#define	VV_CACHEDLABEL	0x0010	/* Vnode has valid cached MAC label */
#define	VV_TEXT		0x0020	/* vnode is a pure text prototype */
#define	VV_COPYONWRITE	0x0040	/* vnode is doing copy-on-write */
#define	VV_SYSTEM	0x0080	/* vnode being used by kernel */
#define	VV_PROCDEP	0x0100	/* vnode is process dependent */
#define	VV_NOKNOTE	0x0200	/* don't activate knotes on this vnode */
#define	VV_DELETED	0x0400	/* should be removed */
#define	VV_MD		0x0800	/* vnode backs the md device */
#define	VV_FORCEINSMQ	0x1000	/* force the insmntque to succeed */



/*
 * Flags for accmode_t.
 */
#define	VEXEC			000000000100 /* execute/search permission */
#define	VWRITE			000000000200 /* write permission */
#define	VREAD			000000000400 /* read permission */
#define	VADMIN			000000010000 /* being the file owner */
#define	VAPPEND			000000040000 /* permission to write/append */


/*
 * Flags to various vnode functions.
 */
#define	SKIPSYSTEM	0x0001	/* vflush: skip vnodes marked VSYSTEM */
#define	FORCECLOSE	0x0002	/* vflush: force file closure */
#define	WRITECLOSE	0x0004	/* vflush: only close writable files */
#define	EARLYFLUSH	0x0008	/* vflush: early call for ffs_flushfiles */
#define	V_SAVE		0x0001	/* vinvalbuf: sync file first */
#define	V_ALT		0x0002	/* vinvalbuf: invalidate only alternate bufs */
#define	V_NORMAL	0x0004	/* vinvalbuf: invalidate only regular bufs */
#define	V_CLEANONLY	0x0008	/* vinvalbuf: invalidate only clean bufs */
#define	REVOKEALL	0x0001	/* vop_revoke: revoke all aliases */
#define	V_WAIT		0x0001	/* vn_start_write: sleep for suspend */
#define	V_NOWAIT	0x0002	/* vn_start_write: don't sleep for suspend */
#define	V_XSLEEP	0x0004	/* vn_start_write: just return after sleep */
#define	V_MNTREF	0x0010	/* vn_start_write: mp is already ref-ed */



#define VOP_ADVLOCK(a, b, c, d, e) (0)
#define VOP_UNLOCK(a, b)
static __inline int
vn_lock(struct vnode *vp, int flags)
{
    return (0);
}

static __inline int
vrefcnt(struct vnode *vp)
{
    return (0);
}

#define VREF(vp) vref(vp)
static __inline void
vref(struct vnode *vp)
{

}

static __inline void
vrele(struct vnode *vp)
{

}

extern struct vnode *rootvnode;
/* 0 or POSIX version of AIO i'face */
extern int async_io_version;

static __inline int
vn_fullpath(struct thread *td, struct vnode *vp,
    char **retbuf, char **freebuf)
{
    return (0);
}

void cvtnstat(struct stat *sb, struct nstat *nsb);

/*
 * Vnode attributes.  A field value of VNOVAL represents a field whose value
 * is unavailable (getattr) or which is not to be changed (setattr).
 */
struct vattr {
	enum vtype	va_type;	/* vnode type (for create) */
	u_short		va_mode;	/* files access mode and type */
	short		va_nlink;	/* number of references to file */
	uid_t		va_uid;		/* owner user id */
	gid_t		va_gid;		/* owner group id */
	dev_t		va_fsid;	/* filesystem id */
	long		va_fileid;	/* file id */
	u_quad_t	va_size;	/* file size in bytes */
	long		va_blocksize;	/* blocksize preferred for i/o */
	struct timespec	va_atime;	/* time of last access */
	struct timespec	va_mtime;	/* time of last modification */
	struct timespec	va_ctime;	/* time file changed */
	struct timespec	va_birthtime;	/* time file created */
	u_long		va_gen;		/* generation number of file */
	u_long		va_flags;	/* flags defined for file */
	dev_t		va_rdev;	/* device the special file represents */
	u_quad_t	va_bytes;	/* bytes of disk space held by file */
	u_quad_t	va_filerev;	/* file modification number */
	u_int		va_vaflags;	/* operations flags, see below */
	long		va_spare;	/* remain quad aligned */
};

/*
 * Flags for va_vaflags.
 */
#define	VA_UTIMES_NULL	0x01		/* utimes argument was NULL */
#define	VA_EXCLUSIVE	0x02		/* exclusive create request */
#define	VA_SYNC		0x04		/* O_SYNC truncation */


/*
 * Flags for ioflag. (high 16 bits used to ask for read-ahead and
 * help with write clustering)
 * NB: IO_NDELAY and IO_DIRECT are linked to fcntl.h
 */
#define	IO_UNIT		0x0001		/* do I/O as atomic unit */
#define	IO_APPEND	0x0002		/* append write to end */
#define	IO_NDELAY	0x0004		/* FNDELAY flag set in file table */
#define	IO_NODELOCKED	0x0008		/* underlying node already locked */
#define	IO_ASYNC	0x0010		/* bawrite rather then bdwrite */
#define	IO_VMIO		0x0020		/* data already in VMIO space */
#define	IO_INVAL	0x0040		/* invalidate after I/O */
#define	IO_SYNC		0x0080		/* do I/O synchronously */
#define	IO_DIRECT	0x0100		/* attempt to bypass buffer cache */
#define	IO_EXT		0x0400		/* operate on external attributes */
#define	IO_NORMAL	0x0800		/* operate on regular data */
#define	IO_NOMACCHECK	0x1000		/* MAC checks unnecessary */
#define	IO_BUFLOCKED	0x2000		/* ffs flag; indir buf is locked */
#define	IO_RANGELOCKED	0x4000		/* range locked */



#define VNOVAL    (-1)

/*
 * Convert between vnode types and inode formats (since POSIX.1
 * defines mode word of stat structure in terms of inode formats).
 */
extern enum vtype iftovt_tab[];
extern int vttoif_tab[];
#define IFTOVT(mode)    (iftovt_tab[((mode) & S_IFMT) >> 12])
#define VTTOIF(indx)    (vttoif_tab[(int)(indx)])
#define MAKEIMODE(indx, mode)    (int)(VTTOIF(indx) | (mode))

#define    VV_PROCDEP    0x0100    /* vnode is process dependent */
#define	NULLVP	((struct vnode *)NULL)
#define	VATTR_NULL(vap)	(*(vap) = va_null)	/* initialize a vattr */



static __inline int
VOP_PATHCONF(struct vnode *vp, int name, register_t *retval)
{
    return (0);
}

static __inline int
VOP_GETATTR(struct vnode *vp, struct vattr *vap, struct ucred *cred)
{
    bzero(vap, sizeof(struct vattr));
    return (0);
}

int vn_open(struct nameidata *ndp, int *flagp, int cmode, struct file *fp);
int vn_close(struct vnode *vp, int flags, struct ucred *file_cred,
    struct thread *td);

int vn_rdwr(enum uio_rw rw, struct vnode *vp, void *base,
    int len, off_t offset, enum uio_seg segflg, int ioflg,
    struct ucred *active_cred, struct ucred *file_cred, ssize_t *aresid,
    struct thread *td);

/* vfs_hash.c */
typedef int vfs_hash_cmp_t(struct vnode *vp, void *arg);

void vfs_hash_changesize(int newhashsize);
int vfs_hash_get(const struct mount *mp, u_int hash, int flags,
    struct thread *td, struct vnode **vpp, vfs_hash_cmp_t *fn, void *arg);
u_int vfs_hash_index(struct vnode *vp);
int vfs_hash_insert(struct vnode *vp, u_int hash, int flags, struct thread *td,
    struct vnode **vpp, vfs_hash_cmp_t *fn, void *arg);
void vfs_hash_ref(const struct mount *mp, u_int hash, struct thread *td,
    struct vnode **vpp, vfs_hash_cmp_t *fn, void *arg);
void vfs_hash_rehash(struct vnode *vp, u_int hash);
void vfs_hash_remove(struct vnode *vp);

//int vfs_kqfilter(struct vop_kqfilter_args *);
void vfs_mark_atime(struct vnode *vp, struct ucred *cred);
struct dirent;
//int vfs_read_dirent(struct vop_readdir_args *ap, struct dirent *dp, off_t off);

int vfs_unixify_accmode(accmode_t *accmode);

void vfs_unp_reclaim(struct vnode *vp);

int setfmode(struct thread *td, struct ucred *cred, struct vnode *vp, int mode);
int setfown(struct thread *td, struct ucred *cred, struct vnode *vp, uid_t uid,
    gid_t gid);
int vn_chmod(struct file *fp, mode_t mode, struct ucred *active_cred,
    struct thread *td);
int vn_chown(struct file *fp, uid_t uid, gid_t gid, struct ucred *active_cred,
    struct thread *td);


#endif    /* _FSTACK_SYS_VNODE_H_ */

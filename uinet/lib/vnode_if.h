/*
 * This file is produced automatically.
 * Do not modify anything in here by hand.
 *
 * Created from $FreeBSD$
 */

extern struct vnodeop_desc vop_default_desc;
#include "vnode_if_typedef.h"
#include "vnode_if_newproto.h"
struct vop_islocked_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_islocked_desc;

int VOP_ISLOCKED_AP(struct vop_islocked_args *);
int VOP_ISLOCKED_APV(struct vop_vector *vop, struct vop_islocked_args *);

static __inline int VOP_ISLOCKED(
		IN struct vnode *vp)
{
	struct vop_islocked_args a;

	a.a_gen.a_desc = &vop_islocked_desc;
	a.a_vp = vp;
	return (VOP_ISLOCKED_APV(vp->v_op, &a));
}

struct vop_lookup_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_dvp;
		INOUT struct vnode **a_vpp;
		IN struct componentname *a_cnp;
};

extern struct vnodeop_desc vop_lookup_desc;

int VOP_LOOKUP_AP(struct vop_lookup_args *);
int VOP_LOOKUP_APV(struct vop_vector *vop, struct vop_lookup_args *);

static __inline int VOP_LOOKUP(
		IN struct vnode *dvp,
		INOUT struct vnode **vpp,
		IN struct componentname *cnp)
{
	struct vop_lookup_args a;

	a.a_gen.a_desc = &vop_lookup_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	return (VOP_LOOKUP_APV(dvp->v_op, &a));
}

struct vop_cachedlookup_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_dvp;
		INOUT struct vnode **a_vpp;
		IN struct componentname *a_cnp;
};

extern struct vnodeop_desc vop_cachedlookup_desc;

int VOP_CACHEDLOOKUP_AP(struct vop_cachedlookup_args *);
int VOP_CACHEDLOOKUP_APV(struct vop_vector *vop, struct vop_cachedlookup_args *);

static __inline int VOP_CACHEDLOOKUP(
		IN struct vnode *dvp,
		INOUT struct vnode **vpp,
		IN struct componentname *cnp)
{
	struct vop_cachedlookup_args a;

	a.a_gen.a_desc = &vop_cachedlookup_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	return (VOP_CACHEDLOOKUP_APV(dvp->v_op, &a));
}

struct vop_create_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_dvp;
		OUT struct vnode **a_vpp;
		IN struct componentname *a_cnp;
		IN struct vattr *a_vap;
};

extern struct vnodeop_desc vop_create_desc;

int VOP_CREATE_AP(struct vop_create_args *);
int VOP_CREATE_APV(struct vop_vector *vop, struct vop_create_args *);

static __inline int VOP_CREATE(
		IN struct vnode *dvp,
		OUT struct vnode **vpp,
		IN struct componentname *cnp,
		IN struct vattr *vap)
{
	struct vop_create_args a;

	a.a_gen.a_desc = &vop_create_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	return (VOP_CREATE_APV(dvp->v_op, &a));
}

struct vop_whiteout_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_dvp;
		IN struct componentname *a_cnp;
		IN int a_flags;
};

extern struct vnodeop_desc vop_whiteout_desc;

int VOP_WHITEOUT_AP(struct vop_whiteout_args *);
int VOP_WHITEOUT_APV(struct vop_vector *vop, struct vop_whiteout_args *);

static __inline int VOP_WHITEOUT(
		IN struct vnode *dvp,
		IN struct componentname *cnp,
		IN int flags)
{
	struct vop_whiteout_args a;

	a.a_gen.a_desc = &vop_whiteout_desc;
	a.a_dvp = dvp;
	a.a_cnp = cnp;
	a.a_flags = flags;
	return (VOP_WHITEOUT_APV(dvp->v_op, &a));
}

struct vop_mknod_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_dvp;
		OUT struct vnode **a_vpp;
		IN struct componentname *a_cnp;
		IN struct vattr *a_vap;
};

extern struct vnodeop_desc vop_mknod_desc;

int VOP_MKNOD_AP(struct vop_mknod_args *);
int VOP_MKNOD_APV(struct vop_vector *vop, struct vop_mknod_args *);

static __inline int VOP_MKNOD(
		IN struct vnode *dvp,
		OUT struct vnode **vpp,
		IN struct componentname *cnp,
		IN struct vattr *vap)
{
	struct vop_mknod_args a;

	a.a_gen.a_desc = &vop_mknod_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	return (VOP_MKNOD_APV(dvp->v_op, &a));
}

struct vop_open_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_mode;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
		IN struct file *a_fp;
};

extern struct vnodeop_desc vop_open_desc;

int VOP_OPEN_AP(struct vop_open_args *);
int VOP_OPEN_APV(struct vop_vector *vop, struct vop_open_args *);

static __inline int VOP_OPEN(
		IN struct vnode *vp,
		IN int mode,
		IN struct ucred *cred,
		IN struct thread *td,
		IN struct file *fp)
{
	struct vop_open_args a;

	a.a_gen.a_desc = &vop_open_desc;
	a.a_vp = vp;
	a.a_mode = mode;
	a.a_cred = cred;
	a.a_td = td;
	a.a_fp = fp;
	return (VOP_OPEN_APV(vp->v_op, &a));
}

struct vop_close_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_fflag;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_close_desc;

int VOP_CLOSE_AP(struct vop_close_args *);
int VOP_CLOSE_APV(struct vop_vector *vop, struct vop_close_args *);

static __inline int VOP_CLOSE(
		IN struct vnode *vp,
		IN int fflag,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_close_args a;

	a.a_gen.a_desc = &vop_close_desc;
	a.a_vp = vp;
	a.a_fflag = fflag;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_CLOSE_APV(vp->v_op, &a));
}

struct vop_access_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN accmode_t a_accmode;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_access_desc;

int VOP_ACCESS_AP(struct vop_access_args *);
int VOP_ACCESS_APV(struct vop_vector *vop, struct vop_access_args *);

static __inline int VOP_ACCESS(
		IN struct vnode *vp,
		IN accmode_t accmode,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_access_args a;

	a.a_gen.a_desc = &vop_access_desc;
	a.a_vp = vp;
	a.a_accmode = accmode;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_ACCESS_APV(vp->v_op, &a));
}

struct vop_accessx_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN accmode_t a_accmode;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_accessx_desc;

int VOP_ACCESSX_AP(struct vop_accessx_args *);
int VOP_ACCESSX_APV(struct vop_vector *vop, struct vop_accessx_args *);

static __inline int VOP_ACCESSX(
		IN struct vnode *vp,
		IN accmode_t accmode,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_accessx_args a;

	a.a_gen.a_desc = &vop_accessx_desc;
	a.a_vp = vp;
	a.a_accmode = accmode;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_ACCESSX_APV(vp->v_op, &a));
}

struct vop_getattr_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		OUT struct vattr *a_vap;
		IN struct ucred *a_cred;
};

extern struct vnodeop_desc vop_getattr_desc;

int VOP_GETATTR_AP(struct vop_getattr_args *);
int VOP_GETATTR_APV(struct vop_vector *vop, struct vop_getattr_args *);

static __inline int VOP_GETATTR(
		IN struct vnode *vp,
		OUT struct vattr *vap,
		IN struct ucred *cred)
{
	struct vop_getattr_args a;

	a.a_gen.a_desc = &vop_getattr_desc;
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_cred = cred;
	return (VOP_GETATTR_APV(vp->v_op, &a));
}

struct vop_setattr_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct vattr *a_vap;
		IN struct ucred *a_cred;
};

extern struct vnodeop_desc vop_setattr_desc;

int VOP_SETATTR_AP(struct vop_setattr_args *);
int VOP_SETATTR_APV(struct vop_vector *vop, struct vop_setattr_args *);

static __inline int VOP_SETATTR(
		IN struct vnode *vp,
		IN struct vattr *vap,
		IN struct ucred *cred)
{
	struct vop_setattr_args a;

	a.a_gen.a_desc = &vop_setattr_desc;
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_cred = cred;
	return (VOP_SETATTR_APV(vp->v_op, &a));
}

struct vop_markatime_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_markatime_desc;

int VOP_MARKATIME_AP(struct vop_markatime_args *);
int VOP_MARKATIME_APV(struct vop_vector *vop, struct vop_markatime_args *);

static __inline int VOP_MARKATIME(
		IN struct vnode *vp)
{
	struct vop_markatime_args a;

	a.a_gen.a_desc = &vop_markatime_desc;
	a.a_vp = vp;
	return (VOP_MARKATIME_APV(vp->v_op, &a));
}

struct vop_read_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		INOUT struct uio *a_uio;
		IN int a_ioflag;
		IN struct ucred *a_cred;
};

extern struct vnodeop_desc vop_read_desc;

int VOP_READ_AP(struct vop_read_args *);
int VOP_READ_APV(struct vop_vector *vop, struct vop_read_args *);

static __inline int VOP_READ(
		IN struct vnode *vp,
		INOUT struct uio *uio,
		IN int ioflag,
		IN struct ucred *cred)
{
	struct vop_read_args a;

	a.a_gen.a_desc = &vop_read_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_cred = cred;
	return (VOP_READ_APV(vp->v_op, &a));
}

struct vop_write_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		INOUT struct uio *a_uio;
		IN int a_ioflag;
		IN struct ucred *a_cred;
};

extern struct vnodeop_desc vop_write_desc;

int VOP_WRITE_AP(struct vop_write_args *);
int VOP_WRITE_APV(struct vop_vector *vop, struct vop_write_args *);

static __inline int VOP_WRITE(
		IN struct vnode *vp,
		INOUT struct uio *uio,
		IN int ioflag,
		IN struct ucred *cred)
{
	struct vop_write_args a;

	a.a_gen.a_desc = &vop_write_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_cred = cred;
	return (VOP_WRITE_APV(vp->v_op, &a));
}

struct vop_ioctl_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN u_long a_command;
		IN void *a_data;
		IN int a_fflag;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_ioctl_desc;

int VOP_IOCTL_AP(struct vop_ioctl_args *);
int VOP_IOCTL_APV(struct vop_vector *vop, struct vop_ioctl_args *);

static __inline int VOP_IOCTL(
		IN struct vnode *vp,
		IN u_long command,
		IN void *data,
		IN int fflag,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_ioctl_args a;

	a.a_gen.a_desc = &vop_ioctl_desc;
	a.a_vp = vp;
	a.a_command = command;
	a.a_data = data;
	a.a_fflag = fflag;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_IOCTL_APV(vp->v_op, &a));
}

struct vop_poll_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_events;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_poll_desc;

int VOP_POLL_AP(struct vop_poll_args *);
int VOP_POLL_APV(struct vop_vector *vop, struct vop_poll_args *);

static __inline int VOP_POLL(
		IN struct vnode *vp,
		IN int events,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_poll_args a;

	a.a_gen.a_desc = &vop_poll_desc;
	a.a_vp = vp;
	a.a_events = events;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_POLL_APV(vp->v_op, &a));
}

struct vop_kqfilter_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct knote *a_kn;
};

extern struct vnodeop_desc vop_kqfilter_desc;

int VOP_KQFILTER_AP(struct vop_kqfilter_args *);
int VOP_KQFILTER_APV(struct vop_vector *vop, struct vop_kqfilter_args *);

static __inline int VOP_KQFILTER(
		IN struct vnode *vp,
		IN struct knote *kn)
{
	struct vop_kqfilter_args a;

	a.a_gen.a_desc = &vop_kqfilter_desc;
	a.a_vp = vp;
	a.a_kn = kn;
	return (VOP_KQFILTER_APV(vp->v_op, &a));
}

struct vop_revoke_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_flags;
};

extern struct vnodeop_desc vop_revoke_desc;

int VOP_REVOKE_AP(struct vop_revoke_args *);
int VOP_REVOKE_APV(struct vop_vector *vop, struct vop_revoke_args *);

static __inline int VOP_REVOKE(
		IN struct vnode *vp,
		IN int flags)
{
	struct vop_revoke_args a;

	a.a_gen.a_desc = &vop_revoke_desc;
	a.a_vp = vp;
	a.a_flags = flags;
	return (VOP_REVOKE_APV(vp->v_op, &a));
}

struct vop_fsync_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_waitfor;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_fsync_desc;

int VOP_FSYNC_AP(struct vop_fsync_args *);
int VOP_FSYNC_APV(struct vop_vector *vop, struct vop_fsync_args *);

static __inline int VOP_FSYNC(
		IN struct vnode *vp,
		IN int waitfor,
		IN struct thread *td)
{
	struct vop_fsync_args a;

	a.a_gen.a_desc = &vop_fsync_desc;
	a.a_vp = vp;
	a.a_waitfor = waitfor;
	a.a_td = td;
	return (VOP_FSYNC_APV(vp->v_op, &a));
}

struct vop_remove_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_dvp;
		IN struct vnode *a_vp;
		IN struct componentname *a_cnp;
};

extern struct vnodeop_desc vop_remove_desc;

int VOP_REMOVE_AP(struct vop_remove_args *);
int VOP_REMOVE_APV(struct vop_vector *vop, struct vop_remove_args *);

static __inline int VOP_REMOVE(
		IN struct vnode *dvp,
		IN struct vnode *vp,
		IN struct componentname *cnp)
{
	struct vop_remove_args a;

	a.a_gen.a_desc = &vop_remove_desc;
	a.a_dvp = dvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	return (VOP_REMOVE_APV(dvp->v_op, &a));
}

struct vop_link_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_tdvp;
		IN struct vnode *a_vp;
		IN struct componentname *a_cnp;
};

extern struct vnodeop_desc vop_link_desc;

int VOP_LINK_AP(struct vop_link_args *);
int VOP_LINK_APV(struct vop_vector *vop, struct vop_link_args *);

static __inline int VOP_LINK(
		IN struct vnode *tdvp,
		IN struct vnode *vp,
		IN struct componentname *cnp)
{
	struct vop_link_args a;

	a.a_gen.a_desc = &vop_link_desc;
	a.a_tdvp = tdvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	return (VOP_LINK_APV(tdvp->v_op, &a));
}

struct vop_rename_args {
	struct vop_generic_args a_gen;
		IN WILLRELE struct vnode *a_fdvp;
		IN WILLRELE struct vnode *a_fvp;
		IN struct componentname *a_fcnp;
		IN WILLRELE struct vnode *a_tdvp;
		IN WILLRELE struct vnode *a_tvp;
		IN struct componentname *a_tcnp;
};

extern struct vnodeop_desc vop_rename_desc;

int VOP_RENAME_AP(struct vop_rename_args *);
int VOP_RENAME_APV(struct vop_vector *vop, struct vop_rename_args *);

static __inline int VOP_RENAME(
		IN WILLRELE struct vnode *fdvp,
		IN WILLRELE struct vnode *fvp,
		IN struct componentname *fcnp,
		IN WILLRELE struct vnode *tdvp,
		IN WILLRELE struct vnode *tvp,
		IN struct componentname *tcnp)
{
	struct vop_rename_args a;

	a.a_gen.a_desc = &vop_rename_desc;
	a.a_fdvp = fdvp;
	a.a_fvp = fvp;
	a.a_fcnp = fcnp;
	a.a_tdvp = tdvp;
	a.a_tvp = tvp;
	a.a_tcnp = tcnp;
	return (VOP_RENAME_APV(fdvp->v_op, &a));
}

struct vop_mkdir_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_dvp;
		OUT struct vnode **a_vpp;
		IN struct componentname *a_cnp;
		IN struct vattr *a_vap;
};

extern struct vnodeop_desc vop_mkdir_desc;

int VOP_MKDIR_AP(struct vop_mkdir_args *);
int VOP_MKDIR_APV(struct vop_vector *vop, struct vop_mkdir_args *);

static __inline int VOP_MKDIR(
		IN struct vnode *dvp,
		OUT struct vnode **vpp,
		IN struct componentname *cnp,
		IN struct vattr *vap)
{
	struct vop_mkdir_args a;

	a.a_gen.a_desc = &vop_mkdir_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	return (VOP_MKDIR_APV(dvp->v_op, &a));
}

struct vop_rmdir_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_dvp;
		IN struct vnode *a_vp;
		IN struct componentname *a_cnp;
};

extern struct vnodeop_desc vop_rmdir_desc;

int VOP_RMDIR_AP(struct vop_rmdir_args *);
int VOP_RMDIR_APV(struct vop_vector *vop, struct vop_rmdir_args *);

static __inline int VOP_RMDIR(
		IN struct vnode *dvp,
		IN struct vnode *vp,
		IN struct componentname *cnp)
{
	struct vop_rmdir_args a;

	a.a_gen.a_desc = &vop_rmdir_desc;
	a.a_dvp = dvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	return (VOP_RMDIR_APV(dvp->v_op, &a));
}

struct vop_symlink_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_dvp;
		OUT struct vnode **a_vpp;
		IN struct componentname *a_cnp;
		IN struct vattr *a_vap;
		IN char *a_target;
};

extern struct vnodeop_desc vop_symlink_desc;

int VOP_SYMLINK_AP(struct vop_symlink_args *);
int VOP_SYMLINK_APV(struct vop_vector *vop, struct vop_symlink_args *);

static __inline int VOP_SYMLINK(
		IN struct vnode *dvp,
		OUT struct vnode **vpp,
		IN struct componentname *cnp,
		IN struct vattr *vap,
		IN char *target)
{
	struct vop_symlink_args a;

	a.a_gen.a_desc = &vop_symlink_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	a.a_target = target;
	return (VOP_SYMLINK_APV(dvp->v_op, &a));
}

struct vop_readdir_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		INOUT struct uio *a_uio;
		IN struct ucred *a_cred;
		INOUT int *a_eofflag;
		OUT int *a_ncookies;
		INOUT u_long **a_cookies;
};

extern struct vnodeop_desc vop_readdir_desc;

int VOP_READDIR_AP(struct vop_readdir_args *);
int VOP_READDIR_APV(struct vop_vector *vop, struct vop_readdir_args *);

static __inline int VOP_READDIR(
		IN struct vnode *vp,
		INOUT struct uio *uio,
		IN struct ucred *cred,
		INOUT int *eofflag,
		OUT int *ncookies,
		INOUT u_long **cookies)
{
	struct vop_readdir_args a;

	a.a_gen.a_desc = &vop_readdir_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_cred = cred;
	a.a_eofflag = eofflag;
	a.a_ncookies = ncookies;
	a.a_cookies = cookies;
	return (VOP_READDIR_APV(vp->v_op, &a));
}

struct vop_readlink_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		INOUT struct uio *a_uio;
		IN struct ucred *a_cred;
};

extern struct vnodeop_desc vop_readlink_desc;

int VOP_READLINK_AP(struct vop_readlink_args *);
int VOP_READLINK_APV(struct vop_vector *vop, struct vop_readlink_args *);

static __inline int VOP_READLINK(
		IN struct vnode *vp,
		INOUT struct uio *uio,
		IN struct ucred *cred)
{
	struct vop_readlink_args a;

	a.a_gen.a_desc = &vop_readlink_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_cred = cred;
	return (VOP_READLINK_APV(vp->v_op, &a));
}

struct vop_inactive_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_inactive_desc;

int VOP_INACTIVE_AP(struct vop_inactive_args *);
int VOP_INACTIVE_APV(struct vop_vector *vop, struct vop_inactive_args *);

static __inline int VOP_INACTIVE(
		IN struct vnode *vp,
		IN struct thread *td)
{
	struct vop_inactive_args a;

	a.a_gen.a_desc = &vop_inactive_desc;
	a.a_vp = vp;
	a.a_td = td;
	return (VOP_INACTIVE_APV(vp->v_op, &a));
}

struct vop_reclaim_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_reclaim_desc;

int VOP_RECLAIM_AP(struct vop_reclaim_args *);
int VOP_RECLAIM_APV(struct vop_vector *vop, struct vop_reclaim_args *);

static __inline int VOP_RECLAIM(
		IN struct vnode *vp,
		IN struct thread *td)
{
	struct vop_reclaim_args a;

	a.a_gen.a_desc = &vop_reclaim_desc;
	a.a_vp = vp;
	a.a_td = td;
	return (VOP_RECLAIM_APV(vp->v_op, &a));
}

struct vop_lock1_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_flags;
		IN char *a_file;
		IN int a_line;
};

extern struct vnodeop_desc vop_lock1_desc;

int VOP_LOCK1_AP(struct vop_lock1_args *);
int VOP_LOCK1_APV(struct vop_vector *vop, struct vop_lock1_args *);

static __inline int VOP_LOCK1(
		IN struct vnode *vp,
		IN int flags,
		IN char *file,
		IN int line)
{
	struct vop_lock1_args a;

	a.a_gen.a_desc = &vop_lock1_desc;
	a.a_vp = vp;
	a.a_flags = flags;
	a.a_file = file;
	a.a_line = line;
	return (VOP_LOCK1_APV(vp->v_op, &a));
}

struct vop_unlock_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_flags;
};

extern struct vnodeop_desc vop_unlock_desc;

int VOP_UNLOCK_AP(struct vop_unlock_args *);
int VOP_UNLOCK_APV(struct vop_vector *vop, struct vop_unlock_args *);

static __inline int VOP_UNLOCK(
		IN struct vnode *vp,
		IN int flags)
{
	struct vop_unlock_args a;

	a.a_gen.a_desc = &vop_unlock_desc;
	a.a_vp = vp;
	a.a_flags = flags;
	return (VOP_UNLOCK_APV(vp->v_op, &a));
}

struct vop_bmap_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN daddr_t a_bn;
		OUT struct bufobj **a_bop;
		IN daddr_t *a_bnp;
		OUT int *a_runp;
		OUT int *a_runb;
};

extern struct vnodeop_desc vop_bmap_desc;

int VOP_BMAP_AP(struct vop_bmap_args *);
int VOP_BMAP_APV(struct vop_vector *vop, struct vop_bmap_args *);

static __inline int VOP_BMAP(
		IN struct vnode *vp,
		IN daddr_t bn,
		OUT struct bufobj **bop,
		IN daddr_t *bnp,
		OUT int *runp,
		OUT int *runb)
{
	struct vop_bmap_args a;

	a.a_gen.a_desc = &vop_bmap_desc;
	a.a_vp = vp;
	a.a_bn = bn;
	a.a_bop = bop;
	a.a_bnp = bnp;
	a.a_runp = runp;
	a.a_runb = runb;
	return (VOP_BMAP_APV(vp->v_op, &a));
}

struct vop_strategy_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct buf *a_bp;
};

extern struct vnodeop_desc vop_strategy_desc;

int VOP_STRATEGY_AP(struct vop_strategy_args *);
int VOP_STRATEGY_APV(struct vop_vector *vop, struct vop_strategy_args *);

static __inline int VOP_STRATEGY(
		IN struct vnode *vp,
		IN struct buf *bp)
{
	struct vop_strategy_args a;

	a.a_gen.a_desc = &vop_strategy_desc;
	a.a_vp = vp;
	a.a_bp = bp;
	return (VOP_STRATEGY_APV(vp->v_op, &a));
}

struct vop_getwritemount_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		OUT struct mount **a_mpp;
};

extern struct vnodeop_desc vop_getwritemount_desc;

int VOP_GETWRITEMOUNT_AP(struct vop_getwritemount_args *);
int VOP_GETWRITEMOUNT_APV(struct vop_vector *vop, struct vop_getwritemount_args *);

static __inline int VOP_GETWRITEMOUNT(
		IN struct vnode *vp,
		OUT struct mount **mpp)
{
	struct vop_getwritemount_args a;

	a.a_gen.a_desc = &vop_getwritemount_desc;
	a.a_vp = vp;
	a.a_mpp = mpp;
	return (VOP_GETWRITEMOUNT_APV(vp->v_op, &a));
}

struct vop_print_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_print_desc;

int VOP_PRINT_AP(struct vop_print_args *);
int VOP_PRINT_APV(struct vop_vector *vop, struct vop_print_args *);

static __inline int VOP_PRINT(
		IN struct vnode *vp)
{
	struct vop_print_args a;

	a.a_gen.a_desc = &vop_print_desc;
	a.a_vp = vp;
	return (VOP_PRINT_APV(vp->v_op, &a));
}

struct vop_pathconf_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_name;
		OUT register_t *a_retval;
};

extern struct vnodeop_desc vop_pathconf_desc;

int VOP_PATHCONF_AP(struct vop_pathconf_args *);
int VOP_PATHCONF_APV(struct vop_vector *vop, struct vop_pathconf_args *);

static __inline int VOP_PATHCONF(
		IN struct vnode *vp,
		IN int name,
		OUT register_t *retval)
{
	struct vop_pathconf_args a;

	a.a_gen.a_desc = &vop_pathconf_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_retval = retval;
	return (VOP_PATHCONF_APV(vp->v_op, &a));
}

struct vop_advlock_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN void *a_id;
		IN int a_op;
		IN struct flock *a_fl;
		IN int a_flags;
};

extern struct vnodeop_desc vop_advlock_desc;

int VOP_ADVLOCK_AP(struct vop_advlock_args *);
int VOP_ADVLOCK_APV(struct vop_vector *vop, struct vop_advlock_args *);

static __inline int VOP_ADVLOCK(
		IN struct vnode *vp,
		IN void *id,
		IN int op,
		IN struct flock *fl,
		IN int flags)
{
	struct vop_advlock_args a;

	a.a_gen.a_desc = &vop_advlock_desc;
	a.a_vp = vp;
	a.a_id = id;
	a.a_op = op;
	a.a_fl = fl;
	a.a_flags = flags;
	return (VOP_ADVLOCK_APV(vp->v_op, &a));
}

struct vop_advlockasync_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN void *a_id;
		IN int a_op;
		IN struct flock *a_fl;
		IN int a_flags;
		IN struct task *a_task;
		INOUT void **a_cookiep;
};

extern struct vnodeop_desc vop_advlockasync_desc;

int VOP_ADVLOCKASYNC_AP(struct vop_advlockasync_args *);
int VOP_ADVLOCKASYNC_APV(struct vop_vector *vop, struct vop_advlockasync_args *);

static __inline int VOP_ADVLOCKASYNC(
		IN struct vnode *vp,
		IN void *id,
		IN int op,
		IN struct flock *fl,
		IN int flags,
		IN struct task *task,
		INOUT void **cookiep)
{
	struct vop_advlockasync_args a;

	a.a_gen.a_desc = &vop_advlockasync_desc;
	a.a_vp = vp;
	a.a_id = id;
	a.a_op = op;
	a.a_fl = fl;
	a.a_flags = flags;
	a.a_task = task;
	a.a_cookiep = cookiep;
	return (VOP_ADVLOCKASYNC_APV(vp->v_op, &a));
}

struct vop_advlockpurge_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_advlockpurge_desc;

int VOP_ADVLOCKPURGE_AP(struct vop_advlockpurge_args *);
int VOP_ADVLOCKPURGE_APV(struct vop_vector *vop, struct vop_advlockpurge_args *);

static __inline int VOP_ADVLOCKPURGE(
		IN struct vnode *vp)
{
	struct vop_advlockpurge_args a;

	a.a_gen.a_desc = &vop_advlockpurge_desc;
	a.a_vp = vp;
	return (VOP_ADVLOCKPURGE_APV(vp->v_op, &a));
}

struct vop_reallocblks_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct cluster_save *a_buflist;
};

extern struct vnodeop_desc vop_reallocblks_desc;

int VOP_REALLOCBLKS_AP(struct vop_reallocblks_args *);
int VOP_REALLOCBLKS_APV(struct vop_vector *vop, struct vop_reallocblks_args *);

static __inline int VOP_REALLOCBLKS(
		IN struct vnode *vp,
		IN struct cluster_save *buflist)
{
	struct vop_reallocblks_args a;

	a.a_gen.a_desc = &vop_reallocblks_desc;
	a.a_vp = vp;
	a.a_buflist = buflist;
	return (VOP_REALLOCBLKS_APV(vp->v_op, &a));
}

struct vop_getpages_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN vm_page_t *a_m;
		IN int a_count;
		IN int *a_rbehind;
		IN int *a_rahead;
};

extern struct vnodeop_desc vop_getpages_desc;

int VOP_GETPAGES_AP(struct vop_getpages_args *);
int VOP_GETPAGES_APV(struct vop_vector *vop, struct vop_getpages_args *);

static __inline int VOP_GETPAGES(
		IN struct vnode *vp,
		IN vm_page_t *m,
		IN int count,
		IN int *rbehind,
		IN int *rahead)
{
	struct vop_getpages_args a;

	a.a_gen.a_desc = &vop_getpages_desc;
	a.a_vp = vp;
	a.a_m = m;
	a.a_count = count;
	a.a_rbehind = rbehind;
	a.a_rahead = rahead;
	return (VOP_GETPAGES_APV(vp->v_op, &a));
}

struct vop_getpages_async_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN vm_page_t *a_m;
		IN int a_count;
		IN int *a_rbehind;
		IN int *a_rahead;
		IN vop_getpages_iodone_t *a_iodone;
		IN void *a_arg;
};

extern struct vnodeop_desc vop_getpages_async_desc;

int VOP_GETPAGES_ASYNC_AP(struct vop_getpages_async_args *);
int VOP_GETPAGES_ASYNC_APV(struct vop_vector *vop, struct vop_getpages_async_args *);

static __inline int VOP_GETPAGES_ASYNC(
		IN struct vnode *vp,
		IN vm_page_t *m,
		IN int count,
		IN int *rbehind,
		IN int *rahead,
		IN vop_getpages_iodone_t *iodone,
		IN void *arg)
{
	struct vop_getpages_async_args a;

	a.a_gen.a_desc = &vop_getpages_async_desc;
	a.a_vp = vp;
	a.a_m = m;
	a.a_count = count;
	a.a_rbehind = rbehind;
	a.a_rahead = rahead;
	a.a_iodone = iodone;
	a.a_arg = arg;
	return (VOP_GETPAGES_ASYNC_APV(vp->v_op, &a));
}

struct vop_putpages_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN vm_page_t *a_m;
		IN int a_count;
		IN int a_sync;
		IN int *a_rtvals;
};

extern struct vnodeop_desc vop_putpages_desc;

int VOP_PUTPAGES_AP(struct vop_putpages_args *);
int VOP_PUTPAGES_APV(struct vop_vector *vop, struct vop_putpages_args *);

static __inline int VOP_PUTPAGES(
		IN struct vnode *vp,
		IN vm_page_t *m,
		IN int count,
		IN int sync,
		IN int *rtvals)
{
	struct vop_putpages_args a;

	a.a_gen.a_desc = &vop_putpages_desc;
	a.a_vp = vp;
	a.a_m = m;
	a.a_count = count;
	a.a_sync = sync;
	a.a_rtvals = rtvals;
	return (VOP_PUTPAGES_APV(vp->v_op, &a));
}

struct vop_getacl_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN acl_type_t a_type;
		OUT struct acl *a_aclp;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_getacl_desc;

int VOP_GETACL_AP(struct vop_getacl_args *);
int VOP_GETACL_APV(struct vop_vector *vop, struct vop_getacl_args *);

static __inline int VOP_GETACL(
		IN struct vnode *vp,
		IN acl_type_t type,
		OUT struct acl *aclp,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_getacl_args a;

	a.a_gen.a_desc = &vop_getacl_desc;
	a.a_vp = vp;
	a.a_type = type;
	a.a_aclp = aclp;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_GETACL_APV(vp->v_op, &a));
}

struct vop_setacl_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN acl_type_t a_type;
		IN struct acl *a_aclp;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_setacl_desc;

int VOP_SETACL_AP(struct vop_setacl_args *);
int VOP_SETACL_APV(struct vop_vector *vop, struct vop_setacl_args *);

static __inline int VOP_SETACL(
		IN struct vnode *vp,
		IN acl_type_t type,
		IN struct acl *aclp,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_setacl_args a;

	a.a_gen.a_desc = &vop_setacl_desc;
	a.a_vp = vp;
	a.a_type = type;
	a.a_aclp = aclp;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_SETACL_APV(vp->v_op, &a));
}

struct vop_aclcheck_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN acl_type_t a_type;
		IN struct acl *a_aclp;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_aclcheck_desc;

int VOP_ACLCHECK_AP(struct vop_aclcheck_args *);
int VOP_ACLCHECK_APV(struct vop_vector *vop, struct vop_aclcheck_args *);

static __inline int VOP_ACLCHECK(
		IN struct vnode *vp,
		IN acl_type_t type,
		IN struct acl *aclp,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_aclcheck_args a;

	a.a_gen.a_desc = &vop_aclcheck_desc;
	a.a_vp = vp;
	a.a_type = type;
	a.a_aclp = aclp;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_ACLCHECK_APV(vp->v_op, &a));
}

struct vop_closeextattr_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_commit;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_closeextattr_desc;

int VOP_CLOSEEXTATTR_AP(struct vop_closeextattr_args *);
int VOP_CLOSEEXTATTR_APV(struct vop_vector *vop, struct vop_closeextattr_args *);

static __inline int VOP_CLOSEEXTATTR(
		IN struct vnode *vp,
		IN int commit,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_closeextattr_args a;

	a.a_gen.a_desc = &vop_closeextattr_desc;
	a.a_vp = vp;
	a.a_commit = commit;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_CLOSEEXTATTR_APV(vp->v_op, &a));
}

struct vop_getextattr_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_attrnamespace;
		IN const char *a_name;
		INOUT struct uio *a_uio;
		OUT size_t *a_size;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_getextattr_desc;

int VOP_GETEXTATTR_AP(struct vop_getextattr_args *);
int VOP_GETEXTATTR_APV(struct vop_vector *vop, struct vop_getextattr_args *);

static __inline int VOP_GETEXTATTR(
		IN struct vnode *vp,
		IN int attrnamespace,
		IN const char *name,
		INOUT struct uio *uio,
		OUT size_t *size,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_getextattr_args a;

	a.a_gen.a_desc = &vop_getextattr_desc;
	a.a_vp = vp;
	a.a_attrnamespace = attrnamespace;
	a.a_name = name;
	a.a_uio = uio;
	a.a_size = size;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_GETEXTATTR_APV(vp->v_op, &a));
}

struct vop_listextattr_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_attrnamespace;
		INOUT struct uio *a_uio;
		OUT size_t *a_size;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_listextattr_desc;

int VOP_LISTEXTATTR_AP(struct vop_listextattr_args *);
int VOP_LISTEXTATTR_APV(struct vop_vector *vop, struct vop_listextattr_args *);

static __inline int VOP_LISTEXTATTR(
		IN struct vnode *vp,
		IN int attrnamespace,
		INOUT struct uio *uio,
		OUT size_t *size,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_listextattr_args a;

	a.a_gen.a_desc = &vop_listextattr_desc;
	a.a_vp = vp;
	a.a_attrnamespace = attrnamespace;
	a.a_uio = uio;
	a.a_size = size;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_LISTEXTATTR_APV(vp->v_op, &a));
}

struct vop_openextattr_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_openextattr_desc;

int VOP_OPENEXTATTR_AP(struct vop_openextattr_args *);
int VOP_OPENEXTATTR_APV(struct vop_vector *vop, struct vop_openextattr_args *);

static __inline int VOP_OPENEXTATTR(
		IN struct vnode *vp,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_openextattr_args a;

	a.a_gen.a_desc = &vop_openextattr_desc;
	a.a_vp = vp;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_OPENEXTATTR_APV(vp->v_op, &a));
}

struct vop_deleteextattr_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_attrnamespace;
		IN const char *a_name;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_deleteextattr_desc;

int VOP_DELETEEXTATTR_AP(struct vop_deleteextattr_args *);
int VOP_DELETEEXTATTR_APV(struct vop_vector *vop, struct vop_deleteextattr_args *);

static __inline int VOP_DELETEEXTATTR(
		IN struct vnode *vp,
		IN int attrnamespace,
		IN const char *name,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_deleteextattr_args a;

	a.a_gen.a_desc = &vop_deleteextattr_desc;
	a.a_vp = vp;
	a.a_attrnamespace = attrnamespace;
	a.a_name = name;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_DELETEEXTATTR_APV(vp->v_op, &a));
}

struct vop_setextattr_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_attrnamespace;
		IN const char *a_name;
		INOUT struct uio *a_uio;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_setextattr_desc;

int VOP_SETEXTATTR_AP(struct vop_setextattr_args *);
int VOP_SETEXTATTR_APV(struct vop_vector *vop, struct vop_setextattr_args *);

static __inline int VOP_SETEXTATTR(
		IN struct vnode *vp,
		IN int attrnamespace,
		IN const char *name,
		INOUT struct uio *uio,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_setextattr_args a;

	a.a_gen.a_desc = &vop_setextattr_desc;
	a.a_vp = vp;
	a.a_attrnamespace = attrnamespace;
	a.a_name = name;
	a.a_uio = uio;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_SETEXTATTR_APV(vp->v_op, &a));
}

struct vop_setlabel_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct label *a_label;
		IN struct ucred *a_cred;
		IN struct thread *a_td;
};

extern struct vnodeop_desc vop_setlabel_desc;

int VOP_SETLABEL_AP(struct vop_setlabel_args *);
int VOP_SETLABEL_APV(struct vop_vector *vop, struct vop_setlabel_args *);

static __inline int VOP_SETLABEL(
		IN struct vnode *vp,
		IN struct label *label,
		IN struct ucred *cred,
		IN struct thread *td)
{
	struct vop_setlabel_args a;

	a.a_gen.a_desc = &vop_setlabel_desc;
	a.a_vp = vp;
	a.a_label = label;
	a.a_cred = cred;
	a.a_td = td;
	return (VOP_SETLABEL_APV(vp->v_op, &a));
}

struct vop_vptofh_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct fid *a_fhp;
};

extern struct vnodeop_desc vop_vptofh_desc;

int VOP_VPTOFH_AP(struct vop_vptofh_args *);
int VOP_VPTOFH_APV(struct vop_vector *vop, struct vop_vptofh_args *);

static __inline int VOP_VPTOFH(
		IN struct vnode *vp,
		IN struct fid *fhp)
{
	struct vop_vptofh_args a;

	a.a_gen.a_desc = &vop_vptofh_desc;
	a.a_vp = vp;
	a.a_fhp = fhp;
	return (VOP_VPTOFH_APV(vp->v_op, &a));
}

struct vop_vptocnp_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		OUT struct vnode **a_vpp;
		IN struct ucred *a_cred;
		INOUT char *a_buf;
		INOUT int *a_buflen;
};

extern struct vnodeop_desc vop_vptocnp_desc;

int VOP_VPTOCNP_AP(struct vop_vptocnp_args *);
int VOP_VPTOCNP_APV(struct vop_vector *vop, struct vop_vptocnp_args *);

static __inline int VOP_VPTOCNP(
		IN struct vnode *vp,
		OUT struct vnode **vpp,
		IN struct ucred *cred,
		INOUT char *buf,
		INOUT int *buflen)
{
	struct vop_vptocnp_args a;

	a.a_gen.a_desc = &vop_vptocnp_desc;
	a.a_vp = vp;
	a.a_vpp = vpp;
	a.a_cred = cred;
	a.a_buf = buf;
	a.a_buflen = buflen;
	return (VOP_VPTOCNP_APV(vp->v_op, &a));
}

struct vop_allocate_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		INOUT off_t *a_offset;
		INOUT off_t *a_len;
};

extern struct vnodeop_desc vop_allocate_desc;

int VOP_ALLOCATE_AP(struct vop_allocate_args *);
int VOP_ALLOCATE_APV(struct vop_vector *vop, struct vop_allocate_args *);

static __inline int VOP_ALLOCATE(
		IN struct vnode *vp,
		INOUT off_t *offset,
		INOUT off_t *len)
{
	struct vop_allocate_args a;

	a.a_gen.a_desc = &vop_allocate_desc;
	a.a_vp = vp;
	a.a_offset = offset;
	a.a_len = len;
	return (VOP_ALLOCATE_APV(vp->v_op, &a));
}

struct vop_advise_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN off_t a_start;
		IN off_t a_end;
		IN int a_advice;
};

extern struct vnodeop_desc vop_advise_desc;

int VOP_ADVISE_AP(struct vop_advise_args *);
int VOP_ADVISE_APV(struct vop_vector *vop, struct vop_advise_args *);

static __inline int VOP_ADVISE(
		IN struct vnode *vp,
		IN off_t start,
		IN off_t end,
		IN int advice)
{
	struct vop_advise_args a;

	a.a_gen.a_desc = &vop_advise_desc;
	a.a_vp = vp;
	a.a_start = start;
	a.a_end = end;
	a.a_advice = advice;
	return (VOP_ADVISE_APV(vp->v_op, &a));
}

struct vop_unp_bind_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN struct socket *a_socket;
};

extern struct vnodeop_desc vop_unp_bind_desc;

int VOP_UNP_BIND_AP(struct vop_unp_bind_args *);
int VOP_UNP_BIND_APV(struct vop_vector *vop, struct vop_unp_bind_args *);

static __inline int VOP_UNP_BIND(
		IN struct vnode *vp,
		IN struct socket *socket)
{
	struct vop_unp_bind_args a;

	a.a_gen.a_desc = &vop_unp_bind_desc;
	a.a_vp = vp;
	a.a_socket = socket;
	return (VOP_UNP_BIND_APV(vp->v_op, &a));
}

struct vop_unp_connect_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		OUT struct socket **a_socket;
};

extern struct vnodeop_desc vop_unp_connect_desc;

int VOP_UNP_CONNECT_AP(struct vop_unp_connect_args *);
int VOP_UNP_CONNECT_APV(struct vop_vector *vop, struct vop_unp_connect_args *);

static __inline int VOP_UNP_CONNECT(
		IN struct vnode *vp,
		OUT struct socket **socket)
{
	struct vop_unp_connect_args a;

	a.a_gen.a_desc = &vop_unp_connect_desc;
	a.a_vp = vp;
	a.a_socket = socket;
	return (VOP_UNP_CONNECT_APV(vp->v_op, &a));
}

struct vop_unp_detach_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_unp_detach_desc;

int VOP_UNP_DETACH_AP(struct vop_unp_detach_args *);
int VOP_UNP_DETACH_APV(struct vop_vector *vop, struct vop_unp_detach_args *);

static __inline int VOP_UNP_DETACH(
		IN struct vnode *vp)
{
	struct vop_unp_detach_args a;

	a.a_gen.a_desc = &vop_unp_detach_desc;
	a.a_vp = vp;
	return (VOP_UNP_DETACH_APV(vp->v_op, &a));
}

struct vop_is_text_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_is_text_desc;

int VOP_IS_TEXT_AP(struct vop_is_text_args *);
int VOP_IS_TEXT_APV(struct vop_vector *vop, struct vop_is_text_args *);

static __inline int VOP_IS_TEXT(
		IN struct vnode *vp)
{
	struct vop_is_text_args a;

	a.a_gen.a_desc = &vop_is_text_desc;
	a.a_vp = vp;
	return (VOP_IS_TEXT_APV(vp->v_op, &a));
}

struct vop_set_text_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_set_text_desc;

int VOP_SET_TEXT_AP(struct vop_set_text_args *);
int VOP_SET_TEXT_APV(struct vop_vector *vop, struct vop_set_text_args *);

static __inline int VOP_SET_TEXT(
		IN struct vnode *vp)
{
	struct vop_set_text_args a;

	a.a_gen.a_desc = &vop_set_text_desc;
	a.a_vp = vp;
	return (VOP_SET_TEXT_APV(vp->v_op, &a));
}

struct vop_unset_text_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_unset_text_desc;

int VOP_UNSET_TEXT_AP(struct vop_unset_text_args *);
int VOP_UNSET_TEXT_APV(struct vop_vector *vop, struct vop_unset_text_args *);

static __inline int VOP_UNSET_TEXT(
		IN struct vnode *vp)
{
	struct vop_unset_text_args a;

	a.a_gen.a_desc = &vop_unset_text_desc;
	a.a_vp = vp;
	return (VOP_UNSET_TEXT_APV(vp->v_op, &a));
}

struct vop_get_writecount_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		OUT int *a_writecount;
};

extern struct vnodeop_desc vop_get_writecount_desc;

int VOP_GET_WRITECOUNT_AP(struct vop_get_writecount_args *);
int VOP_GET_WRITECOUNT_APV(struct vop_vector *vop, struct vop_get_writecount_args *);

static __inline int VOP_GET_WRITECOUNT(
		IN struct vnode *vp,
		OUT int *writecount)
{
	struct vop_get_writecount_args a;

	a.a_gen.a_desc = &vop_get_writecount_desc;
	a.a_vp = vp;
	a.a_writecount = writecount;
	return (VOP_GET_WRITECOUNT_APV(vp->v_op, &a));
}

struct vop_add_writecount_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
		IN int a_inc;
};

extern struct vnodeop_desc vop_add_writecount_desc;

int VOP_ADD_WRITECOUNT_AP(struct vop_add_writecount_args *);
int VOP_ADD_WRITECOUNT_APV(struct vop_vector *vop, struct vop_add_writecount_args *);

static __inline int VOP_ADD_WRITECOUNT(
		IN struct vnode *vp,
		IN int inc)
{
	struct vop_add_writecount_args a;

	a.a_gen.a_desc = &vop_add_writecount_desc;
	a.a_vp = vp;
	a.a_inc = inc;
	return (VOP_ADD_WRITECOUNT_APV(vp->v_op, &a));
}

struct vop_spare1_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_spare1_desc;

int VOP_SPARE1_AP(struct vop_spare1_args *);
int VOP_SPARE1_APV(struct vop_vector *vop, struct vop_spare1_args *);

static __inline int VOP_SPARE1(
		IN struct vnode *vp)
{
	struct vop_spare1_args a;

	a.a_gen.a_desc = &vop_spare1_desc;
	a.a_vp = vp;
	return (VOP_SPARE1_APV(vp->v_op, &a));
}

struct vop_spare2_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_spare2_desc;

int VOP_SPARE2_AP(struct vop_spare2_args *);
int VOP_SPARE2_APV(struct vop_vector *vop, struct vop_spare2_args *);

static __inline int VOP_SPARE2(
		IN struct vnode *vp)
{
	struct vop_spare2_args a;

	a.a_gen.a_desc = &vop_spare2_desc;
	a.a_vp = vp;
	return (VOP_SPARE2_APV(vp->v_op, &a));
}

struct vop_spare3_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_spare3_desc;

int VOP_SPARE3_AP(struct vop_spare3_args *);
int VOP_SPARE3_APV(struct vop_vector *vop, struct vop_spare3_args *);

static __inline int VOP_SPARE3(
		IN struct vnode *vp)
{
	struct vop_spare3_args a;

	a.a_gen.a_desc = &vop_spare3_desc;
	a.a_vp = vp;
	return (VOP_SPARE3_APV(vp->v_op, &a));
}

struct vop_spare4_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_spare4_desc;

int VOP_SPARE4_AP(struct vop_spare4_args *);
int VOP_SPARE4_APV(struct vop_vector *vop, struct vop_spare4_args *);

static __inline int VOP_SPARE4(
		IN struct vnode *vp)
{
	struct vop_spare4_args a;

	a.a_gen.a_desc = &vop_spare4_desc;
	a.a_vp = vp;
	return (VOP_SPARE4_APV(vp->v_op, &a));
}

struct vop_spare5_args {
	struct vop_generic_args a_gen;
		IN struct vnode *a_vp;
};

extern struct vnodeop_desc vop_spare5_desc;

int VOP_SPARE5_AP(struct vop_spare5_args *);
int VOP_SPARE5_APV(struct vop_vector *vop, struct vop_spare5_args *);

static __inline int VOP_SPARE5(
		IN struct vnode *vp)
{
	struct vop_spare5_args a;

	a.a_gen.a_desc = &vop_spare5_desc;
	a.a_vp = vp;
	return (VOP_SPARE5_APV(vp->v_op, &a));
}


#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"
#include "opt_compat.h"
#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/capsicum.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/resourcevar.h>
#include <sys/selinfo.h>
#include <sys/sleepqueue.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/vnode.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/condvar.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif

#include <security/audit/audit.h>
#include <notifier.h>


/*
 *	Notifier chain core routines.  The exported routines below
 *	are layered on top of these, with appropriate locking added.
 */

static int notifier_chain_register(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if (n->priority > (*nl)->priority)
			break;
		nl = &((*nl)->next);
	}
	n->next = *nl;
	*nl = n;
	return 0;
}

static int notifier_chain_cond_register(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if ((*nl) == n)
			return 0;
		if (n->priority > (*nl)->priority)
			break;
		nl = &((*nl)->next);
	}
	n->next = *nl;
	*nl = n;
	return 0;
}

static int notifier_chain_unregister(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if ((*nl) == n) {
			*nl = n->next;
			return 0;
		}
		nl = &((*nl)->next);
	}
	return -ENOENT;
}

/**
 * notifier_call_chain - Informs the registered notifiers about an event.
 *	@nl:		Pointer to head of the blocking notifier chain
 *	@val:		Value passed unmodified to notifier function
 *	@v:		Pointer passed unmodified to notifier function
 *	@nr_to_call:	Number of notifier functions to be called. Don't care
 *			value of this parameter is -1.
 *	@nr_calls:	Records the number of notifications sent. Don't care
 *			value of this field is NULL.
 *	@returns:	notifier_call_chain returns the value returned by the
 *			last notifier function called.
 */
static int  notifier_call_chain(struct notifier_block **nl,
					unsigned long val, void *v,
					int nr_to_call,	int *nr_calls)
{
	int ret = NOTIFY_DONE;
	struct notifier_block *nb, *next_nb;

	nb = (*nl);

	while (nb && nr_to_call) {
		next_nb = (nb->next);

		ret = nb->notifier_call(nb, val, v);

		if (nr_calls)
			(*nr_calls)++;

		if ((ret & NOTIFY_STOP_MASK) == NOTIFY_STOP_MASK)
			break;
		nb = next_nb;
		nr_to_call--;
	}
	return ret;
}


/*
 *	Raw notifier chain routines.  There is no protection;
 *	the caller must provide it.  Use at your own risk!
 */

/**
 *	raw_notifier_chain_register - Add notifier to a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to a raw notifier chain.
 *	All locking must be provided by the caller.
 *
 *	Currently always returns zero.
 */
int raw_notifier_chain_register(struct raw_notifier_head *nh,
		struct notifier_block *n)
{
	return notifier_chain_register(&nh->head, n);
}


/**
 *	raw_notifier_chain_unregister - Remove notifier from a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from a raw notifier chain.
 *	All locking must be provided by the caller.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int raw_notifier_chain_unregister(struct raw_notifier_head *nh,
		struct notifier_block *n)
{
	return notifier_chain_unregister(&nh->head, n);
}


/**
 *	__raw_notifier_call_chain - Call functions in a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *	@nr_to_call: See comment for notifier_call_chain.
 *	@nr_calls: See comment for notifier_call_chain
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in an undefined context.
 *	All locking must be provided by the caller.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then raw_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int __raw_notifier_call_chain(struct raw_notifier_head *nh,
			      unsigned long val, void *v,
			      int nr_to_call, int *nr_calls)
{
	return notifier_call_chain(&nh->head, val, v, nr_to_call, nr_calls);
}


int raw_notifier_call_chain(struct raw_notifier_head *nh,
		unsigned long val, void *v)
{
	return __raw_notifier_call_chain(nh, val, v, -1, NULL);
}


/*************************net device*************************/
RAW_NOTIFIER_HEAD(netdev_chain);


int register_netdevice_notifier(struct notifier_block *nb)
{

	int err;

	//rtnl_lock();
	err = raw_notifier_chain_register(&netdev_chain, nb);

	//rtnl_unlock();
	return err;

}



int unregister_netdevice_notifier(struct notifier_block *nb)
{
	int err;

	//rtnl_lock();
	err = raw_notifier_chain_unregister(&netdev_chain, nb);
	//rtnl_unlock();
	return err;
}

int call_netdevice_notifiers_info(unsigned long val, struct ifnet *dev,
				  struct netdev_notifier_info *info)
{
	//ASSERT_RTNL();
	netdev_notifier_info_init(info, dev);
	return raw_notifier_call_chain(&netdev_chain, val, info);

}


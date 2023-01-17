// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * mshv_root module's main interrupt handler and associated functionality.
 *
 * Authors:
 *   Nuno Das Neves <nunodasneves@linux.microsoft.com>
 *   Lillian Grassin-Drake <ligrassi@microsoft.com>
 *   Vineeth Remanan Pillai <viremana@linux.microsoft.com>
 *   Wei Liu <wei.liu@kernel.org>
 *   Stanislav Kinsburskii <skinsburskii@linux.microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/random.h>
#include <asm/mshyperv.h>

#include "hyperv_vmbus.h"
#include "mshv_eventfd.h"
#include "mshv.h"

u32
synic_event_ring_get_queued_port(u32 sint_index)
{
	struct hv_synic_event_ring_page **event_ring_page;
	volatile struct hv_synic_event_ring *ring;
	struct hv_synic_pages *spages;
	u8 **synic_eventring_tail;
	u32 message;
	u8 tail;

	spages = this_cpu_ptr(mshv.synic_pages);
	event_ring_page = &spages->synic_event_ring_page;
	synic_eventring_tail = (u8 **)this_cpu_ptr(hv_synic_eventring_tail);
	tail = (*synic_eventring_tail)[sint_index];

	if (unlikely(!(*event_ring_page))) {
		pr_err("%s: Missing synic event ring page!\n", __func__);
		return 0;
	}

	ring = &(*event_ring_page)->sint_event_ring[sint_index];

	/*
	 * Get the message.
	 */
	message = ring->data[tail];

	if (!message) {
		if (ring->ring_full) {
			/*
			 * Ring is marked full, but we would have consumed all
			 * the messages. Notify the hypervisor that ring is now
			 * empty and check again.
			 */
			ring->ring_full = 0;
			hv_call_notify_port_ring_empty(sint_index);
			message = ring->data[tail];
		}

		if (!message) {
			ring->signal_masked = 0;
			/*
			 * Unmask the signal and sync with hypervisor
			 * before one last check for any message.
			 */
			mb();
			message = ring->data[tail];

			/*
			 * Ok, lets bail out.
			 */
			if (!message)
				return 0;
		}

		ring->signal_masked = 1;

	}

	/*
	 * Clear the message in the ring buffer.
	 */
	ring->data[tail] = 0;

	if (++tail == HV_SYNIC_EVENT_RING_MESSAGE_COUNT)
		tail = 0;

	(*synic_eventring_tail)[sint_index] = tail;

	return message;
}

static bool
mshv_doorbell_isr(struct hv_message *msg)
{
	struct hv_notification_message_payload *notification;
	u32 port;

	if (msg->header.message_type != HVMSG_SYNIC_SINT_INTERCEPT)
		return false;

	notification = (struct hv_notification_message_payload *)msg->u.payload;
	if (notification->sint_index != HV_SYNIC_DOORBELL_SINT_INDEX)
		return false;

	while ((port = synic_event_ring_get_queued_port(
					HV_SYNIC_DOORBELL_SINT_INDEX))) {
		struct port_table_info ptinfo = { 0 };

		if (hv_portid_lookup(port, &ptinfo)) {
			pr_err("Failed to get port information from port_table!\n");
			continue;
		}

		if (ptinfo.port_type != HV_PORT_TYPE_DOORBELL) {
			pr_warn("Not a doorbell port!, port: %d, port_type: %d\n",
					port, ptinfo.port_type);
			continue;
		}

		/* Invoke the callback */
		ptinfo.port_doorbell.doorbell_cb(port, ptinfo.port_doorbell.data);
	}

	return true;
}

static bool mshv_async_call_completion_isr(struct hv_message *msg)
{
	bool handled = false;
	struct hv_async_completion_message_payload *async_msg;
	struct mshv_partition *partition;
	u64 partition_id;

	if (msg->header.message_type != HVMSG_ASYNC_CALL_COMPLETION)
		goto out;

	async_msg =
		(struct hv_async_completion_message_payload *)msg->u.payload;

	partition_id = async_msg->partition_id;

	/*
	 * Hold this lock for the rest of the isr, because the partition could
	 * be released anytime.
	 * e.g. the MSHV_RUN_VP thread could wake on another cpu; it could
	 * release the partition unless we hold this!
	 */
	rcu_read_lock();

	partition = mshv_partition_find(partition_id);
	if (unlikely(!partition)) {
		pr_err("%s: failed to find partition %llu\n",
		       __func__, partition_id);
		goto unlock_out;
	}

	pr_debug("%s: Partition ID: %llu completing async hypercall\n",
		 __func__, async_msg->partition_id);

	complete(&partition->async_hypercall);

	handled = true;

unlock_out:
	rcu_read_unlock();
out:
	return handled;
}

static void kick_vp(struct mshv_vp *vp)
{
	atomic64_inc(&vp->run.signaled_count);
	vp->run.kicked_by_hv = 1;
	wake_up(&vp->run.suspend_queue);
}

static void
handle_bitset_message(const struct hv_vp_signal_bitset_scheduler_message *msg)
{
	int bank_idx, vp_signaled, bank_mask_size;
	struct mshv_partition *partition;
	const struct hv_vpset *vpset;
	const u64 *bank_contents;
	u64 partition_id = msg->partition_id;

	if (msg->vp_bitset.bitset.format != HV_GENERIC_SET_SPARSE_4K) {
		pr_debug("%s: scheduler message format is not HV_GENERIC_SET_SPARSE_4K",
			__func__);
		return;
	}

	if (msg->vp_count == 0) {
		pr_debug("%s: scheduler message with no VP specified", __func__);
		return;
	}

	rcu_read_lock();

	partition = mshv_partition_find(partition_id);
	if (unlikely(!partition)) {
		pr_err("%s: failed to find partition %llu\n", __func__,
			partition_id);
		goto unlock_out;
	}

	vpset = &msg->vp_bitset.bitset;

	bank_idx = -1;
	bank_contents = vpset->bank_contents;
	bank_mask_size = sizeof(vpset->valid_bank_mask) * BITS_PER_BYTE;

	vp_signaled = 0;

	while (true) {
		int vp_bank_idx = -1;
		int vp_bank_size = sizeof(*bank_contents) * BITS_PER_BYTE;
		int vp_index;

		bank_idx = find_next_bit((unsigned long *)&vpset->valid_bank_mask,
				bank_mask_size, bank_idx + 1);
		if (bank_idx == bank_mask_size)
			break;

		while (true) {
			struct mshv_vp *vp;

			vp_bank_idx = find_next_bit((unsigned long *)bank_contents,
					vp_bank_size, vp_bank_idx + 1);
			if (vp_bank_idx == vp_bank_size)
				break;

			vp_index = (bank_idx << HV_GENERIC_SET_SHIFT) + vp_bank_idx;

			/* This shouldn't happen, but just in case. */
			if (unlikely(vp_index >= MSHV_MAX_VPS)) {
				pr_err("%s: VP index %u out of bounds\n",
					__func__, vp_index);
				goto unlock_out;
			}

			vp = partition->vps.array[vp_index];
			if (unlikely(!vp)) {
				pr_err("%s: failed to find vp\n", __func__);
				goto unlock_out;
			}

			kick_vp(vp);
			vp_signaled++;
		}

		bank_contents++;
	}

unlock_out:
	rcu_read_unlock();

	if (vp_signaled != msg->vp_count)
		pr_debug("%s: asked to signal %u VPs but only did %u\n",
			__func__, msg->vp_count, vp_signaled);
}

static void
handle_pair_message(const struct hv_vp_signal_pair_scheduler_message *msg)
{
	struct mshv_partition *partition = NULL;
	struct mshv_vp *vp;
	int idx;

	rcu_read_lock();

	for (idx = 0; idx < msg->vp_count; idx++) {
		u64 partition_id = msg->partition_ids[idx];
		u32 vp_index = msg->vp_indexes[idx];

		if (idx == 0 || partition->id != partition_id) {
			partition = mshv_partition_find(partition_id);
			if (unlikely(!partition)) {
				pr_err("%s: failed to find partition %llu\n",
					__func__, partition_id);
				break;
			}
		}

		/* This shouldn't happen, but just in case. */
		if (unlikely(vp_index >= MSHV_MAX_VPS)) {
			pr_err("%s: VP index %u out of bounds\n", __func__,
				vp_index);
			break;
		}

		vp = partition->vps.array[vp_index];
		if (!vp) {
			pr_err("%s: failed to find VP\n", __func__);
			break;
		}

		kick_vp(vp);
	}

	rcu_read_unlock();
}

static bool
mshv_scheduler_isr(struct hv_message *msg)
{
	if (msg->header.message_type != HVMSG_SCHEDULER_VP_SIGNAL_BITSET &&
		msg->header.message_type != HVMSG_SCHEDULER_VP_SIGNAL_PAIR)
		return false;

	if (msg->header.message_type == HVMSG_SCHEDULER_VP_SIGNAL_BITSET)
		handle_bitset_message(
			(struct hv_vp_signal_bitset_scheduler_message *)msg->u.payload);
	else
		handle_pair_message(
			(struct hv_vp_signal_pair_scheduler_message *)msg->u.payload);

	return true;
}

static bool
mshv_intercept_isr(struct hv_message *msg)
{
	struct mshv_partition *partition;
	bool handled = false;
	struct mshv_vp *vp;
	u64 partition_id;
	u32 vp_index;

	partition_id = msg->header.sender;

	rcu_read_lock();

	partition = mshv_partition_find(partition_id);
	if (unlikely(!partition)) {
		pr_err("%s: failed to find partition %llu\n",
		       __func__, partition_id);
		goto unlock_out;
	}

	if (msg->header.message_type == HVMSG_X64_APIC_EOI) {
		/*
		 * Check if this gsi is registered in the
		 * ack_notifier list and invoke the callback
		 * if registered.
		 */

		/*
		 * If there is a notifier, the ack callback is supposed
		 * to handle the VMEXIT. So we need not pass this message
		 * to vcpu thread.
		 */
		if (mshv_notify_acked_gsi(partition,
				hv_get_interrupt_vector_from_payload(msg->u.payload[0]))) {
			handled = true;
			goto unlock_out;
		}
	}

	/*
	 * We should get an opaque intercept message here for all intercept
	 * messages, since we're using the mapped VP intercept message page.
	 *
	 * The intercept message will have been placed in intercept message
	 * page at this point.
	 *
	 * Make sure the message type matches our expectation.
	 */
	if (msg->header.message_type != HVMSG_OPAQUE_INTERCEPT) {
		pr_debug("%s: wrong message type %d", __func__,
			msg->header.message_type);
		goto unlock_out;
	}

	/*
	 * Since we directly index the vp, and it has to exist for us to be here
	 * (because the vp is only deleted when the partition is), no additional
	 * locking is needed here
	 */
	vp_index = ((struct hv_opaque_intercept_message *)msg->u.payload)->vp_index;
	vp = partition->vps.array[vp_index];
	if (unlikely(!vp)) {
		pr_err("%s: failed to find vp\n", __func__);
		goto unlock_out;
	}

	kick_vp(vp);

	handled = true;

unlock_out:
	rcu_read_unlock();

	return handled;
}

void mshv_isr(void)
{
	struct hv_synic_pages *spages = this_cpu_ptr(mshv.synic_pages);
	struct hv_message_page **msg_page = &spages->synic_message_page;
	struct hv_message *msg;
	bool handled;

	if (unlikely(!(*msg_page))) {
		pr_err("%s: Missing synic page!\n", __func__);
		return;
	}

	msg = &((*msg_page)->sint_message[HV_SYNIC_INTERCEPTION_SINT_INDEX]);

	/*
	 * If the type isn't set, there isn't really a message;
	 * it may be some other hyperv interrupt
	 */
	if (msg->header.message_type == HVMSG_NONE)
		return;

	handled = mshv_doorbell_isr(msg);

	if (!handled)
		handled = mshv_scheduler_isr(msg);

	if (!handled)
		handled = mshv_async_call_completion_isr(msg);

	if (!handled)
		handled = mshv_intercept_isr(msg);

	if (handled) {
		/*
		 * Acknowledge message with hypervisor if another message is
		 * pending.
		 */
		msg->header.message_type = HVMSG_NONE;
		mb();
		if (msg->header.message_flags.msg_pending)
			hv_set_register(HV_REGISTER_EOM, 0);

#ifdef HYPERVISOR_CALLBACK_VECTOR
		add_interrupt_randomness(HYPERVISOR_CALLBACK_VECTOR);
#endif
	} else {
		pr_warn_once("%s: unknown message type 0x%x\n", __func__,
				msg->header.message_type);
	}
}

int
hv_register_doorbell(u64 partition_id, doorbell_cb_t doorbell_cb, void *data,
		     u64 gpa, u64 val, u64 flags)
{
	struct hv_connection_info connection_info = { 0 };
	union hv_connection_id connection_id = { 0 };
	struct port_table_info *port_table_info;
	struct hv_port_info port_info = { 0 };
	union hv_port_id port_id = { 0 };
	int ret;

	port_table_info = kmalloc(sizeof(struct port_table_info),
				  GFP_KERNEL);
	if (!port_table_info)
		return -ENOMEM;

	port_table_info->port_type = HV_PORT_TYPE_DOORBELL;
	port_table_info->port_doorbell.doorbell_cb = doorbell_cb;
	port_table_info->port_doorbell.data = data;
	ret = hv_portid_alloc(port_table_info);
	if (ret < 0) {
		pr_err("Failed to create the doorbell port!\n");
		kfree(port_table_info);
		return ret;
	}

	port_id.u.id = ret;
	port_info.port_type = HV_PORT_TYPE_DOORBELL;
	port_info.doorbell_port_info.target_sint = HV_SYNIC_DOORBELL_SINT_INDEX;
	port_info.doorbell_port_info.target_vp = HV_ANY_VP;
	ret = hv_call_create_port(hv_current_partition_id, port_id, partition_id,
				  &port_info,
				  0, 0, NUMA_NO_NODE);

	if (ret < 0) {
		pr_err("Failed to create the port!\n");
		hv_portid_free(port_id.u.id);
		return ret;
	}

	connection_id.u.id = port_id.u.id;
	connection_info.port_type = HV_PORT_TYPE_DOORBELL;
	connection_info.doorbell_connection_info.gpa = gpa;
	connection_info.doorbell_connection_info.trigger_value = val;
	connection_info.doorbell_connection_info.flags = flags;

	ret = hv_call_connect_port(hv_current_partition_id, port_id, partition_id,
				   connection_id, &connection_info, 0, NUMA_NO_NODE);
	if (ret < 0) {
		hv_call_delete_port(hv_current_partition_id, port_id);
		hv_portid_free(port_id.u.id);
		return ret;
	}

	// lets use the port_id as the doorbell_id
	return port_id.u.id;
}

int
hv_unregister_doorbell(u64 partition_id, int doorbell_portid)
{
	int ret = 0;
	union hv_port_id port_id = { 0 };
	union hv_connection_id connection_id = { 0 };

	connection_id.u.id = doorbell_portid;
	ret = hv_call_disconnect_port(partition_id, connection_id);
	if (ret < 0)
		pr_err("Failed to disconnect the doorbell connection!\n");

	port_id.u.id = doorbell_portid;
	ret = hv_call_delete_port(hv_current_partition_id, port_id);
	if (ret < 0)
		pr_err("Failed to disconnect the doorbell connection!\n");

	hv_portid_free(doorbell_portid);

	return ret;
}

int mshv_synic_init(unsigned int cpu)
{
	int ret;
	struct hv_synic_pages *spages = this_cpu_ptr(mshv.synic_pages);
	void **msg_page = (void **)&spages->synic_message_page;
	void **event_flags_page = (void **)&spages->synic_event_flags_page;
	void **event_ring_page = (void **)&spages->synic_event_ring_page;

	ret = hv_synic_enable_page(HV_REGISTER_SIMP, msg_page);
	if (ret)
		return ret;

	ret = hv_synic_enable_page(HV_REGISTER_SIEFP, event_flags_page);
	if (ret)
		goto disable_simp;

	ret = hv_synic_enable_page(HV_REGISTER_SIRBP, event_ring_page);
	if (ret)
		goto disable_siefp;

#ifdef HYPERVISOR_CALLBACK_VECTOR
	/* Enable intercepts */
	hv_synic_unmask_sint(
			HV_REGISTER_SINT0 + HV_SYNIC_INTERCEPTION_SINT_INDEX,
			HYPERVISOR_CALLBACK_VECTOR);

	/* Doorbell SINT is an intercept */
	hv_synic_unmask_sint_as_intercept(
			HV_REGISTER_SINT0 + HV_SYNIC_DOORBELL_SINT_INDEX,
			HYPERVISOR_CALLBACK_VECTOR);
#endif

	/* Enable the global synic bit */
	hv_synic_enable_sctrl(HV_REGISTER_SCONTROL);

	return 0;

disable_siefp:
	hv_synic_disable_page(HV_REGISTER_SIEFP, event_flags_page);
disable_simp:
	hv_synic_disable_page(HV_REGISTER_SIMP, msg_page);
	return ret;
}

int mshv_synic_cleanup(unsigned int cpu)
{
	struct hv_synic_pages *spages = this_cpu_ptr(mshv.synic_pages);
	void **msg_page = (void **)&spages->synic_message_page;
	void **event_flags_page = (void **)&spages->synic_event_flags_page;
	void **event_ring_page = (void **)&spages->synic_event_ring_page;

	/* Disable the interrupt */
	hv_synic_mask_sint(HV_REGISTER_SINT0 + HV_SYNIC_INTERCEPTION_SINT_INDEX);
	/* Disable Doorbell SINT */
	hv_synic_mask_sint(HV_REGISTER_SINT0 + HV_SYNIC_DOORBELL_SINT_INDEX);
	/* Disable synic pages */
	hv_synic_disable_page(HV_REGISTER_SIRBP, event_ring_page);
	hv_synic_disable_page(HV_REGISTER_SIEFP, event_flags_page);
	hv_synic_disable_page(HV_REGISTER_SIMP, msg_page);
	/* Disable global synic bit */
	hv_synic_disable_sctrl(HV_REGISTER_SCONTROL);

	return 0;
}

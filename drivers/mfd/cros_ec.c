/*
 * ChromeOS EC multi-function device
 *
 * Copyright (C) 2012 Google, Inc
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * The ChromeOS EC multi function device is used to mux all the requests
 * to the EC device for its multiple features: keyboard controller,
 * battery charging and regulator control, firmware update.
 */

#include <asm/unaligned.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mfd/core.h>
#include <linux/mfd/cros_ec.h>
#include <linux/mfd/cros_ec_commands.h>
#include <linux/mfd/cros_ec_dev.h>
#include <linux/of_platform.h>
#include <linux/delay.h>

#include "cros_ec_dev.h"

#define EC_COMMAND_RETRIES	50

static int prepare_packet(struct cros_ec_device *ec_dev,
			  struct cros_ec_command *msg)
{
	struct ec_host_request *request;
	u8 *out;
	int i;
	u8 csum = 0;

	BUG_ON(ec_dev->proto_version != EC_HOST_REQUEST_VERSION);
	BUG_ON(msg->outsize + sizeof(*request) > ec_dev->dout_size);

	out = ec_dev->dout;
	request = (struct ec_host_request *)out;
	request->struct_version = EC_HOST_REQUEST_VERSION;
	request->checksum = 0;
	request->command = msg->command;
	request->command_version = msg->version;
	request->reserved = 0;
	request->data_len = msg->outsize;

	for (i = 0; i < sizeof(*request); i++)
		csum += out[i];

	/* Copy data and update checksum */
	memcpy(out + sizeof(*request), msg->outdata, msg->outsize);
	for (i = 0; i < msg->outsize; i++)
		csum += msg->outdata[i];

	request->checksum = -csum;

	return sizeof(*request) + msg->outsize;
}

int cros_ec_check_result(struct cros_ec_device *ec_dev,
			 struct cros_ec_command *msg)
{
	switch (msg->result) {
	case EC_RES_SUCCESS:
		return 0;
	case EC_RES_IN_PROGRESS:
		dev_dbg(ec_dev->dev, "command 0x%02x in progress\n",
			msg->command);
		return -EAGAIN;
	default:
		dev_dbg(ec_dev->dev, "command 0x%02x returned %d\n",
			msg->command, msg->result);
		return 0;
	}
}
EXPORT_SYMBOL(cros_ec_check_result);

static int send_command(struct cros_ec_device *ec_dev,
			struct cros_ec_command *msg)
{
	int ret;

	if (ec_dev->suspended) {
		dev_dbg(ec_dev->dev, "Device suspended.\n");
		return -EHOSTDOWN;
	}

	if (ec_dev->proto_version > 2)
		ret = ec_dev->pkt_xfer(ec_dev, msg);
	else
		ret = ec_dev->cmd_xfer(ec_dev, msg);

	if (msg->result == EC_RES_IN_PROGRESS) {
		int i;
		struct cros_ec_command status_msg;
		struct ec_response_get_comms_status status;

		status_msg.version = 0;
		status_msg.command = EC_CMD_GET_COMMS_STATUS;
		status_msg.outdata = NULL;
		status_msg.outsize = 0;
		status_msg.indata = (u8 *)&status;
		status_msg.insize = sizeof(status);

		/*
		 * Query the EC's status until it's no longer busy or
		 * we encounter an error.
		 */
		for (i = 0; i < EC_COMMAND_RETRIES; i++) {
			usleep_range(10000, 11000);

			if (ec_dev->proto_version > 2)
				ret = ec_dev->pkt_xfer(ec_dev, &status_msg);
			else
				ret = ec_dev->cmd_xfer(ec_dev, &status_msg);

			if (ret < 0)
				break;

			msg->result = status_msg.result;
			if (status_msg.result != EC_RES_SUCCESS)
				break;
			if (!(status.flags & EC_COMMS_STATUS_PROCESSING))
				break;
		}
	}

	return ret;
}

static int cros_ec_get_host_command_version_mask(struct cros_ec_device *ec_dev,
	u16 cmd, u32 *mask)
{
	struct ec_params_get_cmd_versions pver;
	struct ec_response_get_cmd_versions rver;
	struct cros_ec_command msg = {
		.command = EC_CMD_GET_CMD_VERSIONS,
		.version = 0,
		.outdata = (u8 *)&pver,
		.outsize = sizeof(pver),
		.indata = (u8 *)&rver,
		.insize = sizeof(rver),
	};
	int ret;

	pver.cmd = cmd;
	ret = cros_ec_cmd_xfer(ec_dev, &msg);
	if (ret > 0)
		*mask = rver.version_mask;
	return ret;
}

static int cros_ec_host_command_proto_probe(struct cros_ec_device *ec_dev,
	int devidx,
	struct ec_response_get_protocol_info *info)
{
	/*
	 * Try using v3+ to query for supported protocols. If this
	 * command fails, fall back to v2. Returns the highest protocol
	 * supported by the EC.
	 * Also sets the max request/response/passthru size.
	 */

	struct cros_ec_command msg;
	int ret;

	if (!ec_dev->pkt_xfer)
		return -EPROTONOSUPPORT;

	memset(&msg, 0, sizeof(msg));
	msg.command = EC_CMD_PASSTHRU_OFFSET(devidx) | EC_CMD_GET_PROTOCOL_INFO;
	msg.indata = (u8 *)info;
	msg.insize = sizeof(*info);

	ret = send_command(ec_dev, &msg);

	if (ret < 0) {
		dev_dbg(ec_dev->dev,
			"failed to probe for EC[%d] protocol version: %d\n",
			devidx, ret);
		return ret;
	}

	if (devidx > 0 && msg.result == EC_RES_INVALID_COMMAND)
		return -ENODEV;
	else if (msg.result != EC_RES_SUCCESS)
		return msg.result;

	return 0;
}

static int cros_ec_host_command_proto_probe_v2(struct cros_ec_device *ec_dev)
{
	struct cros_ec_command msg;
	struct ec_params_hello hello_params;
	struct ec_response_hello hello_response;
	int ret;

	hello_params.in_data = 0xa0b0c0d0;

	memset(&msg, 0, sizeof(msg));
	msg.command = EC_CMD_HELLO;
	msg.outdata = (u8 *)&hello_params;
	msg.outsize = sizeof(hello_params);
	msg.indata = (u8 *)&hello_response;
	msg.insize = sizeof(hello_response);

	ret = send_command(ec_dev, &msg);

	if (ret < 0) {
		dev_dbg(ec_dev->dev,
			"EC failed to respond to v2 hello: %d\n",
			ret);
		return ret;
	} else if (msg.result != EC_RES_SUCCESS) {
		dev_err(ec_dev->dev,
			"EC responded to v2 hello with error: %d\n",
			msg.result);
		return msg.result;
	} else if (hello_response.out_data != 0xa1b2c3d4) {
		dev_err(ec_dev->dev,
			"EC responded to v2 hello with bad result: %u\n",
			hello_response.out_data);
		return -EBADMSG;
	}

	return 0;
}

static int cros_ec_probe_all(struct cros_ec_device *ec_dev)
{
	struct device *dev = ec_dev->dev;
	struct ec_response_get_protocol_info proto_info;
	int ret;
	u32 ver_mask;

	/* First try sending with proto v3. */
	ec_dev->proto_version = 3;
	ret = cros_ec_host_command_proto_probe(ec_dev, 0, &proto_info);

	if (ret == 0) {
		ec_dev->max_request = proto_info.max_request_packet_size -
			sizeof(struct ec_host_request);
		ec_dev->max_response = proto_info.max_response_packet_size -
			sizeof(struct ec_host_response);
		ec_dev->proto_version =
			min(EC_HOST_REQUEST_VERSION,
					fls(proto_info.protocol_versions) - 1);
		dev_dbg(ec_dev->dev, "using proto v%u\n",
			ec_dev->proto_version);

		ec_dev->dout_size = proto_info.max_request_packet_size +
			EC_MAX_REQUEST_OVERHEAD;
		ec_dev->din_size = proto_info.max_response_packet_size +
			EC_MAX_RESPONSE_OVERHEAD;

		/*
		 * Check for PD
		 * TODO(gwendal):crbug/31456: add specific driver for samus PD
		 */
		ret = cros_ec_host_command_proto_probe(ec_dev, 1, &proto_info);

		if (ret) {
			dev_dbg(ec_dev->dev, "no PD chip found: %d\n", ret);
			ec_dev->max_passthru = 0;
		} else {
			dev_dbg(ec_dev->dev, "found PD chip\n");
			ec_dev->max_passthru =
				proto_info.max_request_packet_size -
				sizeof(struct ec_host_request);
		}
	} else {
		/* Try probing with a v2 hello message. */
		ec_dev->proto_version = 2;
		ret = cros_ec_host_command_proto_probe_v2(ec_dev);

		if (ret == 0) {
			/* V2 hello succeeded. */
			dev_dbg(ec_dev->dev, "falling back to proto v2\n");

			ec_dev->max_request = EC_PROTO2_MAX_PARAM_SIZE;
			ec_dev->max_response = EC_PROTO2_MAX_PARAM_SIZE;
			ec_dev->max_passthru = 0;
			ec_dev->pkt_xfer = NULL;
			ec_dev->din_size = EC_MSG_BYTES;
			ec_dev->dout_size = EC_MSG_BYTES;
		} else {
			/*
			 * It's possible for a probe to occur too early when
			 * the EC isn't listening. If this happens, we'll
			 * probe later when the first command is run.
			 */
			ec_dev->proto_version = EC_PROTO_VERSION_UNKNOWN;
			dev_dbg(ec_dev->dev, "EC probe failed: %d\n", ret);
			return ret;
		}
	}

	devm_kfree(dev, ec_dev->din);
	devm_kfree(dev, ec_dev->dout);

	ec_dev->din = devm_kzalloc(dev, ec_dev->din_size, GFP_KERNEL);
	if (!ec_dev->din)
		return -ENOMEM;
	ec_dev->dout = devm_kzalloc(dev, ec_dev->dout_size, GFP_KERNEL);
	if (!ec_dev->dout) {
		devm_kfree(dev, ec_dev->din);
		return -ENOMEM;
	}

	/* Probe if MKBP event is supported */
	ret = cros_ec_get_host_command_version_mask(ec_dev,
						    EC_CMD_GET_NEXT_EVENT,
						    &ver_mask);
	if (ret < 0 || ver_mask == 0)
		ec_dev->mkbp_event_supported = 0;
	else
		ec_dev->mkbp_event_supported = 1;

	return 0;
}

int cros_ec_prepare_tx(struct cros_ec_device *ec_dev,
		       struct cros_ec_command *msg)
{
	u8 *out;
	u8 csum;
	int i;

	if (ec_dev->proto_version > 2)
		return prepare_packet(ec_dev, msg);

	BUG_ON(msg->outsize > EC_PROTO2_MAX_PARAM_SIZE);
	out = ec_dev->dout;
	out[0] = EC_CMD_VERSION0 + msg->version;
	out[1] = msg->command;
	out[2] = msg->outsize;
	csum = out[0] + out[1] + out[2];
	for (i = 0; i < msg->outsize; i++)
		csum += out[EC_MSG_TX_HEADER_BYTES + i] = msg->outdata[i];
	out[EC_MSG_TX_HEADER_BYTES + msg->outsize] = csum;

	return EC_MSG_TX_PROTO_BYTES + msg->outsize;
}
EXPORT_SYMBOL(cros_ec_prepare_tx);

static int cros_ec_get_next_event(struct cros_ec_device *ec_dev)
{
	struct cros_ec_command msg = {
		.version = 0,
		.command = EC_CMD_GET_NEXT_EVENT,
		.outdata = NULL,
		.outsize = 0,
		.indata = (u8 *)&ec_dev->event_data,
		.insize = sizeof(ec_dev->event_data),
	};
	int ret;

	ret = cros_ec_cmd_xfer(ec_dev, &msg);
	if (ret > 0) {
		ec_dev->event_size = ret - 1;
	}
	return ret;
}

static int cros_ec_get_keyboard_state_event(struct cros_ec_device *ec_dev)
{
	struct cros_ec_command msg = {
		.version = 0,
		.command = EC_CMD_MKBP_STATE,
		.outdata = NULL,
		.outsize = 0,
		.indata = (u8 *)&ec_dev->event_data.data,
		.insize = sizeof(ec_dev->event_data.data),
	};

	ec_dev->event_data.event_type = EC_MKBP_EVENT_KEY_MATRIX;
	ec_dev->event_size = cros_ec_cmd_xfer(ec_dev, &msg);
	return ec_dev->event_size;
}

u32 cros_ec_get_host_event(struct cros_ec_device *ec_dev)
{
	u32 host_event;

	BUG_ON(!ec_dev->mkbp_event_supported);
	if (ec_dev->event_data.event_type != EC_MKBP_EVENT_HOST_EVENT)
		return 0;
	if (ec_dev->event_size != sizeof(host_event)) {
		dev_warn(ec_dev->dev, "Invalid host event size\n");
		return 0;
	}

	host_event = get_unaligned_le32(&ec_dev->event_data.data.host_event);
	return host_event;
}

static irqreturn_t ec_irq_thread(int irq, void *data)
{
	struct cros_ec_device *ec_dev = data;
	int ret, wake_event = 1;

	if (ec_dev->mkbp_event_supported) {
		ret = cros_ec_get_next_event(ec_dev);
		if (ec_dev->event_data.event_type == EC_MKBP_EVENT_SENSOR_FIFO) {
			/*
			 * While we are suspending, we may still receive
			 * sensor information on the wake up interrupt line.
			 * Ignore wake up event (significant motion) until we
			 * are fully suspended.
			 */
			wake_event = 0;
		}
	} else {
		ret = cros_ec_get_keyboard_state_event(ec_dev);
	}

	if (device_may_wakeup(ec_dev->dev) && wake_event)
		pm_wakeup_event(ec_dev->dev, 0);

	if (ret > 0)
		blocking_notifier_call_chain(&ec_dev->event_notifier,
					     0, ec_dev);
	return IRQ_HANDLED;
}

int cros_ec_cmd_xfer(struct cros_ec_device *ec_dev,
		     struct cros_ec_command *msg)
{
	int ret;

	mutex_lock(&ec_dev->lock);

	if (ec_dev->proto_version == EC_PROTO_VERSION_UNKNOWN) {
		ret = cros_ec_probe_all(ec_dev);
		if (ret) {
			dev_err(ec_dev->dev,
				"EC version unknown and probe failed; aborting command\n");
			mutex_unlock(&ec_dev->lock);
			return ret;
		}
	}

	if (msg->insize > ec_dev->max_response) {
		dev_dbg(ec_dev->dev, "clamping message receive buffer\n");
		msg->insize = ec_dev->max_response;
	}

	if (msg->command < EC_CMD_PASSTHRU_OFFSET(1)) {
		if (msg->outsize > ec_dev->max_request) {
			dev_err(ec_dev->dev,
				"request of size %u is too big (max: %u)\n",
				msg->outsize,
				ec_dev->max_request);
			mutex_unlock(&ec_dev->lock);
			return -EMSGSIZE;
		}
	} else {
		if (msg->outsize > ec_dev->max_passthru) {
			dev_err(ec_dev->dev,
				"passthru request of size %u is too big (max: %u)\n",
				msg->outsize,
				ec_dev->max_passthru);
			mutex_unlock(&ec_dev->lock);
			return -EMSGSIZE;
		}
	}

	ret = send_command(ec_dev, msg);
	mutex_unlock(&ec_dev->lock);

	return ret;
}
EXPORT_SYMBOL(cros_ec_cmd_xfer);

int cros_ec_cmd_xfer_status(struct cros_ec_device *ec_dev,
			    struct cros_ec_command *msg)
{
	int ret = cros_ec_cmd_xfer(ec_dev, msg);

	if (ret < 0)
		dev_err(ec_dev->dev, "Command xfer error (err:%d)\n", ret);
	else if (msg->result)
		return -EECRESULT - msg->result;

	return ret;
}
EXPORT_SYMBOL(cros_ec_cmd_xfer_status);

static int cros_ec_dev_register(struct cros_ec_device *ec_dev,
				int dev_id, int devidx)
{
	struct device *dev = ec_dev->dev;
	struct cros_ec_dev_platform ec_p = {
		.cmd_offset = 0,
	};
	struct mfd_cell ec_cell = {
		.name = "cros-ec-dev",
		.id = 0,
		.platform_data = &ec_p,
		.pdata_size = sizeof(ec_p),
	};
	switch (devidx) {
	case 0:
#ifdef CONFIG_OF
		ec_p.ec_name = of_get_property(dev->of_node, "devname", NULL);
		if (ec_p.ec_name == NULL) {
			dev_dbg(dev, "Name of device not found, using default");
			ec_p.ec_name = CROS_EC_DEV_NAME;
		}
#else
		ec_p.ec_name = CROS_EC_DEV_NAME;
#endif
		break;
	case 1:
		ec_p.ec_name = CROS_EC_DEV_PD_NAME;
		break;
	default:
		return -EINVAL;
	}
	ec_p.cmd_offset = EC_CMD_PASSTHRU_OFFSET(devidx);
	return mfd_add_devices(dev, dev_id, &ec_cell, 1,
			       NULL, ec_dev->irq, NULL);
}

int cros_ec_register(struct cros_ec_device *ec_dev)
{
	static int ec_dev_id;
	struct device *dev = ec_dev->dev;
	int err = 0;
#ifdef CONFIG_OF
	struct device_node *node;
	char name[128];
	struct mfd_cell cell = {
		.name = name,
		.id = 0,
	};
#endif

	BLOCKING_INIT_NOTIFIER_HEAD(&ec_dev->event_notifier);

	ec_dev->max_request = sizeof(struct ec_params_hello);
	ec_dev->max_response = sizeof(struct ec_response_get_protocol_info);
	ec_dev->max_passthru = 0;

	ec_dev->din = devm_kzalloc(dev, ec_dev->din_size, GFP_KERNEL);
	if (!ec_dev->din)
		return -ENOMEM;
	ec_dev->dout = devm_kzalloc(dev, ec_dev->dout_size, GFP_KERNEL);
	if (!ec_dev->dout) {
		devm_kfree(dev, ec_dev->din);
		return -ENOMEM;
	}
	mutex_init(&ec_dev->lock);

	cros_ec_probe_all(ec_dev);

	if (ec_dev->irq) {
		err = request_threaded_irq(ec_dev->irq, NULL, ec_irq_thread,
					   IRQF_TRIGGER_LOW | IRQF_ONESHOT,
					   "chromeos-ec", ec_dev);
		if (err) {
			dev_err(dev, "request irq %d: error %d\n",
				ec_dev->irq, err);
			return err;
		}
	}

	err = cros_ec_dev_register(ec_dev, ec_dev_id++, 0);
	if (err) {
		dev_err(dev, "failed to add ec\n");
		goto fail_mfd;
	}

	if (ec_dev->max_passthru) {
		/*
		 * Register a PD device as well on top of this device.
		 * We make the following assumptions:
		 * - behind an EC, we have a pd
		 * - only one device added.
		 * - the EC is responsive at init time (it is not true for a
		 *   sensor hub.
		 */
		err = cros_ec_dev_register(ec_dev, ec_dev_id++, 1);
		if (err) {
			dev_err(dev, "failed to add additional ec\n");
			goto fail_mfd;
		}
	}

#ifdef CONFIG_OF
	/*
	 * Add sub-devices declared in the device tree.  NOTE they should NOT be
	 * declared in cros_devs
	 */
	for_each_child_of_node(dev->of_node, node) {
		if (of_modalias_node(node, name, sizeof(name)) < 0) {
			dev_err(dev, "modalias failure on %s\n",
				node->full_name);
			continue;
		}
		dev_dbg(dev, "adding MFD sub-device %s\n", node->name);
		cell.of_compatible = of_get_property(node, "compatible", NULL);
		err = mfd_add_devices(dev, ec_dev_id++, &cell, 1, NULL,
				ec_dev->irq, NULL);
		if (err)
			dev_err(dev, "fail to add %s\n", node->full_name);
	}
#endif
	dev_info(dev, "Chrome EC device registered\n");

	return 0;

fail_mfd:
	if (ec_dev->irq)
		free_irq(ec_dev->irq, ec_dev);
	return err;
}
EXPORT_SYMBOL(cros_ec_register);

int cros_ec_remove(struct cros_ec_device *ec_dev)
{
	mfd_remove_devices(ec_dev->dev);

	return 0;
}
EXPORT_SYMBOL(cros_ec_remove);

#ifdef CONFIG_PM_SLEEP
int cros_ec_suspend(struct cros_ec_device *ec_dev)
{
	struct device *dev = ec_dev->dev;

	if (device_may_wakeup(dev))
		ec_dev->wake_enabled = !enable_irq_wake(ec_dev->irq);

	disable_irq(ec_dev->irq);
	ec_dev->was_wake_device = ec_dev->wake_enabled;
	ec_dev->suspended = true;

	return 0;
}
EXPORT_SYMBOL(cros_ec_suspend);

static void cros_ec_drain_events(struct cros_ec_device *ec_dev)
{
	while (cros_ec_get_next_event(ec_dev) > 0)
		blocking_notifier_call_chain(&ec_dev->event_notifier,
					     1, ec_dev);
}

int cros_ec_resume(struct cros_ec_device *ec_dev)
{
	ec_dev->suspended = false;
	enable_irq(ec_dev->irq);

	/*
	 * In some case, we need to distinguish events that occur during
	 * suspend if the EC is not a wake source. For example, keypresses
	 * during suspend should be discarded if it does not wake the system.
	 *
	 * If the EC is not a wake source, drain the event queue and mark them
	 * as "queued during suspend".
	 */
	if (ec_dev->wake_enabled) {
		disable_irq_wake(ec_dev->irq);
		ec_dev->wake_enabled = 0;
	} else {
		cros_ec_drain_events(ec_dev);
	}

	return 0;
}
EXPORT_SYMBOL(cros_ec_resume);

#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ChromeOS EC core driver");

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
 */

#ifndef __LINUX_MFD_CROS_EC_H
#define __LINUX_MFD_CROS_EC_H

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/notifier.h>
#include <linux/power_supply.h>
#include <linux/mfd/cros_ec_dev.h>
#include <linux/mfd/cros_ec_commands.h>
#include <linux/mutex.h>

/*
 * The EC is unresponsive for a time after a reboot command.  Add a
 * simple delay to make sure that the bus stays locked.
 */
#define EC_REBOOT_DELAY_MS		50

/*
 * Max bus-specific overhead incurred by request/responses.
 * I2C requires 1 additional byte for requests.
 * I2C requires 2 additional bytes for responses.
 * SPI requires up to 32 additional bytes for responses.
 * */
#define EC_MAX_REQUEST_OVERHEAD		1
#define EC_MAX_RESPONSE_OVERHEAD	32

#define EC_PROTO_VERSION_UNKNOWN	0

/* ec_command return value for non-success result from EC */
#define EECRESULT 1000

/*
 * Command interface between EC and AP, for LPC, I2C and SPI interfaces.
 */
enum {
	EC_MSG_TX_HEADER_BYTES	= 3,
	EC_MSG_TX_TRAILER_BYTES	= 1,
	EC_MSG_TX_PROTO_BYTES	= EC_MSG_TX_HEADER_BYTES +
					EC_MSG_TX_TRAILER_BYTES,
	EC_MSG_RX_PROTO_BYTES	= 3,

	/* Max length of messages */
	EC_MSG_BYTES		= EC_PROTO2_MAX_PARAM_SIZE +
					EC_MSG_TX_PROTO_BYTES,
};

struct cros_ec_device;
struct cros_ec_debugfs;

/*
 * struct cros_ec_dev - ChromeOS EC device entry point
 *
 * @class_dev: Device structure used in sysfs
 * @cdev: Character device structure in /dev
 * @ec_dev: cros_ec_device structure to talk to the physical device
 * @dev: pointer to the platform device
 * @debug_info: cros_ec_debugfs structure for debugging information
 * @cmd_offset: offset to apply for each command.
 */
struct cros_ec_dev {
	struct device class_dev;
	struct cdev cdev;
	struct cros_ec_device *ec_dev;
	struct device *dev;
	struct cros_ec_debugfs *debug_info;
	u16 cmd_offset;
	u32 features[2];
};

/*
 * event_data is used by keyboard or event notifier:
 * event_data format:
 * If MKBP protocol is supported:
 * 0           1
 * +-----------+--------------------------------
 * | type      | payload
 * +-----------+--------------------------------
 * |HOST_EVENT | EVENT (32 bit)
 * |KEY_MATRIX | Keyboard keys pressed.
 * |SENSOR_FIFO| Sensors FIFO information.
 *
 * Otherwise:
 * 0           1
 * +-----------+--------------------------------
 * |Unused     | Keyboard keys pressed.
 */

/**
 * struct cros_ec_device - Information about a ChromeOS EC device
 *
 * @phys_name: name of physical comms layer (e.g. 'i2c-4')
 * @dev: Device pointer for physical comms device
 * @was_wake_device: true if this device was set to wake the system from
 * sleep at the last suspend
 *
 * @priv: Private data
 * @irq: Interrupt to use
 * @din: input buffer (for data from EC)
 * @dout: output buffer (for data to EC)
 * \note
 * These two buffers will always be dword-aligned and include enough
 * space for up to 7 word-alignment bytes also, so we can ensure that
 * the body of the message is always dword-aligned (64-bit).
 * We use this alignment to keep ARM and x86 happy. Probably word
 * alignment would be OK, there might be a small performance advantage
 * to using dword.
 * @din_size: size of din buffer to allocate (zero to use static din)
 * @dout_size: size of dout buffer to allocate (zero to use static dout)
 * @wake_enabled: true if this device can wake the system from sleep
 * @suspended: true if this device had been suspended
 * @cmd_xfer: send command to EC and get response
 *     Returns the number of bytes received if the communication succeeded, but
 *     that doesn't mean the EC was happy with the command. The caller
 *     should check msg.result for the EC's result code.
 * @cmd_read_mem: direct read of the EC memory-mapped region, if supported
 *     @offset is within EC_LPC_ADDR_MEMMAP region.
 *     @bytes: number of bytes to read. zero means "read a string" (including
 *     the trailing '\0'). At most only EC_MEMMAP_SIZE bytes can be read.
 *     Caller must ensure that the buffer is large enough for the result when
 *     reading a string.
 * @lock: one transaction at a time
 * @event_notifier: interrupt event notifier for transport devices.
 * @event_data: raw payload transferred with the MKBP event.
 * @event_size: size in bytes of the event data.
 */
struct cros_ec_device {

	/* These are used by other drivers that want to talk to the EC */
	const char *phys_name;
	struct device *dev;
	bool was_wake_device;
	struct class *cros_class;

	/* These are used to implement the platform-specific interface */
	u16 max_request;
	u16 max_response;
	u16 max_passthru;
	u16 proto_version;
	void *priv;
	int irq;
	u8 *din;
	u8 *dout;
	int din_size;
	int dout_size;
	bool wake_enabled;
	bool suspended;
	int (*cmd_xfer)(struct cros_ec_device *ec,
			struct cros_ec_command *msg);
	int (*cmd_readmem)(struct cros_ec_device *ec, unsigned int offset,
			   unsigned int bytes, void *dest);
	int (*cmd_read_u32)(struct cros_ec_device *ec, unsigned int offset,
			    u32 *dest);
	int (*cmd_read_u16)(struct cros_ec_device *ec, unsigned int offset,
			    u16 *dest);
	int (*cmd_read_u8)(struct cros_ec_device *ec, unsigned int offset,
			   u8 *dest);
	int (*pkt_xfer)(struct cros_ec_device *ec,
			struct cros_ec_command *msg);
	struct power_supply *charger;
	struct mutex lock;
	bool mkbp_event_supported;
	struct blocking_notifier_head event_notifier;
	struct ec_response_get_next_event event_data;
	int event_size;
};

/* struct cros_ec_dev_platform - ChromeOS EC platform information
 *
 * On top of a cros_ec device, information cros_ec_device needs.
 *
 * @ec_name: name of EC device (e.g. 'cros-ec', 'cros-pd', ...)
 * used in /dev/ and sysfs.
 * @cmd_offset: offset to apply for each command. Set when
 * registering a devicde behind another one.
 */
struct cros_ec_dev_platform {
	const char *ec_name;
	u16 cmd_offset;
};

/* struct cros_ec_sensor_platform - ChromeOS EC sensor platform information
 *
 * On top of cros_ec_devicem information cros_ec_sensors needs.
 *
 * @sensor_num: Id of the sensor, as reported by the EC.
 */
struct cros_ec_sensor_platform {
	u8 sensor_num;
};



/**
 * cros_ec_suspend - Handle a suspend operation for the ChromeOS EC device
 *
 * This can be called by drivers to handle a suspend event.
 *
 * ec_dev: Device to suspend
 * @return 0 if ok, -ve on error
 */
int cros_ec_suspend(struct cros_ec_device *ec_dev);

/**
 * cros_ec_resume - Handle a resume operation for the ChromeOS EC device
 *
 * This can be called by drivers to handle a resume event.
 *
 * @ec_dev: Device to resume
 * @return 0 if ok, -ve on error
 */
int cros_ec_resume(struct cros_ec_device *ec_dev);

/**
 * cros_ec_prepare_tx - Prepare an outgoing message in the output buffer
 *
 * This is intended to be used by all ChromeOS EC drivers, but at present
 * only SPI uses it. Once LPC uses the same protocol it can start using it.
 * I2C could use it now, with a refactor of the existing code.
 *
 * @ec_dev: Device to register
 * @msg: Message to write
 */
int cros_ec_prepare_tx(struct cros_ec_device *ec_dev,
		       struct cros_ec_command *msg);

/**
 * cros_ec_check_result - Check ec_msg->result
 *
 * This is used by ChromeOS EC drivers to check the ec_msg->result for
 * errors and to warn about them.
 *
 * @ec_dev: EC device
 * @msg: Message to check
 */
int cros_ec_check_result(struct cros_ec_device *ec_dev,
			 struct cros_ec_command *msg);

/**
 * cros_ec_cmd_xfer - Send a command to the ChromeOS EC
 *
 * Call this to send a command to the ChromeOS EC.  This should be used
 * instead of calling the EC's cmd_xfer() callback directly. Note that
 * msg->result should be checked before assuming that the command ran
 * successfully on the EC.
 *
 * @ec_dev: EC device
 * @msg: Message to write
 * @return: Num. of bytes transferred on success, <0 on failure
 */
int cros_ec_cmd_xfer(struct cros_ec_device *ec_dev,
		     struct cros_ec_command *msg);

/**
 * cros_ec_cmd_xfer_status - Send a command to the ChromeOS EC
 *
 * This function is identical to cros_ec_cmd_xfer, except it returns succes
 * status only if both the command was transmitted successfully and the EC
 * replied with success status. It's not necessary to check msg->result when
 * using this function.
 *
 * @ec_dev: EC device
 * @msg: Message to write
 * @return: Num. of bytes transferred on success, <0 on failure
 */
int cros_ec_cmd_xfer_status(struct cros_ec_device *ec_dev,
			    struct cros_ec_command *msg);

/**
 * cros_ec_remove - Remove a ChromeOS EC
 *
 * Call this to deregister a ChromeOS EC, then clean up any private data.
 *
 * @ec_dev: Device to register
 * @return 0 if ok, -ve on error
 */
int cros_ec_remove(struct cros_ec_device *ec_dev);

/**
 * cros_ec_register - Register a new ChromeOS EC, using the provided info
 *
 * Before calling this, allocate a pointer to a new device and then fill
 * in all the fields up to the --private-- marker.
 *
 * @ec_dev: Device to register
 * @return 0 if ok, -ve on error
 */
int cros_ec_register(struct cros_ec_device *ec_dev);

/**
 * cros_ec_get_host_event - Return a mask of event set by the EC.
 *
 * When MKBP is supported, when the EC raises an interrupt,
 * We collect the events raised and call the functions in the ec notifier.
 *
 * This function is a helper to know which events are raised.
 */
uint32_t cros_ec_get_host_event(struct cros_ec_device *ec_dev);

#endif  /* __LINUX_MFD_CROS_EC_H */

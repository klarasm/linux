// SPDX-License-Identifier: GPL-2.0
/*
 * USB interface for ChromeOS Embedded Controller
 *
 * Copyright (C) 2025 Google LLC.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/usb.h>

#include <linux/platform_data/cros_ec_commands.h>
#include <linux/platform_data/cros_ec_proto.h>
#include <linux/platform_device.h>

#include "cros_ec.h"

/* Google */
#define USB_VENDOR_ID_GOOGLE 0x18d1

#define USB_SUBCLASS_GOOGLE_EC_HOST_CMD 0x5a
#define USB_PROTOCOL_GOOGLE_EC_HOST_CMD 0x00

#define RESPONSE_TIMEOUT_MS 200
#define BULK_TRANSFER_TIMEOUT_MS 100

enum cros_ec_usb_int_type {
	INT_TYPE_EVENT_OCCURED = 0,
	INT_TYPE_RESPONSE_READY = 1,
};

/* table of devices that work with this driver */
static const struct usb_device_id cros_ec_usb_table[] = {
	{ USB_VENDOR_AND_INTERFACE_INFO(USB_VENDOR_ID_GOOGLE,
					USB_CLASS_VENDOR_SPEC,
					USB_SUBCLASS_GOOGLE_EC_HOST_CMD,
					USB_PROTOCOL_GOOGLE_EC_HOST_CMD) },
	{} /* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, cros_ec_usb_table);

/* Structure to hold all of our device specific stuff */
struct cros_ec_usb {
	/* the usb device for this device */
	struct usb_device *udev;
	/* the interface for this device */
	struct usb_interface *interface;
	/* Cros EC device structure */
	struct cros_ec_device *ec_dev;
	/* the buffer to receive data from bulk ep */
	u8 *bulk_in_buffer;
	/* the buffer to receive data from int ep */
	u8 *int_in_buffer;
	/* the urb to receive data from int ep */
	struct urb *int_in_urb;
	/* the size of the receive buffer from bulk ep */
	size_t bulk_in_size;
	/* the size of the receive buffer from int ep */
	size_t int_in_size;
	/* the pipe of the bulk in ep */
	unsigned int bulk_in_pipe;
	/* the pipe of the bulk out ep */
	unsigned int bulk_out_pipe;
	/* the pipe of the int in ep */
	unsigned int int_in_pipe;
	/* the interval of the int in ep */
	uint8_t int_in_interval;
	/* Response ready on EC side */
	bool resp_ready;
	/* EC has been registered */
	bool registered;
	/* EC is disconnected */
	bool disconnected;
	/* synchronize I/O with disconnect */
	struct mutex io_mutex;
	/* Work to handle EC events */
	struct work_struct work_ec_evt;
	/* Wait queue to signal the response is ready on EC side */
	wait_queue_head_t resp_ready_wait;
};

struct int_msg {
	uint8_t int_type;
} __packed;

struct registered_ec {
	struct list_head node;
	u16 idProduct;
	struct cros_ec_usb *ec_usb;
};

static LIST_HEAD(registered_list);
static DEFINE_MUTEX(registered_list_mutex);
static void cros_ec_int_callback(struct urb *urb);

static int expected_response_size(const struct ec_host_response *host_response)
{
	/* Check host request version */
	if (host_response->struct_version != 3)
		return 0;

	/* Reserved byte should be 0 */
	if (host_response->reserved)
		return 0;

	return sizeof(*host_response) + host_response->data_len;
}

static int cros_ec_usb_register(u16 idProduct, struct cros_ec_usb *ec_usb)
{
	struct registered_ec *ec;

	ec = kzalloc(sizeof(*ec), GFP_KERNEL);
	if (!ec)
		return -ENOMEM;

	ec->ec_usb = ec_usb;
	ec->idProduct = idProduct;
	mutex_lock(&registered_list_mutex);
	list_add(&ec->node, &registered_list);
	mutex_unlock(&registered_list_mutex);

	return 0;
}

static struct cros_ec_usb *cros_ec_usb_get_registered(u16 idProduct)
{
	struct registered_ec *ec;
	struct cros_ec_usb *ret = NULL;

	mutex_lock(&registered_list_mutex);
	list_for_each_entry(ec, &registered_list, node) {
		if (ec->idProduct == idProduct) {
			ret = ec->ec_usb;
			break;
		}
	}
	mutex_unlock(&registered_list_mutex);
	return ret;
}

static int submit_int_urb(struct cros_ec_device *ec_dev)
{
	struct cros_ec_usb *ec_usb = ec_dev->priv;
	struct usb_device *usb_dev = interface_to_usbdev(ec_usb->interface);
	int ret;

	/* Submit the INT URB. */
	usb_fill_int_urb(ec_usb->int_in_urb, usb_dev, ec_usb->int_in_pipe,
			 ec_usb->int_in_buffer, ec_usb->int_in_size,
			 cros_ec_int_callback, ec_usb, ec_usb->int_in_interval);
	ret = usb_submit_urb(ec_usb->int_in_urb, GFP_KERNEL);

	return ret;
}

static void cros_ec_int_callback(struct urb *urb)
{
	struct cros_ec_usb *ec_usb = urb->context;
	struct cros_ec_device *ec_dev = ec_usb->ec_dev;
	int ret;

	switch (urb->status) {
	case 0:
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* Expected errors. */
		return;
	default:
		dev_dbg(ec_dev->dev, "Unexpected int urb error: %d\n",
			urb->status);
		goto resubmit;
	}

	if (urb->actual_length >= sizeof(struct int_msg)) {
		struct int_msg *int_msg =
			(struct int_msg *)ec_usb->int_in_buffer;
		enum cros_ec_usb_int_type int_type =
			(enum cros_ec_usb_int_type)int_msg->int_type;
		switch (int_type) {
		case INT_TYPE_EVENT_OCCURED:
			if (ec_usb->registered) {
				ec_dev->last_event_time = cros_ec_get_time_ns();
				schedule_work(&ec_usb->work_ec_evt);
			}
			break;
		case INT_TYPE_RESPONSE_READY:
			ec_usb->resp_ready = true;
			wake_up(&ec_usb->resp_ready_wait);
			break;
		default:
			dev_err(ec_dev->dev, "Unrecognized event: %d\n",
				int_type);
		}
	} else {
		dev_err(ec_dev->dev, "Incorrect int transfer len: %d\n",
			urb->actual_length);
	}

resubmit:
	/* Resubmit the INT URB. */
	ret = submit_int_urb(ec_dev);
	if (ret)
		dev_err(ec_dev->dev, "Failed to resumbit int urb: %d", ret);
}

static int do_cros_ec_pkt_xfer_usb(struct cros_ec_device *ec_dev,
				   struct cros_ec_command *ec_msg)
{
	struct cros_ec_usb *ec_usb = ec_dev->priv;
	struct ec_host_response *host_response;
	int req_size, ret, actual_length, expected_resp_size, resp_size;
	const int header_size = sizeof(*host_response);
	const int max_resp_size = header_size + ec_msg->insize;
	const int bulk_in_size = umin(ec_usb->bulk_in_size, ec_dev->din_size);
	uint8_t sum = 0;

	mutex_lock(&ec_usb->io_mutex);
	if (ec_usb->disconnected) {
		mutex_unlock(&ec_usb->io_mutex);
		ret = -ENODEV;
		return ret;
	}

	if (max_resp_size > ec_dev->din_size) {
		dev_err(ec_dev->dev, "Potential response too big: %d\n", max_resp_size);
		ret = -EINVAL;
		goto exit;
	}

	req_size = cros_ec_prepare_tx(ec_dev, ec_msg);
	if (req_size < 0) {
		dev_err(ec_dev->dev, "Failed to prepare msg %d\n", req_size);
		ret = req_size;
		goto exit;
	}
	dev_dbg(ec_dev->dev, "Prepared len=%d\n", req_size);

	ec_usb->resp_ready = false;
	/*
	 * Buffers dout and din are allocated with devm_kzalloc which means it is suitable
	 * for DMA and we can use by usb functions.
	 */
	ret = usb_bulk_msg(ec_usb->udev, ec_usb->bulk_out_pipe, ec_dev->dout,
			   req_size, NULL, BULK_TRANSFER_TIMEOUT_MS);
	if (ret) {
		dev_err(ec_dev->dev, "Failed to send request: %d\n", ret);
		goto exit;
	}

	/*
	 * Wait till EC signals response ready event via INT endpoint,
	 * before polling a response with a bulk transfer.
	 */
	if (!wait_event_timeout(ec_usb->resp_ready_wait, ec_usb->resp_ready,
				msecs_to_jiffies(RESPONSE_TIMEOUT_MS))) {
		dev_err(ec_dev->dev, "Timed out waiting for response\n");
		ret = -ETIMEDOUT;
		goto exit;
	}

	/* Get first part of response that contains a header. */
	ret = usb_bulk_msg(ec_usb->udev, ec_usb->bulk_in_pipe, ec_dev->din,
			   bulk_in_size, &actual_length,
			   BULK_TRANSFER_TIMEOUT_MS);
	if (ret) {
		dev_err(ec_dev->dev, "Failed to get response: %d\n", ret);
		goto exit;
	}

	/* Verify number of received bytes. */
	if (actual_length < header_size) {
		dev_err(ec_dev->dev, "Received too little bytes: %d\n",
			actual_length);
		ret = -ENOSPC;
		goto exit;
	}
	expected_resp_size =
		expected_response_size((struct ec_host_response *)ec_dev->din);
	if ((expected_resp_size > max_resp_size) || (expected_resp_size == 0) ||
	    (actual_length > expected_resp_size)) {
		dev_err(ec_dev->dev, "Incorrect number of expected bytes: %d\n",
			expected_resp_size);
		ret = -ENOSPC;
		goto exit;
	}
	resp_size = actual_length;
	/* Get the rest of the response if needed. */
	if (resp_size < expected_resp_size) {
		ret = usb_bulk_msg(ec_usb->udev, ec_usb->bulk_in_pipe,
				   ec_dev->din + resp_size,
				   expected_resp_size - resp_size,
				   &actual_length, BULK_TRANSFER_TIMEOUT_MS);
		if (ret) {
			dev_err(ec_dev->dev,
				"Failed to get second part of response: %d\n",
				ret);
			goto exit;
		}
		resp_size += actual_length;
	}

	/* Check if number of received of bytes is correct. */
	if (resp_size != expected_resp_size) {
		dev_err(ec_dev->dev,
			"Received incorrect number of bytes: %d, expected: %d\n",
			resp_size, expected_resp_size);
		ret = -ENOSPC;
		goto exit;
	}

	/* Validate checksum */
	host_response = (struct ec_host_response *)ec_dev->din;
	for (int i = 0; i < sizeof(*host_response) + host_response->data_len;
	     i++) {
		sum += ec_dev->din[i];
	}
	if (sum) {
		dev_err(ec_dev->dev, "Bad packet checksum calculated %x\n",
			sum);
		ret = -EBADMSG;
		goto exit;
	}

	ec_msg->result = host_response->result;
	memcpy(ec_msg->data, ec_dev->din + sizeof(*host_response),
	       host_response->data_len);
	ret = host_response->data_len;

	if (ec_msg->command == EC_CMD_REBOOT_EC)
		msleep(EC_REBOOT_DELAY_MS);
exit:
	mutex_unlock(&ec_usb->io_mutex);
	if (ret < 0) {
		/* Try to reset EC in case of error to restore default state. */
		usb_reset_device(ec_usb->udev);
	}

	return ret;
}

/**
 * usb_evt_handler - USB to AP event handler
 * @work: Work struct
 */
static void usb_evt_handler(struct work_struct *work)
{
	struct cros_ec_usb *ec_usb =
		container_of(work, struct cros_ec_usb, work_ec_evt);

	cros_ec_irq_thread(0, ec_usb->ec_dev);
}

static void cros_ec_usb_delete(struct cros_ec_usb *ec_usb)
{
	usb_kill_urb(ec_usb->int_in_urb);
	cancel_work_sync(&ec_usb->work_ec_evt);

	usb_free_urb(ec_usb->int_in_urb);
	usb_put_intf(ec_usb->interface);
	usb_put_dev(ec_usb->udev);
	kfree(ec_usb->int_in_buffer);
	kfree(ec_usb->bulk_in_buffer);
}

static int cros_ec_usb_probe(struct usb_interface *intf,
			     const struct usb_device_id *id)
{
	struct usb_device *usb_dev = interface_to_usbdev(intf);
	struct usb_endpoint_descriptor *bulk_in, *bulk_out, *int_in;
	struct device *if_dev = &intf->dev;
	struct cros_ec_device *ec_dev;
	const u16 idProduct = usb_dev->descriptor.idProduct;
	struct cros_ec_usb *ec_usb = cros_ec_usb_get_registered(idProduct);
	const bool is_registered = ec_usb != NULL;
	int retval;

	/*
	 * Do not register the same EC device twice. The probing is performed every
	 * reboot, sysjump, crash etc. Recreating the /dev/cros_X file every time
	 * would force all application to reopen the file, which is not a case for
	 * other cros_ec_x divers. Instead, keep the cros_ec_device and cros_ec_usb
	 * structures constant and replace USB related structures for the same EC
	 * that is reprobed.
	 *
	 * The driver doesn't support handling two devices with the same idProduct,
	 * but it will never be a real usecase.
	 */
	if (!is_registered)
		ec_usb = kzalloc(sizeof(*ec_usb), GFP_KERNEL);

	if (!ec_usb)
		return -ENOMEM;

	if (!is_registered) {
		mutex_init(&ec_usb->io_mutex);
		ec_dev = kzalloc(sizeof(*ec_dev), GFP_KERNEL);
		if (!ec_dev) {
			retval = -ENOMEM;
			goto error;
		}
		ec_usb->ec_dev = ec_dev;
	} else {
		ec_dev = ec_usb->ec_dev;
	}

	ec_usb->udev = usb_get_dev(usb_dev);
	ec_usb->interface = usb_get_intf(intf);
	/* Use first bulk-in/out endpoints + int-in endpoint */
	retval = usb_find_common_endpoints(intf->cur_altsetting, &bulk_in,
					   &bulk_out, &int_in, NULL);
	if (retval) {
		dev_err(if_dev,
			"Could not find bulk-in, bulk-out or int-in endpoint\n");
		goto error;
	}
	/* Bulk endpoints have to be capable of sending headers in one transfer. */
	if ((usb_endpoint_maxp(bulk_out) < sizeof(struct ec_host_request)) ||
	    (usb_endpoint_maxp(bulk_in) < sizeof(struct ec_host_response)) ||
	    (usb_endpoint_maxp(int_in)) < sizeof(struct int_msg)) {
		retval = -ENOSPC;
		dev_err(if_dev, "Incorrect max packet size\n");
		goto error;
	}
	ec_usb->bulk_out_pipe =
		usb_sndbulkpipe(ec_usb->udev, bulk_out->bEndpointAddress);
	ec_usb->bulk_in_size = usb_endpoint_maxp(bulk_in);
	ec_usb->bulk_in_pipe =
		usb_rcvbulkpipe(ec_usb->udev, bulk_in->bEndpointAddress);
	ec_usb->bulk_in_buffer = kmalloc(ec_usb->bulk_in_size, GFP_KERNEL);
	if (!ec_usb->bulk_in_buffer) {
		dev_err(if_dev, "Failed to allocate bulk in buffer\n");
		retval = -ENOMEM;
		goto error;
	}
	ec_usb->int_in_size = usb_endpoint_maxp(int_in);
	ec_usb->int_in_pipe =
		usb_rcvintpipe(ec_usb->udev, int_in->bEndpointAddress);
	ec_usb->int_in_interval = int_in->bInterval;
	ec_usb->int_in_buffer = kmalloc(ec_usb->int_in_size, GFP_KERNEL);
	if (!ec_usb->int_in_buffer) {
		dev_err(if_dev, "Failed to allocate int in buffer\n");
		retval = -ENOMEM;
		goto error;
	}
	ec_usb->int_in_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!ec_usb->int_in_urb) {
		dev_err(if_dev, "Failed to allocate int in urb\n");
		retval = -ENOMEM;
		goto error;
	}

	ec_dev->dev = if_dev;
	ec_dev->phys_name = dev_name(if_dev);
	if (!is_registered) {
		ec_dev->priv = ec_usb;
		/* EC uses int endpoint to signal events. */
		ec_dev->irq = 0;
		ec_dev->cmd_xfer = NULL;
		ec_dev->pkt_xfer = do_cros_ec_pkt_xfer_usb;
		ec_dev->din_size = sizeof(struct ec_host_response) +
				sizeof(struct ec_response_get_protocol_info);
		ec_dev->dout_size = sizeof(struct ec_host_request) +
				sizeof(struct ec_params_rwsig_action);
		INIT_WORK(&ec_usb->work_ec_evt, usb_evt_handler);
		init_waitqueue_head(&ec_usb->resp_ready_wait);
	} else {
		/*
		 * We need to allocate dout and din buffers, because cros_ec_register
		 * won't be called. These buffers were freed once previous usb device was
		 * disconnected. Use buffer sizes from the last query.
		 * The EC_HOST_EVENT_INTERFACE_READY event will be triggered at the end
		 * of a boot, which calls cros_ec_query_all function, that reallocates
		 * buffers.
		 */
		ec_dev->din = devm_kzalloc(ec_dev->dev, ec_dev->din_size, GFP_KERNEL);
		if (!ec_dev->din) {
			retval = -ENOMEM;
			dev_err(if_dev, "Failed to allocate din buffer\n");
			goto error;
		}
		ec_dev->dout = devm_kzalloc(ec_dev->dev, ec_dev->dout_size, GFP_KERNEL);
		if (!ec_dev->dout) {
			retval = -ENOMEM;
			dev_err(if_dev, "Failed to allocate dout buffer\n");
			goto error;
		}
	}

	/* Needed by ec register function */
	usb_set_intfdata(intf, ec_dev);

	mutex_lock(&ec_usb->io_mutex);
	ec_usb->disconnected = false;
	mutex_unlock(&ec_usb->io_mutex);

	/* Use URB for the int endpoint. */
	retval = submit_int_urb(ec_dev);
	if (retval) {
		dev_err(if_dev, "Failed to sumbit int urb: %d\n", retval);
		goto error;
	}

	if (!is_registered) {
		retval = cros_ec_register(ec_dev);
		if (retval) {
			dev_err(if_dev, "Cannot register EC\n");
			goto error;
		}
		retval = cros_ec_usb_register(idProduct, ec_usb);
		if (retval) {
			cros_ec_unregister(ec_dev);
			goto error;
		}
		ec_usb->registered = true;
	}

	/* Handle potential events that haven't been handled before registration */
	schedule_work(&ec_usb->work_ec_evt);

	/*
	 * Allows EC to do remote wake-up -
	 * host sends SET_FEATURE(remote wake-up) before suspend.
	 */
	device_init_wakeup(&usb_dev->dev, true);

	return 0;
error:
	/* Free allocated memory */
	cros_ec_usb_delete(ec_usb);

	return retval;
}

static void cros_ec_usb_disconnect(struct usb_interface *intf)
{
	struct cros_ec_device *ec_dev = usb_get_intfdata(intf);
	struct cros_ec_usb *ec_usb = ec_dev->priv;

	/* prevent more I/O from starting */
	mutex_lock(&ec_usb->io_mutex);
	ec_usb->disconnected = true;
	mutex_unlock(&ec_usb->io_mutex);

	cros_ec_usb_delete(ec_usb);

	dev_info(&intf->dev, "Disconnected\n");
}

static int cros_ec_usb_suspend(struct usb_interface *intf, pm_message_t message)
{
	return 0;
}

static int cros_ec_usb_resume(struct usb_interface *intf)
{
	struct cros_ec_device *ec_dev = usb_get_intfdata(intf);
	int err;

	/* URB is killed during suspend. */
	err = submit_int_urb(ec_dev);
	if (err) {
		dev_err(ec_dev->dev,
			"Failed to sumbit int urb after resume: %d\n", err);
	}

	return 0;
}

static int cros_ec_usb_pre_reset(struct usb_interface *intf)
{
	struct cros_ec_device *ec_dev = usb_get_intfdata(intf);
	struct cros_ec_usb *ec_usb = ec_dev->priv;

	/* Do not start any new operations. */
	mutex_lock(&ec_usb->io_mutex);

	usb_kill_urb(ec_usb->int_in_urb);

	return 0;
}

static int cros_ec_usb_post_reset(struct usb_interface *intf)
{
	struct cros_ec_device *ec_dev = usb_get_intfdata(intf);
	struct cros_ec_usb *ec_usb = ec_dev->priv;
	int err;

	err = submit_int_urb(ec_dev);
	if (err) {
		dev_err(ec_dev->dev,
			"Failed to sumbit int urb after reset: %d\n", err);
	}
	mutex_unlock(&ec_usb->io_mutex);

	return 0;
}

static struct usb_driver cros_ec_usb = {
	.name = "cros-ec-usb",
	.probe = cros_ec_usb_probe,
	.disconnect = cros_ec_usb_disconnect,
	.suspend = cros_ec_usb_suspend,
	.resume = cros_ec_usb_resume,
	.pre_reset = cros_ec_usb_pre_reset,
	.post_reset = cros_ec_usb_post_reset,
	.id_table = cros_ec_usb_table,
	/* Do not autosuspend EC */
	.supports_autosuspend = 0,
};
module_usb_driver(cros_ec_usb);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ChromeOS EC USB HC driver");

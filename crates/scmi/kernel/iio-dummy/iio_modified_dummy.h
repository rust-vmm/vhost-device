/* SPDX-License-Identifier: GPL-2.0-only */
/**
 * Copyright (c) 2011 Jonathan Cameron
 *
 * Join together the various functionality of iio_modified_dummy driver
 *
 * Changes by Milan Zamazal <mzamazal@redhat.com> 2023, for testing
 * with vhost-device-scmi:
 *
 * - Dropped conditional parts.
 * - Use 3 axes in the accelerometer device.
 */

#ifndef _IIO_MODIFIED_DUMMY_H_
#define _IIO_MODIFIED_DUMMY_H_
#include <linux/kernel.h>

struct iio_dummy_accel_calibscale;
struct iio_dummy_regs;

/**
 * struct iio_dummy_state - device instance specific state.
 * @dac_val:			cache for dac value
 * @single_ended_adc_val:	cache for single ended adc value
 * @differential_adc_val:	cache for differential adc value
 * @accel_val:			cache for acceleration value
 * @accel_calibbias:		cache for acceleration calibbias
 * @accel_calibscale:		cache for acceleration calibscale
 * @lock:			lock to ensure state is consistent
 * @event_irq:			irq number for event line (faked)
 * @event_val:			cache for event threshold value
 * @event_en:			cache of whether event is enabled
 */
struct iio_dummy_state {
	int dac_val;
	int single_ended_adc_val;
	int differential_adc_val[2];
	int accel_val[3];
	int accel_calibbias;
	int activity_running;
	int activity_walking;
	const struct iio_dummy_accel_calibscale *accel_calibscale;
	struct mutex lock;
	struct iio_dummy_regs *regs;
	int steps_enabled;
	int steps;
	int height;
};

/**
 * enum iio_modified_dummy_scan_elements - scan index enum
 * @DUMMY_INDEX_VOLTAGE_0:         the single ended voltage channel
 * @DUMMY_INDEX_DIFFVOLTAGE_1M2:   first differential channel
 * @DUMMY_INDEX_DIFFVOLTAGE_3M4:   second differential channel
 * @DUMMY_INDEX_ACCELX:            acceleration channel
 *
 * Enum provides convenient numbering for the scan index.
 */
enum iio_modified_dummy_scan_elements {
	DUMMY_INDEX_VOLTAGE_0,
	DUMMY_INDEX_DIFFVOLTAGE_1M2,
	DUMMY_INDEX_DIFFVOLTAGE_3M4,
	DUMMY_INDEX_ACCEL_X,
	DUMMY_INDEX_ACCEL_Y,
	DUMMY_INDEX_ACCEL_Z,
};

#endif /* _IIO_MODIFIED_DUMMY_H_ */

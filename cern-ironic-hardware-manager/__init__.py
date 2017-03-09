import time
from ironic_python_agent import errors, hardware
from oslo_log import log

LOG = log.getLogger()


class CernHardwareManager(hardware.GenericHardwareManager):
    # Overrides superclass's name (generic_hardware_manager).
    HARDWARE_MANAGER_NAME = 'cern_hardware_manager'
    # This should be incremented at every upgrade to avoid making the agent
    # change which hardware manager it uses when cleaning in the middle of a
    # hardware manager upgrade.
    HARDWARE_MANAGER_VERSION = '1'

    def evaluate_hardware_support(self):
        """Declare level of hardware support provided.

        Since this example covers a case of supporting a specific device,
        this method is where you would do anything needed to initalize that
        device, including loading drivers, and then detect if one exists.

        In some cases, if you expect the hardware to be available on any node
        running this hardware manager, or it's undetectable, you may want to
        return a static value here.

        Be aware all managers' loaded in IPA will run this method before IPA
        performs a lookup or begins heartbeating, so the time needed to
        execute this method will make cleaning and deploying slower.

        :returns: HardwareSupport level for this manager.
        """
        self._initialize_hardware()
        if self._detect_hardware():
            # This actually resolves down to an int. Upstream IPA will never
            # return a value higher than 2 (HardwareSupport.MAINLINE). This
            # means your managers should always be SERVICE_PROVIDER or higher.
            LOG.debug('Found example device, returning SERVICE_PROVIDER')
            return hardware.HardwareSupport.SERVICE_PROVIDER
        else:
            # If the hardware isn't supported, return HardwareSupport.NONE (0)
            # in order to prevent IPA from loading its clean steps or
            # attempting to use any methods inside it.
            LOG.debug('No example devices found, returning NONE')
            return hardware.HardwareSupport.NONE

    def _initialize_hardware(self):
        """Example method for initalizing hardware."""
        # Perform any operations here that are required to initialize your
        # hardware.
        LOG.debug('Loading drivers, settling udevs, and generally initalizing')
        pass

    def _detect_hardware(self):
        """Example method for hardware detection."""
        # For this example, return true if hardware is detected, false if not
        LOG.debug('Looking for example device')
        return True

    def get_clean_steps(self, node, ports):
        """Get a list of clean steps with priority.

        Define any clean steps added by this manager here. These will be mixed
        with other loaded managers that support this hardware, and ordered by
        priority. Higher priority steps run earlier.

        Note that out-of-band clean steps may also be provided by Ironic.
        These will follow the same priority ordering even though they are not
        executed by IPA.

        There is *no guarantee whatsoever* that steps defined here will be
        executed by this HardwareManager. When it comes time to run these
        steps, they'll be called using dispatch_to_managers() just like any
        other IPA HardwareManager method. This means if they are unique to
        your hardware, they should be uniquely named. For example,
        upgrade_firmware would be a bad step name. Whereas
        upgrade_foobar_device_firmware would be better.

        :param node: The node object as provided by Ironic.
        :param ports: Port objects as provided by Ironic.
        :returns: A list of cleaning steps, as a list of dicts.
        """
        # While obviously you could actively run code here, generally this
        # should just return a static value, as any initialization and
        # detection should've been done in evaluate_hardware_support().
        return [
            {
                'step': 'upgrade_example_device_model1234_firmware',
                'priority': 37,
                # If you need Ironic to coordinate a reboot after this step
                # runs, but before continuing cleaning, this should be true.
                'reboot_requested': True,
                # If it's safe for Ironic to abort cleaning while this step
                # runs, this should be true.
                'abortable': False
            },
            {
                'step': 'companyx_verify_device_lifecycle',
                'priority': 472,
                # If you need Ironic to coordinate a reboot after this step
                # runs, but before continuing cleaning, this should be true.
                'reboot_requested': False,
                # If it's safe for Ironic to abort cleaning while this step
                # runs, this should be true.
                'abortable': True
            }
        ]

    def upgrade_example_device_model1234_firmware(self, node, ports):
        """Upgrade firmware on Example Device Model #1234."""
        # Any commands needed to perform the firmware upgrade should go here.
        # If you plan on actually flashing firmware every cleaning cycle, you
        # should ensure your device will not experience flash exhaustion. A
        # good practice in some environments would be to check the firmware
        # version against a constant in the code, and noop the method if an
        # upgrade is not needed.
        if self._is_latest_firmware():
            LOG.debug('Latest firmware already flashed, skipping')
            # Return values are ignored here on success
            return True
        else:
            LOG.debug('Firmware version X found, upgrading to Y')
            # Perform firmware upgrade.
            try:
                self._upgrade_firmware()
            except Exception as e:
                # Log and pass through the exception so cleaning will fail
                LOG.exception(e)
                raise
            return True

    def _is_latest_firmware(self):
        """Detect if device is running latest firmware."""
        # Actually detect the firmware version instead of returning here.
        return True

    def _upgrade_firmware(self):
        """Upgrade firmware on device."""
        # Actually perform firmware upgrade instead of returning here.
        return True

    def companyx_verify_device_lifecycle(self, node, ports):
        """Verify node is not beyond useful life of 3 years."""
        # Other examples of interesting cleaning steps for this kind of hardware
        # manager would include verifying node.properties matches current state of
        # the node, checking smart stats to ensure the disk is not soon to fail,
        # or enforcing security policies.
        create_date = node.get('created_at')
        if create_date is not None:
            server_age = time.time() - time.mktime(time.strptime(create_date))
            if server_age > (60 * 60 * 24 * 365 * 3):
                raise errors.CleaningError(
                        'Server is too old to pass cleaning!')
            else:
                LOG.info('Node is %s seconds old, younger than 3 years, '
                         'cleaning passes.', server_age)

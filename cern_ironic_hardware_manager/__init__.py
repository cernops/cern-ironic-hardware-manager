import time
import urllib2

from ironic_python_agent import errors, hardware, utils
from oslo_log import log

LOG = log.getLogger()


class CernHardwareManager(hardware.GenericHardwareManager):
    HARDWARE_MANAGER_NAME = 'cern_hardware_manager'
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
        super(CernHardwareManager, self).evaluate_hardware_support()

        aims_deregistration = urllib2.urlopen("http://linuxsoft.cern.ch/aims2server/aims2reboot.cgi").read()
        LOG.info(aims_deregistration)

        return hardware.HardwareSupport.SERVICE_PROVIDER

    def list_hardware_info(self):
        """Return full hardware inventory as a serializable dict.

        This inventory is sent to Ironic on lookup and to Inspector on
        inspection.

        :return: a dictionary representing inventory
        """
        return super(CernHardwareManager, self).list_hardware_info()

    def get_clean_steps(self, node, ports):
        """Return the clean steps supported by this hardware manager.

        This method returns the clean steps that are supported by
        proliant hardware manager.  This method is invoked on every
        hardware manager by Ironic Python Agent to give this information
        back to Ironic.

        :param node: A dictionary of the node object
        :param ports: A list of dictionaries containing information of ports
            for the node
        :returns: A list of dictionaries, each item containing the step name,
            interface and priority for the clean step.
        """

        return [
            {
                'step': 'upgrade_example_device_model1234_firmware',
                'priority': 0,
                'interface': 'deploy',
                'reboot_requested': False,
                'abortable': False
            },
            {
                'step': 'erase_devices',
                'priority': 0,
                'interface': 'deploy',
                'reboot_requested': False,
                'abortable': True
            },
            {
                'step': 'erase_devices_metadata',
                'priority': 0,
                'interface': 'deploy',
                'reboot_requested': False,
                'abortable': True
            },
            {
                'step': 'check_ipmi_users',
                'priority': 0,
                'interface': 'management',
                'reboot_requested': False,
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

        def _is_latest_firmware():
            """Detect if device is running latest firmware."""
            # Actually detect the firmware version instead of returning here.
            create_date = node.get('created_at')
            return True

        def _upgrade_firmware():
            """Upgrade firmware on device."""
            # Actually perform firmware upgrade instead of returning here.
            return True

        if _is_latest_firmware():
            LOG.debug('Latest firmware already flashed, skipping')
            # Return values are ignored here on success
            return True
        else:
            LOG.debug('Firmware version X found, upgrading to Y')
            # Perform firmware upgrade.
            try:
                _upgrade_firmware()
            except Exception as e:
                # Log and pass through the exception so cleaning will fail
                LOG.exception(e)
                raise
            return True

    def erase_devices(self, node, ports):
        """Erase any device that holds user data.

        This method in its current state will erase all block devices using
        either ATA Secure Erase or shred, depending on the system capabilities.
        """
        super(CernHardwareManager, self).erase_devices(node, ports)
        return True

    def erase_devices_metadata(self, node, ports):
        """Attempt to erase the disk devices metadata."""
        super(CernHardwareManager, self).erase_devices_metadata(node, ports)

    def check_ipmi_users(self, node, ports):
        return True

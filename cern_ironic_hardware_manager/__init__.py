import os
import urllib2
import socket
import time

from ironic_python_agent import hardware
from oslo_log import log

import cern_ironic_hardware_manager.cleaning
import cern_ironic_hardware_manager.inspection

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

        # Get IPv4 address of linuxsoft in order to send AIMS deregistration
        # request using IPv4, not IPv6 (as the support of the latter is broken
        # in CERN network infra)

        os.system("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        os.system("sysctl -w net.ipv6.conf.default.disable_ipv6=1")

        # As AIMS server checks revDNS of the caller, we need to wait here
        # in case we had an user who requested cern-services=False.
        # Otherwise AIMS fails to deregister and we have an endless loop to
        # boot into deploy image

        host = socket.gethostbyname('linuxsoft.cern.ch')
        aims_url = "http://{}/aims2server/aims2reboot.cgi".format(host)

        for attempt in range(0, 12):
            aims_deregistration = urllib2.urlopen(aims_url).read()
            if "installed by AIMS2 at" in aims_deregistration:
                # All good, machine deregistered
                LOG.info(aims_deregistration)
                break
            elif "is not registered with aims2" in aims_deregistration:
                # revDNS not recognized by AIMS, please wait and retry
                LOG.warning(aims_deregistration)
                time.sleep(60)
                continue
            else:
                # Something unexpected happened
                LOG.error(aims_deregistration)
                raise Exception("AIMS deregistration failed")
        else:
            raise Exception("AIMS deregistration timed out")

        return hardware.HardwareSupport.SERVICE_PROVIDER

    def list_hardware_info(self):
        """Return full hardware inventory as a serializable dict.

        This inventory is sent to Ironic on lookup and to Inspector on
        inspection.

        :returns: A dictionary representing inventory
        """
        hardware_info = super(CernHardwareManager, self).list_hardware_info()
        hardware_info = self.propagate_custom_properties(hardware_info)

        return hardware_info

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
                'interface': 'deploy'
            },
            {
                'step': 'erase_devices',
                # This step is disabled as "shred" takes a lot of time ...
                'priority': 0,
                'interface': 'deploy'
            },
            {
                'step': 'erase_devices_metadata',
                'priority': 80,
                'interface': 'deploy'
            },
            {
                'step': 'check_ipmi_users',
                'priority': 0,
                'interface': 'deploy'
            },
            {
                'step': 'delete_configuration',
                'priority': 21,
                'interface': 'deploy'
            },
            {
                'step': 'create_configuration',
                'priority': 20,
                'interface': 'deploy'
            }
        ]

    def erase_devices(self, node, ports):
        """Erase any device that holds user data.

        This method in its current state will erase all block devices using
        either ATA Secure Erase or shred, depending on the system capabilities.
        """
        super(CernHardwareManager, self).erase_devices(node, ports)

    def erase_devices_metadata(self, node, ports):
        """Attempt to erase the disk devices metadata."""
        super(CernHardwareManager, self).erase_devices_metadata(node, ports)

    upgrade_example_device_model1234_firmware = cern_ironic_hardware_manager.cleaning.upgrade_example_device_model1234_firmware
    get_infiniband_adapters = cern_ironic_hardware_manager.inspection.get_infiniband_adapters
    get_disk_enclosures = cern_ironic_hardware_manager.inspection.get_disk_enclosures
    propagate_custom_properties = cern_ironic_hardware_manager.inspection.propagate_custom_properties

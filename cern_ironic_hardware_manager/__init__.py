import urllib2

from ironic_python_agent import errors, hardware, utils
from oslo_concurrency import processutils
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

        :returns: A dictionary representing inventory
        """
        hardware_info = super(CernHardwareManager, self).list_hardware_info()
        hardware_info['disk_enclosures'] = self.get_disk_enclosures()

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
            node.get('created_at')
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

    def erase_devices_metadata(self, node, ports):
        """Attempt to erase the disk devices metadata."""
        super(CernHardwareManager, self).erase_devices_metadata(node, ports)

    def create_configuration(self, node, ports):
        """Create RAID configuration on the bare metal.

        This method creates the desired RAID configuration as read from
        node['target_raid_config'].

        :param node: A dictionary of the node object
        :param ports: A list of dictionaries containing information of ports
                      for the node
        :returns: The current RAID configuration of the below format.
                  raid_config = {
                    'logical_disks': [{
                      'raid_level': 1,
                      'size_gb': 'MAX'
                      }
                    ]
                  }
        """
        raid_config = node.get('target_raid_config', {})

        # In case no config provided, leave the node unconfigured
        if raid_config == {}:
            return {}

        if not self.validate_configuration(raid_config):
            raise Exception("RAID configuration is incorrect")

        local_drives, _ = utils.execute("cat /proc/partitions | grep -e sd[a-z]$ | awk '{ print $4 }'", shell=True)
        local_drives = local_drives.split()

        # Check if there are any partitions created directly on sd*. In case
        # any is detected, abort for manual intervention
        local_partitions, _ = utils.execute("cat /proc/partitions | grep -e sd[a-z][0-9] | awk '{ print $4 }'", shell=True)
        if local_partitions.strip() not in ("", " "):
            raise Exception("Partitions {} detected. Aborting".format(
                local_partitions.strip()))

        for logical_disk in raid_config['logical_disks']:
            # At this moment we assume there will be only one iteration here.

            out, err = utils.execute("mdadm --create /dev/md0 --level={} --raid-devices={} {} --force".format(
                logical_disk['raid_level'], len(local_drives), ' '.join(
                    ["/dev/" + elem for elem in local_drives])), shell=True)

            LOG.warning("Debug create stdout: {}".format(out))
            LOG.warning("Debug create stderr: {}".format(err))

        return {'logical_disks':
                [{'raid_level': raid_config['logical_disks'][0]['raid_level'],
                  'size_gb': 'MAX'}]
                }

    def validate_configuration(self, raid_config):
        LOG.info("Target RAID config: {}".format(raid_config))

        if len(raid_config.get('logical_disks')) != 1:
            return False

        if raid_config['logical_disks'][0]['size_gb'] != "MAX":
            return False

        accepted_levels = ["0", "1", "10"]
        if raid_config['logical_disks'][0]['raid_level'] not in accepted_levels:
            return False

        return True

    def delete_configuration(self, node, ports):
        """Deletes RAID configuration on the bare metal.

        This method deletes all the RAID disks on the bare metal.

        :param node: A dictionary of the node object
        :param ports: A list of dictionaries containing information of ports
                      for the node
        """
        raid_devices, _ = utils.execute("cat /proc/mdstat | grep 'active raid' | awk '{ print $1 }'", shell=True)

        for device in ['/dev/' + x for x in raid_devices.split()]:
            try:
                component_devices, err = utils.execute("mdadm --detail {} | grep 'active sync' | awk '{{ print $7 }}'".format(device), shell=True)
                LOG.info("Component devices for {}: {}".format(device, component_devices))

                if err:
                    raise processutils.ProcessExecutionError(err)
            except (processutils.ProcessExecutionError, OSError) as e:
                raise errors.CleaningError("Error getting details of RAID device {}. {}".format(device, e))

            try:
                # Positive output of the following goes into stderr, thus
                # we don't want to check its content
                utils.execute("mdadm --stop {}".format(device), shell=True)

            except (processutils.ProcessExecutionError, OSError) as e:
                raise errors.CleaningError("Error stopping RAID device {}. {}".format(device, e))

            try:
                utils.execute("mdadm --remove {}".format(device), shell=True)
            except:
                # After successful stop this returns
                # "mdadm: error opening /dev/md3: No such file or directory"
                # with error code 1, which we can safely ignore
                pass

            for device in component_devices.split():
                try:
                    _, err = utils.execute("mdadm --E {}".format(device), shell=True)
                    if "No md superblock detected" in err:
                        continue

                    _, err = utils.execute("mdadm --zero-superblock {}".format(device), shell=True)
                    if err:
                        raise processutils.ProcessExecutionError(err)
                except (processutils.ProcessExecutionError, OSError) as e:
                    raise errors.CleaningError("Error erasing superblock for device {}. {}".format(device, e))

    def check_ipmi_users(self, node, ports):
        """Check users having IPMI access with admin rights

        In CERN environment there should be only 2 users having admin access
        to the IPMI interface. One of them is node.driver_info["ipmi_username"]
        and the other is admin/root.

        As the superadmin's username is not known beforehand, if we detect >2
        users, cleaning should fail. In future we may want to implement logic
        to automatically delete any unnecessary user from IPMI.
        """
        for channel in range(16):
            # Count number of enabled admin users
            out, e = utils.execute(
                "ipmitool user list {0!s} | awk '{{if ($3 == \"true\" && $6 == \"ADMINISTRATOR\") print $0;}}' | wc -l".format(channel + 1), shell=True)
            if int(out) != 1:
                raise errors.CleaningError("Detected {} admin users for IPMI !".format(out))

            # In case there is only 1 ipmi user, check if name matches the one
            # known by Ironic
            out, e = utils.execute(
                "ipmitool user list {0!s} | awk '{{if ($3 == \"true\" && $6 == \"ADMINISTRATOR\") print $2;}}' | wc -l".format(channel + 1), shell=True)
            if out != node.get('driver_info')['ipmi_username']:
                raise errors.CleaningError("Detected illegal admin user \"{}\" for IPMI !".format(out))

            # The following error message indicates we started querying
            # non existing channel
            if "Get User Access command failed" in e:
                break

    def get_disk_enclosures(self):
        """Detect number of external drive enclosures

        Used by list_hardware_info to populate node's properties with a number
        of external arrays connected to the device. Please note this assumes
        all the drivers required to detect the array have been loaded
        beforehand.

        :returns: A number of external arrays
        """
        # TODO(makowals): Check if the drivers are loaded before doing lsscsi;
        # we should compile a list of potentials modules we want to have
        # and then use utils.try_execute('modprobe', 'xyz')

        out, e = utils.execute("lsscsi | grep enclosu | wc -l", shell=True)
        return int(out)

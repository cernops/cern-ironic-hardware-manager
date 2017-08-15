import os
import urllib2
import socket
import time
import pyudev
import shlex

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
        LOG.info("evaluate_hardware_support ()")

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
        hardware_info['disk_enclosures'] = self.get_disk_enclosures()
        hardware_info['infiniband_adapters'] = self.get_infiniband_adapters()

        hardware_info['boot_mode'] = 'bios'
        hardware_info['disk_label'] = 'gpt'

        # (makowals) Each value is stored in a separate key as ironic driver prefers to have capabilities
        # without nested jsons, i.e. in a form of key:val
        hardware_info['cpu_name'], hardware_info['cpu_family'], hardware_info['cpu_model'], hardware_info['cpu_stepping'] = self.get_cpu()

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
                'step': 'delete_configuration',
                'priority': 30,
                'interface': 'deploy'
            },
            {
                'step': 'erase_devices_metadata',
                # NOTE(arne): Needs lower priority than delete_configuration
                # so that a RAID can be stopped and cleaned before the RAID
                # metadata is wiped of the the RAID members.
                'priority': 20,
                'interface': 'deploy'
            },
            {
                'step': 'create_configuration',
                'priority': 10,
                'interface': 'deploy'
            },
            {
                'step': 'wait_a_minute',
                'priority': 1,
                'interface': 'deploy'
            },
            {
                'step': 'erase_devices',
                # NOTE(arne): Disabled for now: "shred" takes too long.
                'priority': 0,
                'interface': 'deploy'
            },
            {
                'step': 'check_ipmi_users',
                # NOTE(arne): Disabled for now: needs discussion and sync
                # with procurement team.
                'priority': 0,
                'interface': 'deploy'
            },
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

        # Create two partitions on each local drive:
        #   - p1 for the image (in particular /boot and /)
        #   - p2 for the desired RAID configuration
        LOG.info("create partitions")
        for local_drive in local_drives:
            utils.execute("parted /dev/{} -s -- mklabel msdos".format(local_drive), shell=True)
            utils.execute("parted /dev/{} -s -a optimal -- mkpart primary 2048s 16384".format(local_drive), shell=True)
            utils.execute("parted /dev/{} -s -a optimal -- mkpart primary 16384 -1".format(local_drive), shell=True)

        # Create the RAID-1 for the image
        LOG.info("create RAID-1")
        out, err = utils.execute("mdadm --create /dev/md0 --level=1 --raid-devices={} {} --force --metadata=1.0".format(
            len(local_drives), ' '.join(
                ["/dev/" + elem + "1" for elem in local_drives])), shell=True)

        # Create the RAID-X according to the desired configuration
        LOG.info("create RAID-X")
        for logical_disk in raid_config['logical_disks']:
            out, err = utils.execute("mdadm --create /dev/md1 --level={} --raid-devices={} {} --force --metadata=1.0".format(
                logical_disk['raid_level'], len(local_drives), ' '.join(
                    ["/dev/" + elem + "2" for elem in local_drives])), shell=True)

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

        # accepted_levels = ["0", "1", "10"]
        accepted_levels = ["0", "1"]
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
        LOG.info("Deleting RAID configurations")

        raid_devices, _ = utils.execute("cat /proc/mdstat | grep 'active' | awk '{ print $1 }'", shell=True)

        for device in ['/dev/' + x for x in raid_devices.split()]:
            LOG.info("Deleting RAID configuration for device {}".format(device))
            try:
                component_devices, err = utils.execute("mdadm --detail {} | grep 'active sync' | awk '{{ print $7 }}'".format(device), shell=True)
                LOG.info("Component devices for {}: {}".format(device, component_devices))

                if err:
                    raise processutils.ProcessExecutionError(err)
            except (processutils.ProcessExecutionError, OSError) as e:
                raise errors.CleaningError("Error getting details of RAID device {}. {}".format(device, e))

            # Wipe partition tables from the RAID device. Needed before
            # creating a new md device.
            try:
                LOG.info("Wiping device {}".format(device))
                utils.execute("wipefs -af {}".format(device), shell=True)
            except (processutils.ProcessExecutionError, OSError) as e:
                raise errors.CleaningError("Error wiping RAID device {}. {}".format(device, e))

            try:
                LOG.info("Stopping device {}".format(device))
                utils.execute("mdadm --stop {}".format(device), shell=True)
            except (processutils.ProcessExecutionError, OSError) as e:
                raise errors.CleaningError("Error stopping RAID device {}. {}".format(device, e))

            try:
                LOG.info("Removing device {}".format(device))
                utils.execute("mdadm --remove {}".format(device), shell=True)
            except processutils.ProcessExecutionError:
                # After successful stop this returns
                # "mdadm: error opening /dev/md3: No such file or directory"
                # with error code 1, which we can safely ignore
                pass
            LOG.info("Removed RAID device {}".format(device))

            for component_device in component_devices.split():
                try:
                    _, err = utils.execute("mdadm --examine {}".format(component_device), shell=True)
                    if "No md superblock detected" in err:
                        continue

                    _, err = utils.execute("mdadm --zero-superblock {}".format(component_device), shell=True)
                    if err:
                        raise processutils.ProcessExecutionError(err)
                except (processutils.ProcessExecutionError, OSError) as e:
                    raise errors.CleaningError("Error erasing superblock for device {}. {}".format(component_device, e))
                LOG.info("Deleted md superblock on {}".format(component_device))

            LOG.info("Removed RAID configuration of {}".format(device))

        LOG.info("Finished deleting RAID configurations")

    def wait_a_minute(self, node, ports):
        """Holds the IPA for a minute after automatic cleaning to inspect logs.

        :param node: A dictionary of the node object
        :param ports: A list of dictionaries containing information of ports
                      for the node
        """
        LOG.warning("Waiting 60 seconds for log inspection ....")
        time.sleep(60)

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

    def get_infiniband_adapters(self):
        """Detect number of infiniband network adapters

        Used by list_hardware_info to populate node's properties with a number
        of infiniband adapters connected to the device. Please note this
        assumes all the drivers required to detect the device have been loaded
        beforehand.

        :returns: A number of infiniband network adapters
        """

        out, e = utils.execute("ibv_devinfo | awk '/transport[[:space:]]*:/ {{print $2}}' | grep InfiniBand | wc -l", shell=True)
        return int(out)

    def get_cpu(self):
        result = {}

        result['cpu_name'], e = utils.execute("lscpu | awk '/Model name[[:space:]]*:/ {{$1=$2=\"\"; print $0}}'", shell=True)
        result['cpu_family'], e = utils.execute("lscpu | awk '/CPU family[[:space:]]*:/ {{print $3}}'", shell=True)
        result['cpu_model'], e = utils.execute("lscpu | awk '/Model[[:space:]]*:/ {{print $2}}'", shell=True)
        result['cpu_stepping'], e = utils.execute("lscpu | awk '/Stepping[[:space:]]*:/ {{print $2}}'", shell=True)

        result = {k: v.strip() for k, v in result.items()}

        return result['cpu_name'], result['cpu_family'], result['cpu_model'], result['cpu_stepping']

    def list_block_devices(self):
        return list_all_block_devices()


def list_all_block_devices(block_type='disk',
                           ignore_raid=False):
    """List all physical block devices

    The switches we use for lsblk: P for KEY="value" output, b for size output
    in bytes, i to ensure ascii characters only, and o to specify the
    fields/columns we need.

    Broken out as its own function to facilitate custom hardware managers that
    don't need to subclass GenericHardwareManager.

    :param block_type: Type of block device to find
    :param ignore_raid: Ignore auto-identified raid devices, example: md0
                        Defaults to false as these are generally disk
                        devices and should be treated as such if encountered.
    :return: A list of BlockDevices
    """
    hardware._udev_settle()

    # map device names to /dev/disk/by-path symbolic links that points to it

    by_path_mapping = {}

    disk_by_path_dir = '/dev/disk/by-path'

    try:
        paths = os.listdir(disk_by_path_dir)

        for path in paths:
            path = os.path.join(disk_by_path_dir, path)
            # Turn possibly relative symbolic link into absolute
            devname = os.path.join(disk_by_path_dir, os.readlink(path))
            devname = os.path.abspath(devname)
            by_path_mapping[devname] = path

    except OSError as e:
        # NOTE(TheJulia): This is for multipath detection, and will raise
        # some warning logs with unrelated tests.
        LOG.warning("Path %(path)s is inaccessible, /dev/disk/by-path/* "
                    "version of block device name is unavailable "
                    "Cause: %(error)s", {'path': disk_by_path_dir, 'error': e})

    columns = ['KNAME', 'MODEL', 'SIZE', 'ROTA', 'TYPE']
    report = utils.execute('lsblk', '-Pbi', '-o{}'.format(','.join(columns)),
                           check_exit_code=[0])[0]
    # lines = report.split('\n')
    lines = report.splitlines()
    lines = list(set(lines))
    context = pyudev.Context()

    LOG.debug("list_block_devices(): found {}".format(lines))

    devices = []
    for line in lines:
        device = {}
        # Split into KEY=VAL pairs
        vals = shlex.split(line)
        for key, val in (v.split('=', 1) for v in vals):
            device[key] = val.strip()
        # Ignore block types not specified
        devtype = device.get('TYPE')
        # Search for raid in the reply type, as RAID is a
        # disk device, and we should honor it if is present.
        # Other possible type values, which we skip recording:
        #   lvm, part, rom, loop
        if devtype != block_type:
            if devtype is not None and 'raid' in devtype and not ignore_raid:
                LOG.info(
                    "TYPE detected to contain 'raid', signifying a RAID "
                    "volume. Found: {!r}".format(line))
            else:
                LOG.info(
                    "TYPE did not match. Wanted: {!r} but found: {!r}".format(
                        block_type, line))
                continue

        # Ensure all required columns are at least present, even if blank
        missing = set(columns) - set(device)
        if missing:
            raise errors.BlockDeviceError(
                '%s must be returned by lsblk.' % ', '.join(sorted(missing)))

        name = os.path.join('/dev', device['KNAME'])

        try:
            udev = pyudev.Device.from_device_file(context, name)
        # pyudev started raising another error in 0.18
        except (ValueError, EnvironmentError, pyudev.DeviceNotFoundError) as e:
            LOG.warning("Device %(dev)s is inaccessible, skipping... "
                        "Error: %(error)s", {'dev': name, 'error': e})
            extra = {}
        else:
            # TODO(lucasagomes): Since lsblk only supports
            # returning the short serial we are using
            # ID_SERIAL_SHORT here to keep compatibility with the
            # bash deploy ramdisk
            extra = {key: udev.get('ID_%s' % udev_key) for key, udev_key in
                     [('wwn', 'WWN'), ('serial', 'SERIAL_SHORT'),
                      ('wwn_with_extension', 'WWN_WITH_EXTENSION'),
                      ('wwn_vendor_extension', 'WWN_VENDOR_EXTENSION')]}

        # NOTE(lucasagomes): Newer versions of the lsblk tool supports
        # HCTL as a parameter but let's get it from sysfs to avoid breaking
        # old distros.
        try:
            extra['hctl'] = os.listdir(
                '/sys/block/%s/device/scsi_device' % device['KNAME'])[0]
        except (OSError, IndexError):
            LOG.warning('Could not find the SCSI address (HCTL) for '
                        'device %s. Skipping', name)

        # Not all /dev entries are pointed to from /dev/disk/by-path
        by_path_name = by_path_mapping.get(name)

        devices.append(hardware.BlockDevice(name=name,
                                            model=device['MODEL'],
                                            size=int(device['SIZE']),
                                            rotational=bool(int(device['ROTA'])),
                                            vendor=hardware._get_device_info(device['KNAME'],
                                                                             'block', 'vendor'),
                                            by_path=by_path_name,
                                            **extra))

    return devices

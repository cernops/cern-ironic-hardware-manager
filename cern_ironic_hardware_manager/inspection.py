from ironic_python_agent import utils


def get_infiniband_adapters():
    """Detect number of infiniband network adapters

    Used by list_hardware_info to populate node's properties with a number
    of infiniband adapters connected to the device. Please note this
    assumes all the drivers required to detect the device have been loaded
    beforehand.

    :returns: A number of infiniband network adapters
    """

    out, e = utils.execute("ibv_devinfo | awk '/transport[[:space:]]*:/ {{print $2}}' | grep InfiniBand | wc -l", shell=True)
    return int(out)


def get_disk_enclosures():
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

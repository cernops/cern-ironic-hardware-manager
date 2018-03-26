#!/usr/bin/python -u

from oslo_log import log
import os.path
from multiprocessing import cpu_count
from multiprocessing.pool import ThreadPool
import subprocess
import re

# instantiate oslo logger
LOG = log.getLogger()

# TODO AG: import logging, tools and error handling
#      based on the name of the current image
# TODO AG: consider that different classes have different methods;
#       therefore, a 'method translation dictionary' will be required
#       in order to use the same code for different live images

# TODO AG: create utils.py file, import utility functions
def get_installed_packages():
    """ Provide a list of installed packages

    returns []
    """
    installed_packages = []
    yumbase = yum.YumBase()
    # ignore yum API output ("Loaded plugins:..")
    yumbase.preconf.debuglevel = 0
    yumbase.preconf.errorlevel = 0
    yumbase.conf.cache = 1
    # build package list
    for package in sorted(yumbase.rpmdb.returnPackages()):
        installed_packages.append(package.name)       
    return installed_packages

def get_possible_hw_tests():
    """ Provide a dictionary of hardware tests
    which may be run, based on required packages
    
    returns {}
    """
    # dictionary of required OS packages
    rpms = {'memory' : 'memtester',
            'cpu'    : 'cpu_test',
            'hepspec': 'hepspec06',
            'disk'   : 'e2fsprogs'}

    # Instantiate dictionary of possible tests
    possible_tests = {k:False for k in rpms.keys()}

    # get the list of installed packages
    installed = get_installed_packages()

    # if required package is installed,
    # possible tests dictionary is updated 
    for test, package in rpms.items() :
        if package in installed:
            possible_tests[test] = 'True'

    return possible_tests

def run_cmd_proc(no_procs, my_cmd, t_out = False):
    """ Launch processes in a thread pool
        of no_procs(unsigned int), running my_cmd(char)
        with a timeout of t_out(char).
        
        If t_out is not specified, my_cmd will run to completion.

        From "timeout" function man page: 
        's' for seconds (the default), 'm' for minutes, 'h' for hours or 'd' for days
        If the command times out, and --preserve-status is not set, then exit with
        status 124.  Otherwise, exit with the status of COMMAND.  If no signal
        is specified, send the TERM signal upon timeout.  The TERM signal kills
        any process that does not block or catch that signal.  It may be necessary
        to use the KILL (9) signal, since this signal cannot be caught, in which
        case the exit status is 128+9 rather than 124.

        TODO AG: sanitise user input (re, shlex)
        TODO AG: log details on the command and return code
        TODO AG: parse test logs?
    """
    # build command with timeout, if t_out is specified
    if t_out:
        # TODO AG: find a way to keep the *one* space when splitting
        # { /usr/bin/memtester 1000 1;}, after opening curly bracket
        t_out_cmd = ['/usr/bin/timeout', '10', 'bash', '-c']
        my_cmd = '{{ {};}}'.format(my_cmd)
        t_out_cmd.append(my_cmd)

        my_cmd = "/usr/bin/timeout {0} -c bash '{{  {1} }}'".format(t_out, my_cmd).split(' ')

        t_out_cmd  = '/usr/bin/timeout {} bash -c "{{ '.format(t_out)
        t_out_cmd .= '{}; }}"'.format(my_cmd)

    try:
        pool = ThreadPool(no_procs)
        for i in range(no_procs):
            pool.apply_async(subprocess.check_output, (my_cmd,))
        pool.close()
        pool.join()
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 124:
            LOG.info("Command {} timed out after {}".format(my_cmd, t_out))
        else:
            raise Exception('Running {} got exception {}'.format(my_cmd, exc))


class Tests(object):
    def __init__(self, parameter_list):
        self.num_cpus = cpu_count()

    def test_memory(self, t_out = False):
        """ Test system memory, using memtester package.

        First compute the amount of free memory, considering 
        a 'spare' memory zone. Then test the available memory
        equally shared between as many parallel processes as
        CPU threads.
        
        """
        self.timeout = t_out
        # declarative part
        # TODO AG: remove magic numbers && hardcoded paths (whole code)
        self.mem_spare_per_cpu = 64
        self.MEMTESTER = "/usr/bin/memtester"
        # get free memory (MB)
        meminfo = open('/proc/meminfo').read()
        match = re.search(r'MemFree:\s+(\d+)', meminfo)
        if match:
            self.mem_avail = int(match.groups()[0])/1024
            # how much memory to test per process
            self.mb_per_cpu = (self.mem_avail - self.mem_spare_per_cpu * self.num_cpus) / self.num_cpus
            LOG.info("Detected {} processing units".format(self.num_cpus))
            LOG.info("{} MiB available for testing".format(self.mem_avail))
            LOG.info("{} MiB per processing unit will be tested".format(self.mb_per_cpu))
            # start as many memory test subprocesses as CPUs
            LOG.info("Starting memory tests")
            self.mem_cmd  = '{} {} {}'.format(self.MEMTESTER, str(self.mb_per_cpu), "1")
            run_cmd_proc(self.num_cpus, self.mem_cmd, self.timeout)
            LOG.info("Finished memory tests")
        else:
            raise Exception('Failed to find MemFree in /proc/meminfo')

    def test_cpu(self, t_out = '48h'):
        """ Stress test CPU
        based on burnK7, burnMMX and burnP6 (from cpuburn package);
        TODO AG: use burnbx for cpu cache testing

        """
        self.timeout = t_out
        self.known_CPU = False
        # get CPU manufacturer
        self.cpuinfo = open('/proc/cpuinfo').read()
        match = re.search(r'vendor_id\t:\s+(\S+)',self.cpuinfo)
        self.cpu_model = match.groups()[0]
        if "Intel" in self.cpu_model:
            self.cpu_cmd = '{/opt/cpu_test/burnP6 & /opt/cpu_test/burnMMX;}'
            self.known_CPU = True
        elif "AMD" in self.cpu_model:
            self.cpu_cmd = '{/opt/cpu_test/burnK7 & /opt/cpu_test/burnMMX;}'
            self.known_CPU = True
        # start CPU tests
        if self.known_CPU:
            LOG.info("Starting CPU tests")
            run_cmd_proc(self.num_cpus, self.cpu_cmd, self.timeout)
            LOG.info("Finished memory tests")
        else:
            LOG.error('{} is not a known CPU model'.format(self.cpu_model))
            raise Exception('Unknown CPU model')

    def test_disk(self, parameter_list):
        pass
    
    def test_hepspec(self, parameter_list):
        pass
    
    def test_network(self, parameter_list):
        pass
    

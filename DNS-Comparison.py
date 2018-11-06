#!/usr/bin/python
#
# DNS Comparison Tool - v2.0(beta1)
#
# This tool emulates the behavior of Dig's +trace function by performing
# recursive queries starting using either specified nameservers or the
# system default.
#

import argparse
import curses
import time
import dns.resolver
import sys
import socket
import random
import multiprocessing
import csv
import datetime
import signal
import subprocess
import re
import os
import logging
from collections import deque
from enum import Enum
from multiprocessing.managers import SyncManager

""" Location of debug log and file starting name """
DEBUG_LOG_FILE = "/tmp/dns-debug-"

""" Maximum sample interval between DNS queries (in seconds) """
DNS_MAX_SAMPLE_INTERVAL = 1000000

""" Time to sleep between performing DNS queries """
DNS_QUERY_INTERVAL = 1

""" Timeout in seconds to wait for DNS query response """
DNS_QUERY_TIMEOUT = 5

""" Program Identification """
DNS_TOOL_TITLE = "DNS Comparison Tool v2.0(beta1)"

""" Flag from singnal handler to cleanly exit """
CAUGHT_EXIT_FLAG = False

""" List of DNS resolvers to query """
DNS_RESOLVER_LIST = deque()

""" Local host name for CSV output """
LOCAL_HOSTNAME = socket.gethostname()

""" Timer and loop guard for CSV data collection"""
WORKER_POLL_INTERVAL = 0.2
WORKER_LOOP_GUARD = 10000

""" UI sleep timer """
UI_SLEEP_TIMER=0.5

""" PING Binary"""
PING_EXE=None
PING6_EXE=None


""" Number of pings to test host """
DNS_PING_COUNT=1


class Task_State(Enum):
    """ Defines states for DNS query tasks
    """
    INIT_SINGLE = 1
    INIT_POLL = 2
    POLLING = 3
    SINGLE = 4
    PAUSED = 5
    EXIT = 6


class Query_Type(Enum):
    """ Defines type of query - IPv4 or IPv6 """
    IPV4 = 1
    IPv6 = 2


class Worker:
    """ Holds the information for each worker process
    """

    def __init__(self):
        self.process = None
        self.worker_id = -1
        self.target = ""
        self.query_type = Query_Type.IPV4
        self.results = None
        self.stats = None


class DNS_Answer:
    """ Class to store combined results from DNS query
    """
    def __init__(self):
        self.name = ""
        self.ttl = 0
        self.record_type = 0
        self.response_time = 0
        self.ping_time = -1
        self.authority = ""
        self.authority_ip = ""
        self.failure = False

    def __str__(self):
        return "Name=%s,TTL=%d,RecordType=%d,RespTime=%f,PingTime=%f,Auth=%s,AuthIP=%s,Failure=%s" % (self.name,
                                                                                                      self.ttl,
                                                                                                      self.record_type,
                                                                                                      self.response_time,
                                                                                                      self.ping_time,
                                                                                                      self.authority,
                                                                                                      self.authority_ip,
                                                                                                      str(self.failure))

    def set_response_time(self, time_val):
        """ Set the query response time (with bounds checking) """
        if time_val > 0:
            self.response_time = time_val

    def get_response_time(self):
        return self.response_time

    def get_response_time_formatted(self):
        """ Return the response time as a formatted string in ms or s """
        time_val = self.response_time
        if time_val > 1:
            return "{:4.2f} s".format(time_val)
        else:
            time_val *= 1000
            return "{:4.2f} ms".format(time_val)

    def get_ping_time_formatted(self):
        if self.ping_time > 0:
            return "{:4.2f} ms".format(self.ping_time)

        return "N/A"

    def get_record_type(self):
        """ Return the record type as a string """
        if self.record_type == 5:
            return "CNAME"
        elif self.record_type == 2:
            return "NS"
        elif self.record_type == 1:
            return "A"
        elif self.record_type == 6:
            return "SOA"
        elif self.record_type == 28:
            return "AAAA"
        return ""


class DNS_Statistics:
    """ Class to store statistical results of DNS queries """

    def __init__(self):
        self.query_min = 1000000
        self.query_max = 0
        self.query_total = 0
        self.query_last = 0
        self.query_count = 0
        self.query_failures = 0
        self.query_resolver = None

    def get_response_time_formatted(self, time_val):
        """ Return the response time as a formatted string in ms or s """
        if time_val > 1:
            return "{:4.2f} s".format(time_val)
        else:
            time_val *= 1000
            return "{:4.2f} ms".format(time_val)

    def get_query_min_formatted(self):
        return self.get_response_time_formatted(self.query_min)

    def get_query_max_formatted(self):
        return self.get_response_time_formatted(self.query_max)

    def get_query_last_formatted(self):
        return self.get_response_time_formatted(self.query_last)

    def get_query_avg_formatted(self):
        if self.query_count > 0:
            return self.get_response_time_formatted(self.query_total / self.query_count)
        else:
            return ""


def cleanup_workers():
    """ Utility function to clean up worker processes and make sure they exit """
    for worker in workers:
        task_states[worker.worker_id] = Task_State.EXIT

    for worker in workers:
        worker.process.join(DNS_QUERY_TIMEOUT)


def error_exit(msg):
    """ Utility function to display an error message and exit non-zero """
    print("ERROR: "+msg)
    sys.exit(1)


def handle_sigint(signal, frame):
    """ Catch SIGINT and mark flag to allow for clean exit """
    global CAUGHT_EXIT_FLAG

    CAUGHT_EXIT_FLAG = True


def load_resolver_list(filename):
    """ Load the list of DNS resolvers and perform a sanity check on the data"""
    global DNS_RESOLVER_LIST

    try:
        with open(filename, "r") as data_file:
            for dns_entry in data_file:
                try:
                    socket.inet_aton(dns_entry.rstrip())
                except socket.error:
                    error_exit("Invalid IP address provided in resolver list file = " + filename +
                               ". Entry = " + dns_entry)
                DNS_RESOLVER_LIST.append(dns_entry.rstrip())

    except (OSError, IOError) as e:
        error_exit("Unable to open resolver list file " + filename)

    return


def sync_mgr_init():
    """ Utility function to initialize SyncManager and establish signal handler """

    """ Install a signal handler to prevent CTL-C from interrupting process """
    signal.signal(signal.SIGINT, handle_sigint)


def set_ping_exe():
    """ Utility function to verify location of ping to support cross platform execution """
    global PING_EXE
    global PING6_EXE

    check_locations = ['/bin/ping', '/sbin/ping', '/usr/bin/ping']
    check6_locations = ['/bin/ping6', '/sbin/ping6', '/usr/bin/ping6']

    for location in check_locations:
        if os.path.isfile(location) and os.access(location, os.X_OK):
            PING_EXE = location
            break

    if PING_EXE is None:
        error_exit("Unable to verify location of ping in paths "+str(check_locations))

    for location in check6_locations:
        if os.path.isfile(location) and os.access(location, os.X_OK):
            PING6_EXE = location
            break

    if PING6_EXE is None:
        error_exit("Unable to verify location of ping6 in paths "+str(check_locations))


def ping_host(host, query_type):
    global PING_EXE
    global PING6_EXE
    global DNS_PING_COUNT

    logging.debug("ping_host() - ENTRY")

    #
    # Do some validation on the ping target to ensure proper EXE is used
    #
    use_ping = PING_EXE
    if host.find(":") != -1:
        use_ping = PING6_EXE

    #ping_cmd = "%s -W 1 -c %s %s" % (use_ping, str(DNS_PING_COUNT), host)
    ping_cmd = "%s  -c %s %s" % (use_ping, str(DNS_PING_COUNT), host)
    host_min, host_avg, host_max = None, None, None
    host_error = None

    try:
        logging.debug("ping_host(): CMD=%s",ping_cmd)
        response = subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT, shell=True)
        logging.debug("ping_host(): RESPONSE=\n%s",response)
        match = re.search("rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)", response, re.MULTILINE)

        if match:
            host_min = match.group(1)
            host_avg = match.group(2)
            host_max = match.group(3)
        else:
            match = re.search("round-trip min/avg/max/stddev = ([\d.]+)/([\d.]+)/([\d.]+)", response, re.MULTILINE)

            if match:
                host_min = match.group(1)
                host_avg = match.group(2)
                host_max = match.group(3)

    except subprocess.CalledProcessError as e:
        host_error = e.output
    except OSError as e:
        host_error = e.strerror

    if host_avg:
        return float(host_avg)

    return -1


def query_host(dns_target, resolver, query_type):
    """ This function does the bulk of the work for performing the DNS queries and evaluating
        the results

        dns_target = Hostname to perform lookup on

        resolver = DNS resolver to use for initial query (optional)
    """
    return_value = None

    logging.debug("query_host() - ENTRY")
    logging.debug("query_host(): Target=%s Resolver=%s QueryType=%s",str(dns_target),str(resolver),str(query_type))

    """ Take the DNS target and reverse it for query """
    rev_fqdn = dns_target.split('.')[::-1]

    """ Set up ability to change DNS resolver and if initial resolver specified - use it """
    active_resolver = dns.resolver.Resolver()

    if resolver:
        active_resolver.nameservers = [resolver]
        active_resolver.lifetime = DNS_QUERY_TIMEOUT


    """ Query for root NS """
    try:
        root_query = active_resolver.query('.', dns.rdatatype.NS)
    except:
        root_info = DNS_Answer()
        root_info.name = "."
        root_info.failure = True
        return_value = deque()
        return_value.append(root_info)
        return return_value


    root_server = ""

    if root_query.rrset is not None:
        root_info = DNS_Answer()
        root_info.name = "."
        root_info.ttl = root_query.rrset.ttl
        root_info.record_type = root_query.rrset.rdtype
        root_info.set_response_time(root_query.response.time)
        root_server = str(random.choice(root_query.rrset.items))
        root_info.authority = root_server
        root_info.authority_ip = socket.gethostbyname(root_server)
        root_info.ping_time = ping_host(root_info.authority_ip, query_type)
        return_value = deque()
        return_value.append(root_info)
    else:
        return return_value


    """ Set active NS to root NS """
    active_resolver.nameservers = [socket.gethostbyname(root_server)]

    dns_target = ""


    final_query = True

    """ Work through DNS target FQDN from root down performing queries and storing results """
    for part in rev_fqdn:

        dns_target = part + "." + dns_target

        try:
            part_query = active_resolver.query(dns_target, dns.rdatatype.A, raise_on_no_answer=False)
            logging.debug("query_host(): Target=%s Answer=%s\nAuthority=%s",dns_target,str(part_query.response.answer),
                          str(part_query.response.authority))

        except:
            part_info = DNS_Answer()
            part_info.name = dns_target
            part_info.failure = True
            return_value.append(part_info)
            return return_value

        if len(part_query.response.answer) > 0:
            part_info = DNS_Answer()
            part_info.name = dns_target
            part_info.set_response_time(part_query.response.time)
            part_info.ttl = part_query.response.answer[0].ttl
            part_info.record_type = part_query.response.answer[0].rdtype
            part_info.authority = str(random.choice(part_query.response.answer[0].items))
            part_info.authority_ip = socket.gethostbyname(part_info.authority)
            part_info.ping_time = ping_host(part_info.authority_ip, query_type)
            if part_info.record_type == dns.rdatatype.CNAME:
                final_query = False
            return_value.append(part_info)

        elif len(part_query.response.authority) > 0:
            part_info = DNS_Answer()
            part_info.name = dns_target
            part_info.ttl = part_query.response.authority[0].ttl
            part_info.record_type = part_query.response.authority[0].rdtype
            if part_query.response.authority[0].rdtype == 6:
                part_info.authority = str(part_query.response.authority[0].items[0].mname)
            else:
                part_info.authority = str(random.choice(part_query.response.authority[0].items))
            part_info.authority_ip = socket.gethostbyname(part_info.authority)
            part_info.set_response_time(part_query.response.time)
            part_info.ping_time = ping_host(part_info.authority_ip, query_type)
            return_value.append(part_info)
            active_resolver.nameservers = [socket.gethostbyname(part_info.authority)]

    if final_query:

        try:
            if query_type == Query_Type.IPV4:
                part_query = active_resolver.query(dns_target, dns.rdatatype.A, raise_on_no_answer=False)
            else:
                part_query = active_resolver.query(dns_target, dns.rdatatype.AAAA, raise_on_no_answer=False)
        except:
            part_info = DNS_Answer()
            part_info.name = dns_target
            part_info.failure = True
            return_value.append(part_info)
            return return_value

        logging.debug("query_host(): Target=%s Answer=%s\nAuthority=%s",dns_target,str(part_query.response.answer),
                      str(part_query.response.authority))

        if len(part_query.response.answer) > 0:
            part_info = DNS_Answer()
            part_info.name = dns_target
            part_info.authority= str(random.choice(part_query.response.answer[0].items))
            part_info.authority_ip = part_info.authority
            part_info.set_response_time(part_query.response.time)
            part_info.ping_time = ping_host(part_info.authority_ip, query_type)
            part_info.ttl = part_query.response.answer[0].ttl
            part_info.record_type = part_query.response.answer[0].rdtype
            return_value.append(part_info)
        elif len(part_query.response.authority) > 0:
            part_info = DNS_Answer()
            part_info.name = dns_target
            if part_query.response.authority[0].rdtype == 6:
                part_info.authority = str(part_query.response.authority[0].items[0].mname)
            else:
                part_info.authority = str(random.choice(part_query.response.authority[0].items))
            part_info.authority_ip = socket.gethostbyname(part_info.authority)
            part_info.set_response_time(part_query.response.time)
            part_info.ping_time = ping_host(part_info.authority_ip, query_type)
            part_info.ttl = part_query.response.authority[0].ttl
            part_info.record_type = part_query.response.authority[0].rdtype
            return_value.append(part_info)

    return return_value


def worker(worker_id, dns_target, query_type, task_list, results_queue ):
    """ Task worker function which runs per Process and collects the data
    """
    global CAUGHT_EXIT_FLAG
    global DNS_RESOLVER_LIST
    global workers
    global DEBUG_LOG_FILE

    logFile = DEBUG_LOG_FILE + str(worker_id) + ".log"
    logging.basicConfig(filename=logFile, filemode='w', level=logging.DEBUG)
    logging.debug("START OF WORKER"+str(worker_id))
    query_stats = DNS_Statistics()

    while not CAUGHT_EXIT_FLAG:
        try:
            resolver = None

            """ If worker process not paused and we have a list of DNS resolvers,
                pull the next one from the dequeue and rotate the list """
            if task_list[worker_id] == Task_State.EXIT:
                break
            elif task_list[worker_id] != Task_State.PAUSED:
                if DNS_RESOLVER_LIST:
                    resolver = DNS_RESOLVER_LIST[0]
                    DNS_RESOLVER_LIST.rotate(-1)

                logging.debug("WORKER QT = " + str(query_type))
                """ Perform the query and process the results"""
                target_data = query_host(dns_target, resolver, query_type)

                query_stats.query_resolver = resolver
                response_time = 0
                for answers in target_data:
                    response_time += answers.response_time
                    if answers.failure:
                        query_stats.query_failures += 1

                query_stats.query_count += 1
                query_stats.query_total += response_time
                query_stats.query_last = response_time

                if response_time < query_stats.query_min:
                    query_stats.query_min = response_time

                if response_time > query_stats.query_max:
                    query_stats.query_max = response_time

                """ Worker processes send their results back to the main process
                    using the results_queue. Each update contains the worker_id,
                    the cumulative query statistics, and the current query results. """
                if target_data is not None:
                    update = [worker_id, query_stats, target_data]
                    results_queue.put(update)

                if task_list[worker_id] == Task_State.INIT_SINGLE or task_list[worker_id] == Task_State.SINGLE:
                    task_list[worker_id] = Task_State.PAUSED
                elif task_list[worker_id] == Task_State.INIT_POLL:
                    task_list[worker_id] = Task_State.POLLING

            time.sleep(DNS_QUERY_INTERVAL)

        except KeyboardInterrupt:
            CAUGHT_EXIT_FLAG = True

        except Exception:
            break


def histogram_string(units, line_value, total_value):
    """ Convert time value into a histogram string for display"""
    if line_value < 1:
        line_value *= 1000

    if total_value < 1:
        total_value *= 1000

    per_unit = int(total_value / units)

    if per_unit > 0:
        return "#"*int(line_value / per_unit)

    return ""


def process_screen_ui():
    """ Main function to handle Curses based UI """

    global CAUGHT_EXIT_FLAG
    global UI_SLEEP_TIMER
    global args
    global workers
    global task_states
    global results_queue

    stdscr = curses.initscr()

    stdscr.nodelay(1)

    toggle_show_ip = False

    while True:
        try:
            """ Process all results from workers """
            while results_queue.empty() is not True:
                update = results_queue.get()
                id = update[0]
                workers[id].stats = update[1]
                workers[id].results = update[2]

            """ Redraw the screen with data """
            stdscr.clear()
            screen_size = stdscr.getmaxyx()

            stdscr.addstr(0, 0, DNS_TOOL_TITLE, curses.A_REVERSE)
            wall_clock = time.strftime("%I:%M:%S %p", time.localtime())

            stdscr.addstr(0, screen_size[1] - 11, wall_clock)
            host_space = 30
            column_space = host_space + 5 + 6 + 10 + 8 + 2 + 10
            column_count = 0
            for worker in workers:
                y_index = 2
                x_index = column_count * column_space
                if x_index > screen_size[1] or (x_index + column_space) > screen_size[1]:
                    stdscr.addstr(screen_size[0] - 2, 1, "ERROR: Screen not wide enough to draw all columns! ",
                                  curses.A_BOLD)
                    break
                if worker.results is not None:
                    stdscr.addstr(y_index, x_index,
                                  "{:{hs}s} {:>5s} {:>6s} {:>9s}       {:>9s}".format(' ', 'TYPE', 'TTL',
                                                                                     'RESPONSE', "PING", hs=host_space))
                    y_index += 1
                    for data in worker.results:
                        if data.failure is not True:
                            stdscr.addstr(y_index, x_index, "{:{hs}s} {:>5s} {:>6d} {:>9s} {:5s} {:>9s}".format(
                                data.authority_ip if toggle_show_ip else data.authority, data.get_record_type(),
                                data.ttl, data.get_response_time_formatted(),
                                histogram_string(5, data.response_time, worker.stats.query_last),
                                data.get_ping_time_formatted(), hs = host_space))
                        else:
                            stdscr.addstr(y_index, x_index, "{:{hs}s}".format("QUERY FAILURE", hs = host_space))
                        y_index += 1
                    y_index += 1
                    stdscr.addstr(y_index, x_index, "{:{hs}s}".format(worker.target, hs = host_space),curses.A_BOLD)
                    y_index += 1
                    stdscr.addstr(y_index, x_index,
                                  "Resolver   : {:>9s}".format(worker.stats.query_resolver))
                    y_index += 1
                    stdscr.addstr(y_index, x_index, "Last Query : {:>9s}".format(worker.stats.get_query_last_formatted()))
                    y_index += 1
                    stdscr.addstr(y_index, x_index, "Min/Avg/Max: {:>9s} / {:>9s} / {:>9s}".format(
                        worker.stats.get_query_min_formatted(), worker.stats.get_query_avg_formatted(),
                        worker.stats.get_query_max_formatted()))
                    column_count += 1

            stdscr.addstr(screen_size[0]-1, 1, "Press character: (q)uit, (s)tart polling, (p)ause polling, (i)p show/no show")
            stdscr.refresh()

            # Check for input to exit
            c = stdscr.getch()

            if c == ord('q') or c == ord('Q') or CAUGHT_EXIT_FLAG:
                break

            if c == ord('p') or c == ord('P'):
                for worker in workers:
                    task_states[worker.worker_id] = Task_State.PAUSED

            if c == ord('s') or c == ord('s'):
                for worker in workers:
                    task_states[worker.worker_id] = Task_State.POLLING

            if c == ord('i') or c == ord('I'):
                toggle_show_ip = not toggle_show_ip

            time.sleep(UI_SLEEP_TIMER)

        except KeyboardInterrupt:
            CAUGHT_EXIT_FLAG = True

    """ Clean up curses and print an empty line for cases where cursor is left on last line of UI """
    curses.echo()
    curses.endwin()
    print()


def process_csv_file():
    """ Main function to process output to CSV file"""

    global CAUGHT_EXIT_FLAG
    global LOCAL_HOSTNAME
    global WORKER_LOOP_GUARD
    global WORKER_POLL_INTERVAL
    global args
    global workers
    global task_states
    global results_queue

    print(DNS_TOOL_TITLE)
    print("Processing queries into CSV file. DNS query interval = "+str(DNS_QUERY_INTERVAL)+" secs. CTL-C to exit.")

    try:
        """ Wait for query timeout to allow workers to collect initial data """
        workersComplete = False
        while not workersComplete:
            workersComplete = True
            for worker in workers:
                if task_states[worker.worker_id] != Task_State.PAUSED:
                    workersComplete = False

            time.sleep(DNS_QUERY_TIMEOUT)
    except KeyboardInterrupt:
        CAUGHT_EXIT_FLAG = True

    try:
        with open(args.csvfile, "wb") as csv_file:

            csv_writer = csv.writer(csv_file, quoting=csv.QUOTE_NONNUMERIC)

            """ Initial pass to collect results and write header lines in CSV file """
            while results_queue.empty() is not True:
                update = results_queue.get()
                id = update[0]
                workers[id].stats = update[1]
                workers[id].results = update[2]

            header_timestamp = datetime.datetime.now().isoformat()
            header_one = [header_timestamp]
            header_two = [header_timestamp]
            header_three = [header_timestamp]

            header_one.append('Hostname')
            header_two.append('')
            header_three.append('')

            header_one.append('DNS Resolver')
            header_two.append('')
            header_three.append('')

            for worker in workers:
                if worker.results is not None:
                    for data in worker.results:
                        if data.failure is not True:
                            header_one.append(data.authority)
                            header_two.append(data.get_record_type())
                            header_three.append(data.ttl)
                            header_one.append(data.authority)
                            header_two.append('')
                            header_three.append('')
                            header_one.append(data.authority)
                            header_two.append('')
                            header_three.append('')
                        else:
                            header_one.append("QUERY_FAILED")
                            header_two.append('N/A')
                            header_three.append('N/A')
                            header_one.append("QUERY_FAILED")
                            header_two.append('N/A')
                            header_three.append('N/A')
                            header_one.append("QUERY_FAILED")
                            header_two.append('N/A')
                            header_three.append('N/A')

                    header_one.append(worker.target)
                    header_two.append('')
                    header_three.append('')

                    header_one.append('')
                    header_two.append('')
                    header_three.append('')

            csv_writer.writerow(header_one)
            csv_writer.writerow(header_two)
            csv_writer.writerow(header_three)

            data_update = False

            while not CAUGHT_EXIT_FLAG:
                try:
                    """ To coordinate all the worker processes and make sure they are using the same
                        resolver, we trigger single queries instead of polling """
                    for worker in workers:
                        task_states[worker.worker_id] = Task_State.SINGLE

                    """ Workers have been triggered so we have to wait for them to all complete their
                        queries. Check all the workers and if any are still working, we sleep for a
                        small amount of time to minimize CPU usage. As a safe guard, we count the 
                        loop iterations to detect a locked-up condition and exit of of the program 
                        with an error. """
                    loopCount = 0
                    workersComplete = False
                    while not workersComplete:
                        workersComplete = True
                        for worker in workers:
                            if task_states[worker.worker_id] != Task_State.PAUSED:
                                workersComplete = False

                        loopCount += 1
                        time.sleep(WORKER_POLL_INTERVAL)
                        if loopCount > WORKER_LOOP_GUARD:
                            error_exit("One or more worker processes failed to complete queries after an extended time")

                    """ Pull all the worker results from the queue and begin processing the data. """
                    while results_queue.empty() is not True:
                        update = results_queue.get()
                        id = update[0]
                        workers[id].stats = update[1]
                        workers[id].results = update[2]
                        data_update = True

                    """ Check all the results for all the workers - if any errors, skip this update"""
                    for worker in workers:
                        if worker.results is not None:
                            for data in worker.results:
                                if data.failure is True:
                                    data_update = False

                    """ Data from workers present and no errors found, write a new CSV record """
                    if data_update:
                        data_update = False
                        data_row = [datetime.datetime.now().isoformat()]
                        data_row.append(LOCAL_HOSTNAME)
                        if workers[id].stats.query_resolver:
                            data_row.append(workers[id].stats.query_resolver)
                        else:
                            data_row.append('SYSTEM')

                        for worker in workers:
                            if worker.results is not None:
                                failed_query = False

                                for data in worker.results:
                                    if data.failure is not True:
                                        data_row.append(data.authority_ip)
                                        data_row.append(data.response_time)
                                        if data.ping_time > 0:
                                            data_row.append(data.ping_time / 1000)
                                        else:
                                            data_row.append('N/A')
                                    else:
                                        data_row.append('N/A')
                                        data_row.append('N/A')
                                        data_row.append('N/A')
                                        failed_query = True

                                if failed_query is False:
                                    data_row.append(worker.stats.query_last)
                                else:
                                    data_row.append('N/A')

                                data_row.append('')

                        csv_writer.writerow(data_row)
                        csv_file.flush()

                    time.sleep(DNS_QUERY_INTERVAL)

                except KeyboardInterrupt:
                    CAUGHT_EXIT_FLAG = True

            csv_file.close()
    except Exception as e:
        print("ERROR: Unable to open CSV file " + args.csvfile)
        cleanup_workers()

    return


if __name__ == '__main__':
    """ Parse command line arguments"""

    parser = argparse.ArgumentParser(description='DNS Comparison Tool')

    parser.add_argument("--hostname", action='store', default=None,
                        help='Name to use for the local host when generating CSV data.')

    parser.add_argument("--resolver", action='store', default=None,
                        help='IP of resolver to use for queries. Defaults to host configuration.')

    parser.add_argument("--resolverlist", action='store', default=None,
                        help='File containing a list of DNS resolvers to use (one per line as IP addresses)')

    parser.add_argument("--nopoll", action='store_true', default=False,
                        help='Start with single query / no polling when using UI')

    parser.add_argument("--ipv6", action='store_true', default=False,
                        help='Perform IPv6 queries for the listed targets')

    parser.add_argument("--csvfile", action='store', default=None,
                        help='CSV filename to store collected data')

    parser.add_argument("--sample", action='store', type=float, default=None,
                        help='Sample interval between queries in seconds to collect data (Default=1s)')

    parser.add_argument("target", nargs=1,
                        help='DNS target')

    parser.add_argument("addl_targets", nargs='*',
                        help='Additional DNS targets (up to 7)')

    args = parser.parse_args()

    if args.sample:
        if args.sample < 0.0 or args.sample > DNS_MAX_SAMPLE_INTERVAL:
            error_exit("DNS sample interval of "+str(args.sample)+" is invalid. Value must be > 0 and < "
                       + str(DNS_MAX_SAMPLE_INTERVAL))

        DNS_QUERY_INTERVAL = args.sample

    host_list = [args.target[0]]

    if len(args.addl_targets) > 7:
        error_exit("A maximum of 8 hosts can be specified.")

    for addl_hosts in args.addl_targets:
        host_list.append(addl_hosts)

    if args.resolver and args.resolverlist:
        error_exit("Must specify EITHER a single DNS resolver OR a list of resolvers.")

    if args.resolver:
        try:
            socket.inet_aton(args.resolver)
        except socket.error:
            error_exit("Invalid IP address provided for resolver = "+args.resolver)
        DNS_RESOLVER_LIST.append(args.resolver)

    if args.resolverlist:
        load_resolver_list(args.resolverlist)

    if args.hostname:
        LOCAL_HOSTNAME = args.hostname

    """ Verify location of ping exe"""
    set_ping_exe()

    """ Create worker processes to perform queries - one per target - to a maximum of 8 """
    dns_manager = SyncManager()
    dns_manager.start(sync_mgr_init)

    """ task_states - used to control operation of worker processes
        results_queue - used by worker processes to return data to the main process """
    task_states = dns_manager.list()
    results_queue = dns_manager.Queue()
    workers = []

    """ Create a worker process for each target in the host list. If program is started in UI
        mode, then workers are set to start continuously polling otherwise they will perform
        an initial query and then pause until told to query again. This is done so that all
        workers are polling using the same resolver when writing data to CSV files. """
    worker_id = 0
    for host in host_list:
        entry = Worker()
        entry.worker_id = worker_id
        if args.ipv6:
            entry.query_type = Query_Type.IPv6

        if args.nopoll or args.csvfile:
            task_states.insert(worker_id, Task_State.INIT_SINGLE)
        else:
            task_states.insert(worker_id, Task_State.INIT_POLL)

        p = multiprocessing.Process(target=worker, args=(worker_id, host, entry.query_type, task_states, results_queue))
        p.start()
        entry.process = p
        entry.target = host

        workers.insert(worker_id, entry)
        worker_id += 1

    if args.csvfile:
        process_csv_file()
    else:
        process_screen_ui()

    cleanup_workers()

    dns_manager.shutdown()

    sys.exit(0)

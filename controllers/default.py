# -*- coding: utf-8 -*-
# this file is released under public domain and you can use without limitations

#########################################################################
## This is a sample controller
## - index is the default action of any application
## - user is required for authentication and authorization
## - download is for downloading files uploaded in the db (does streaming)
#########################################################################
import time
from datetime import date
from datetime import datetime
import subprocess
import os
import sys
import netaddr



date = str(date.today())

db.define_table('target_specification',
               Field('target',requires=IS_NOT_EMPTY()),
               Field('v6_scanning1','boolean'))
form1 = SQLFORM(db.target_specification,labels={'target':'Scan target. Enter subnets in the form \'10.0.0.0/24\':','v6_scanning1':'Enable IPv6 Scanning (if an IPv6 address was entered above)'},submit_button='Scan Now (without more options)')

db.define_table('discovery',
               Field('target2',requires=IS_NOT_EMPTY()),
               Field('v6_scanning','boolean'),
               Field('list_scan','boolean'),
               Field('ping_scan','boolean'),
               Field('tcp_ping_type',requires=IS_IN_SET(['Default','No ping - Skip Host Discovery','TCP SYN Ping','TCP ACK Ping','SCTP INIT Ping'])),
               Field('tcp_portlist'),
               Field('icmp_ping_type',requires=IS_IN_SET(['Default','ICMP Echo','Timestamp','Address Mask'])),
               Field('icmp_portlist'),
               Field('arp_ping','boolean'),
               Field('traceroute','boolean'),
               Field('port_discovery',requires=IS_IN_SET(['Default','TCP SYN scan','TCP Connect scan','TCP ACK scan','TCP Window scan','TCP Maimon scan','SCTP INIT scan','SCTP COOKIE ECHO scan'])),
              Field('udp_scan','boolean'),
              Field('fast_scan','boolean'),
              Field('port_range'),
              Field('consecutive','boolean'),
              Field('check_version','boolean'),
              Field('os_detection','boolean'),
              Field('extreme','boolean'),
              Field('reason','boolean'),
              Field('packet_trace','boolean'),
              Field('open_ports','boolean'),
              Field('verbose_output','boolean'),
              Field('debugging_output','boolean'))
form2 = SQLFORM(db.discovery,labels={'target2':'Scan target. Enter subnets in the form \'10.0.0.0/24\':','fast_scan':'Fast Scan (do not use if you are specifying ports to scan)','v6_scanning':'Enable IPv6 Scanning (if an IPv6 address was entered above)','list_scan':'List targets to scan. Not valid with other scan types.','ping_scan':'Ping scan. Not valid with other scan types.','tcp_ping_type':'TCP/SCTP Ping Type','tcp_portlist':'TCP Ports:','icmp_ping_type':'ICMP Ping Type','icmp_portlist':'ICMP Ports:','arp_ping':'ARP (Address Resolution Protocol) Ping','tracroute':'Trace hop path to each host','udp_scan':'UDP scan','port_range':'Ports to scan. Enter ranges in the form \'1-100\' and separate ports with a comma. There should be no spaces.','consecutive':'Scan ports consectuively - don\'t randomize','check_version':'Probe open ports to determine service/version info','os_detection':'Enable OS detection','extreme':'Enable OS detection with version detection, script scanning, and traceroute','reason':'Display the reason for a port\'s state','packet_trace':'Show all packets sent and received','open_ports':'Only show open (or possibly open) ports'},submit_button = 'Scan Now')


def index():
    session.datetime = str(datetime.now())
    session.basic_args = ["sudo","nmap","-o/home/bwelch/Scans/Scan_%s.txt" % (session.datetime)] # CHANGE PATH
    form1.vars.target = ''
    form1.vars.v6_scanning1 = False
    form2.vars.tcp_ping_type = 'Default'
    form2.vars.tcp_portlist = ''
    form2.vars.icmp_ping_type = 'Default'
    form2.vars.icmp_portlist = ''
    form2.vars.port_discovery = 'Default'

    # Invoked once form1 is submitted
    if form1.process().accepted: # If form is submitted without errors

        # FORM 1 INPUT VALIDATION
        if form1.vars.v6_scanning1 != True:

            target_input = str(form1.vars.target)

            # Uses the netaddr package for IP validiation
            if target_input.find('/') != -1:
                target_input = target_input[:target_input.find('/')]
                cidr = target_input[target_input.find('/'):]
            valid_ip = netaddr.valid_ipv4(target_input)


        else:

            target_input = str(form1.vars.target)

            # Uses the netaddr package for IP validiation
            if target_input.find('/') != -1:
                target_input = target_input[:target_input.find('/')]
                cidr = target_input[target_input.find('/'):]
            valid_ip = netaddr.valid_ipv6(target_input)

        if valid_ip: # If the entered target passes input validation

            # Building the nmap command
            if form1.vars.v6_scanning1:
                session.basic_args.append('-6')
            session.basic_args.append(str(form1.vars.target))

            # Building the string version of the command for display on the scan_result page
            session.command_line = ''
            count = 0
            for value in session.basic_args:
                count += 1
            count2 = 0
            for command in session.basic_args:
                count2 += 1
                if command.find('-o') == -1:
                    if (count - count2) != 0:
                        session.command_line += command + ' '
                    else:
                        session.command_line += command

            # Starting the nmap scan process
            try:
                # Attempting to start the process as a background process
                session.process = subprocess.Popen(session.basic_args,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
            except subprocess.CalledProcessError:
                # If there was an error starting the process, redirect to the scan_result page with an error message
                session.result = 'There was an error when executing the scan.'
                redirect(URL('scan_result'))

            # User is redirected to the scanning page while the scan is being carried out
            redirect(URL('scanning'))

        else: # If target entered doesn't pass input validation
            response.flash = 'Invalid target entered.'

    elif form1.errors: # If there was an error submitting the form
        response.flash = 'Enter a target.'

    # Invoked once form2 is submitted
    if form2.process().accepted: # If form is submitted without errors

        # FORM2 INPUT VALIDATION
        if form2.vars.v6_scanning1 != True:

            target_input = str(form2.vars.target2)

            # Uses the netaddr package for IP validiation
            if target_input.find('/') != -1:
                target_input = target_input[:target_input.find('/')]
                cidr = target_input[target_input.find('/'):]
            valid_ip = netaddr.valid_ipv4(target_input)


        else:

            target_input = str(form1.vars.target)

            # Uses the netaddr package for IP validiation
            if target_input.find('/') != -1:
                target_input = target_input[:target_input.find('/')]
                cidr = target_input[target_input.find('/'):]
            valid_ip = netaddr.valid_ipv6(target_input)

        if valid_ip: # If target passes input validation

            # FORM2 INPUT PROCESSING
            if form2.vars.v6_scanning == True:
                session.basic_args.append('-6')
            if form2.vars.list_scan == True:
                session.basic_args.append(str(form2.vars.target2))
                redirect(URL('list_scan'))
            if form2.vars.ping_scan == True:
                session.basic_args.append(str(form2.vars.target2))
                redirect(URL('ping_scan'))
            session.email_addr = form2.vars.email_results2
            if form2.vars.tcp_ping_type == 'No Ping - Skip Host Discovery':
                session.basic_args.append('-Pn')
            elif form2.vars.tcp_ping_type == 'TCP SYN Ping' and form2.vars.tcp_portlist != '':
                session.basic_args.append('-PS' + str(form2.vars.tcp_portlist))
            elif form2.vars.tcp_ping_type == 'TCP SYN Ping':
                 session.basic_args.append('-PS')
            elif form2.vars.tcp_ping_type == 'TCP ACK Ping' and form2.vars.tcp_portlist != '':
                session.basic_args.append('-PA' + str(form2.vars.tcp_portlist))
            elif form2.vars.tcp_ping_type == 'TCP ACK Ping':
                session.basic_args.append('-PA')
            elif form2.vars.tcp_ping_type == 'SCTP INIT Ping' and form2.vars.tcp_portlist != '':
                session.basic_args.append('-PY' + str(form2.vars.tcp_portlist))
            elif form2.vars.tcp_ping_type == 'SCTP INIT Ping':
                session.basic_args.append('-PY')
            if form2.vars.icmp_ping_type == 'ICMP Echo' and form2.vars.icmp_portlist != '':
                session.basic_args.append('-PE' + str(form2.vars.icmp_portlist))
            elif form2.vars.icmp_ping_type == 'ICMP Echo':
                session.basic_args.append('-PE')
            elif form2.vars.icmp_ping_type == 'Timestamp' and form2.vars.icmp_portlist != '':
                session.basic_args.append('-PP' + str(form2.vars.icmp_portlist))
            elif form2.vars.icmp_ping_type == 'Timestamp':
                session.basic_args.append('-PP')
            elif form2.vars.icmp_ping_type == 'Address Mask' and form2.vars.icmp_portlist != '':
                session.basic_args.append('-PM' + str(form2.vars.icmp_portlist))
            elif form2.vars.icmp_ping_type == 'Address Mask':
                session.basic_args.append('-PM')
            if form2.vars.arp_ping == True:
                session.basic_args.append('-PR')
            if form2.vars.traceroute == True:
                session.basic_args.append('--traceroute')
            if form2.vars.ping_scan == True:
                session.basic_args.append('-sn')

            if form2.vars.port_discovery != 'Default' and form2.vars.discovery != None:
                if form2.vars.port_discovery == 'TCP SYN scan':
                    session.basic_args.append('-sS')

                elif form2.vars.port_discovery == 'TCP Connect scan':
                    session.basic_args.append('-sT')

                elif form2.vars.port_discovery == 'TCP ACK scan':
                    session.basic_args.append('-sA')

                elif form2.vars.port_discovery == 'TCP Window scan':
                    session.basic_args.append('-sW')

                elif form2.vars.port_discovery == 'TCP Maimon scan':
                    session.basic_args.append('-sM')
                elif form2.vars.port_discovery == 'SCTP INIT scan':
                    session.basic_args.append('-sY')
                elif form2.vars.port_discovery == 'SCTP COOKIE ECHO scan':
                    session.basic_args.append('-sZ')

            if form2.vars.udp_scan == True and form2.vars.scan_technique != 'Default':
                session.basic_args.append('-sU')
            elif form2.vars.udp_scan == True:
                session.basic_args.append('-sU')
            if form2.vars.fast_scan == True:
                session.basic_args.append('-F')
            elif form2.vars.port_range:
                session.basic_args.append('-p' + str(form2.vars.port_range))
            if form2.vars.consecutive == True:
                session.basic_args.append('-r')
            if form2.vars.version == True:
                session.basic_args.append('-sV')
            if form2.vars.extreme == True and form2.vars.os_detection == True:
                session.basic_args.append('-A')
            elif form2.vars.os_detection == True:
                session.basic_args.append('-O')
            elif form2.vars.extreme == True:
                session.basic_args.append('-A')

            if form2.vars.reason == True:
                session.basic_args.append('--reason')
            if form2.vars.packet_trace == True:
                session.basic_args.append('--packet-trace')
            if form2.vars.open == True:
                session.basic_args.append('--open')
            if form2.vars.verbose_output == True:
                session.basic_args.append('-vv')
            if form2.vars.debugging_output == True:
                session.basic_args.append('-dd')
            session.basic_args.append(str(form2.vars.target2))
            session.command_line = ''

            # Building the string version of the nmap command used for display on the scan_result page
            count = 0
            for value in session.basic_args:
                count += 1
            count2 = 0
            for command in session.basic_args:
                count2 += 1
                if command.find('-o') == -1:
                    if (count - count2) != 0:
                        session.command_line += command + ' '
                    else:
                        session.command_line += command

            # Starting the nmap scan process
            try:
                # Attempting to start the process as a background process
                session.process = subprocess.Popen(session.basic_args,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
            except subprocess.CalledProcessError:
                # If there was an error starting the process, redirect to the scan_result page with an error message
                session.result = 'There was an error when executing the scan.'
                redirect(URL('scan_result'))

            # Redirect the user to the scanning page while the scan is being carried out
            redirect(URL('scanning'))
        else:
            response.flash = 'Invalid target entered.'
    elif form2.errors:
        response.flash = 'Check each field.'
    return dict(form1=form1,form2=form2)

def scan_result():
    if session.result == 'There was an error when executing the scan.':
        session.forget()
        return dict(command=session.command_line,result=session.result,date=date)
    else:
        txt = open("/home/bwelch/Scans/Scan_%s.txt" % (session.datetime)) # CHANGE PATH
        session.result = txt.read()
        txt.close()
    session.forget()
    return dict(command=session.command_line,result=session.result,date=date)

def ping_scan():
    session.basic_args.append('-sn')
    session.command_line = ''
    count = 0
    for value in session.basic_args:
        count += 1
    count2 = 0
    for command in session.basic_args:
        count2 += 1
        if command.find('-o') == -1:
            if (count - count2) != 0:
                session.command_line += command + ' '
            else:
                session.command_line += command
    try:
        session.process = subprocess.Popen(session.basic_args,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        session.result = 'There was an error when executing the scan.'
        redirect(URL('scan_result'))
    return redirect(URL('scanning'))

def list_scan():
    session.basic_args.append('-sL')
    session.command_line = ''
    count = 0
    for value in session.basic_args:
        count += 1
    count2 = 0
    for command in session.basic_args:
        count2 += 1
        if command.find('-o') == -1:
            if (count - count2) != 0:
                session.command_line += command + ' '
            else:
                session.command_line += command
    try:
        session.process = subprocess.Popen(session.basic_args,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        session.result = 'There was an error when executing the scan.'
        redirect(URL('scan_result'))
    return redirect(URL('scanning'))

def abort():

    try:
        cpid = str(int(session.process.pid) + 1)
        try: # Attempting to kill the child process of the sudo version of the nmap scan
            subprocess.call(["sudo","kill",cpid])
        except:
            pass
        session.process.kill() # Killing the main nmap process
        result = "Scan aborted successfully."
    except:
        result = "Scan did not abort successfully. It was probably already completed."
        pass
    return dict(result=result,command=session.command_line)

def help_page():
    return dict()

def scanning():
    session.result = ''
    try:
        if session.process.poll() is not None: # Checking if the scan has completed
            redirect(URL('scan_result'))
        else:
            pass
    except subprocess.CalledProcessError:
        pass
    return dict()

@cache.action()
def download():
    """
    allows downloading of uploaded files
    http://..../[app]/default/download/[filename]
    """
    return response.download(request, db)


def call():
    """
    exposes services. for example:
    http://..../[app]/default/call/jsonrpc
    decorate with @services.jsonrpc the functions to expose
    supports xml, json, xmlrpc, jsonrpc, amfrpc, rss, csv
    """
    return service()

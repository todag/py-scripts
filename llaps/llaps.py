#!/bin/python3
#
#MIT License
#
#Copyright (c) 2020 https://github.com/todag
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

import ldap, ldap.sasl
import os
import datetime
import syslog
import sys
import subprocess
import random
import string
import crypt
import argparse

#
# Set som default variables, these can instead be set by command line arguments
#
scriptVersion = '0.4 2020-04-25'
pwd_length = 15     # Length of the new password
pwd_max_age = 30    # When setting a new password, set it to expire in this many days
user_name = 'root'  # Name of the local account to reset password on
log_level = 3       # What to log to syslog, 1=errors, 2=informational, 3=debug
ldap_server = 'domain.local'
search_base = 'dc=domain,dc=local'
hostname = os.uname()[1].split('.', 1)[0]

#
# Parse command line arguments
#
parser = argparse.ArgumentParser()
parser.add_argument('--ldapserver', help='domain controller to bind to', type=str)
parser.add_argument('--loglevel',   help='set loglevel 1=errors, 2=informational, 3=debug', type=int, choices=[1, 2, 3])
parser.add_argument('--searchbase', help='set searchbase', type=str)
parser.add_argument('--username',   help='set username for the account for which the password will be reset', type=str)
parser.add_argument('--pwdmaxage',  help='set max age of password, password will be reset after this many days', type=int)
parser.add_argument('--pwdlength',  help='set number of characters in the generated password', type=int)
parser.add_argument('--force',      help='force immediate change of password', action='store_true')
parser.add_argument('--showpass',   help='show password in console output', action='store_true')
parser.add_argument('--nosyslog',   help='disable logging to syslog', action='store_true')
args = parser.parse_args()
if(args.loglevel):
    log_level = args.loglevel
if(args.ldapserver):
    ldap_server = args.ldapserver
if(args.searchbase):
    search_base = args.searchbase
if(args.username):
    user_name = args.username
if(args.pwdmaxage):
    pwd_max_age = args.pwdmaxage
if(args.pwdlength):
    pwd_length = args.pwdlength

#
# Function to log to syslog and console
#
def log(log_string):
    if not args.nosyslog and log_string.startswith(('[CRITICAL]', '[ERROR]')) and log_level >= 1 or \
       not args.nosyslog and log_string.startswith(('[WARNING]', '[NOTICE]', '[INFO]')) and log_level >= 2 or \
       not args.nosyslog and log_string.startswith('[DEBUG]') and log_level >= 3:
        print ('[LOG_TO_SYSLOG]: ' + log_string)
        syslog.syslog(syslog.LOG_INFO, 'LLAPS: ' + log_string)
    else:
        print('[LOG_TO_CONSOLE]: ' + log_string)
        return

#
# Generate a random password
#
def generate_password():
    pwd_chars = string.ascii_letters + string.digits + '!"#%&/[]-_@.,:$'
    pwd = ''.join(random.choice(pwd_chars) for i in range(pwd_length))
    if args.showpass:
        print('[LOG_TO_CONSOLE]: [PASSWORD] The generated password is: {}'.format(pwd))
    return pwd

log('[DEBUG] Script version {} Running on host {}'.format(scriptVersion, hostname))
log('[DEBUG] Options: log_level={}, ldap_server={}, search_base={}'.format(log_level, ldap_server, search_base))
log('[DEBUG] Options: user_name={}, pwd_max_age={}, pwd_length={}'.format(user_name, pwd_max_age, pwd_length))
log('[DEBUG] Options: force_change={}, show_pass={}'.format(args.force, args.showpass))

#
# Check if we have a Kerberos ticket. If not request one with a short lifetime.
#
if subprocess.call(['klist', '-s']) == 1:
    if subprocess.call(['kinit', '-k', '-l', '5m', '-t', '/etc/krb5.keytab', 'host/' + hostname]) == 0:
        log('[DEBUG] Successfully requested a Kerberos ticket')
    else:
        log('[ERROR] Requesting Kerberos ticket failed! Script will terminate!')
        sys.exit()
else:
    log('[DEBUG] Found existing valid Kerberos ticket!')

#
# Setup the LDAP connection
#
try:
    con = ldap.initialize('ldap://' + ldap_server)
    con.set_option(ldap.OPT_REFERRALS,0)
    con.set_option(ldap.OPT_X_SASL_SSF_MIN, 128)
    con.sasl_interactive_bind_s("", ldap.sasl.gssapi(''))
except Exception as e:
    log('[ERROR] Failed to bind to server with error: {}'.format(e))
    con.unbind()
    sys.exit()

#
# Connect to ldap and search for computer
#
try:
    res = con.search_s(search_base, ldap.SCOPE_SUBTREE, "sAMAccountName={}".format(hostname+'$'), ['ms-Mcs-AdmPwdExpirationTime','ms-Mcs-AdmPwd'])
    host_dn = str(res[0][0])
    if host_dn == 'None':
        log('[ERROR] LDAP search returned no valid results!')
        con.unbind()
        sys.exit()
except Exception as e:
    log('[ERROR] Unhandled exception while connecting to ldap: {}'.format(repr(e)),syslog.LOG_ERR)
    con.unbind()
    sys.exit()

#
# Read the 'ms-Mcs-AdmPwdExpirationTime' attribute which contains a Windows FileTime signaling
# when the password is to expire and convert it to a datetime object.
#
try:
    ft_pwd_expires=int(res[0][1]['ms-Mcs-AdmPwdExpirationTime'][0].decode('utf-8'))
    pwd_expires = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=ft_pwd_expires/10000000)
    log('[DEBUG] Current password expires at ' + str(pwd_expires) + ' Attribute value=' + str(ft_pwd_expires))
except KeyError as e:
    # Assume KeyError means the attribute is empty, so set pwd_expires to datetime.now() to force immediate update
    # This should really only happen on the first run.
    pwd_expires = datetime.datetime.now() - datetime.timedelta(seconds=10)
    log('[WARNING] ' + repr(e) + ' Assuming the attribute is empty, setting pwd_expires to {}.'.format(str(pwd_expires)))
except Exception as e:
    log('[ERROR] Unhandled exception: {}. Terminating script.'.format(repr(e)))
    con.unbind()
    sys.exit()

#
# Check if it's time to change the password
#
if datetime.datetime.now() > pwd_expires or args.force:
    #
    # Ok, looks like it's time to change the password:
    # 1. Convert the new expiration date to Windows FileTime format
    # 2. Generate a new password
    # 3. Update the 'ms-Mcs-AdmPwdExpirationTime' attribute with the new expiration date
    # 4. Update the 'ms-Mcs-AdmPwd' attribute with the new password
    # 5. Change the local password
    #
    try:
        log('[DEBUG] Attempting to update password for DN {}'.format(str(host_dn)))
        #
        # Calculate new value for ms-Mcs-AdmPwdExpirationTime which must be in Windows FileTime format
        # Ie. number or 100-nanoseconds since 1601-01-01.
        #
        new_expiry = datetime.datetime.now() + datetime.timedelta(days=pwd_max_age)
        ft_new_expiry = round((new_expiry - datetime.datetime.strptime('1601-01-01', '%Y-%m-%d')).total_seconds() * 10000000)
        log('[DEBUG] Setting new password to expire in {} days, at {} Attribute value={}'.format(str(pwd_max_age),str(new_expiry),str(ft_new_expiry)))

        # Generate new password
        new_pwd = str(generate_password())

        # Update AD attribtues
        # We will have to trust that ldap.MOD_REPLACE works or throws if it fails.
        # There is no way to re-read the ms-Mcs-AdmPwd attribute to see if it's
        # been set correctly since by default, the computer account cannot read
        # this attribute, only replace it.
        #
        con.modify_s(host_dn, [
            (ldap.MOD_REPLACE, 'ms-Mcs-AdmPwdExpirationTime', str(ft_new_expiry).encode('utf-8')),
            (ldap.MOD_REPLACE, 'ms-Mcs-AdmPwd', str(new_pwd).encode('utf-8'))
            ])

        # Change local password
        if subprocess.call(['usermod', '-p', crypt.crypt(new_pwd, crypt.mksalt()), user_name]) == 0:
            log('[INFO] Password changed successfully!')
        else:
            log('[CRITICAL] Failed setting local password after updating attribute, passwords are probably inconsistent!')
            con.unbind()
            sys.exit()

    except Exception as e:
        log('[CRITICAL] Unhandled exception: {}. Local and remote passwords might be inconsistent!'.format(repr(e)))
        con.unbind()
        sys.exit()
else:
    delta = datetime.datetime.now() - pwd_expires
    log('[INFO] It is not necessary to change password yet. Days to change: {}.'.format(str(delta.days).replace('-','')))
    con.unbind()
    sys.exit()

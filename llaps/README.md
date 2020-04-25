# LLAPS
Linux LAPS implementation written in Python.

This script will periodically reset the local administrator password, usually the 'root' account on Linux, and store it in Active Directory. It will bind to AD with SASL/GSSAPI using the hosts kerberos keytab so it can establish a secure and encrypted connection without the use of certificates.

## This is the script workflow:
* Request a Kerberos ticket.
* Establish an ldap connection and retrieve the value of the 'ms-Mcs-AdmPwdExpirationTime' attribute which contains the time when the password expires.
* If the value of the attribute is < datetime.now(), ie the password has expired it will:
  * Generate a new password
  * Write it to the 'ms-Mcs-AdmPwd' attribute
  * Update the 'ms-Mcs-AdmPwdExpirationTime' with datetime.now() + 30d
  * Reset the local 'root' password with the generated password.

## Prerequisites
LAPS requires extending the Active Directory schema, read Microsofts documentation. If you have the Windows version of LAPS working, this script will also work.
Be sure permissions are set on the OU where you Linux hosts are placed (Set-AdmPwdComputerSelfPermission -Identity “OU Name”).

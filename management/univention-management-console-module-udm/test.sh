#!/bin/bash
# Univention Management Console
#  Univention Directory Manager Module
#
# Copyright 2017-2019 Univention GmbH
#
# http://www.univention.de/
#
# All rights reserved.
#
# The source code of this program is made available
# under the terms of the GNU Affero General Public License version 3
# (GNU AGPL V3) as published by the Free Software Foundation.
#
# Binary versions of this program provided by Univention to you as
# well as other copyrighted, protected or trademarked materials like
# Logos, graphics, fonts, specific documentations and configurations,
# cryptographic keys etc. are subject to a license agreement between
# you and Univention and not subject to the GNU AGPL V3.
#
# In the case you use this program under the terms of the GNU AGPL V3,
# the program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <http://www.gnu.org/licenses/>.
# shortcut to test some requests

# ucr set security/packetfilter/package/univention-udm/tcp/8888/all=ACCEPT
# Folgende Apache Regel ist notwendig in univention.conf:
# <LocationMatch "^/univention/(udm/.*)">
#        ProxyPassMatch http://127.0.0.1:8888/$1 retry=0 timeout=311
#</LocationMatch>


host="10.200.27.20"
#host="192.168.188.129"
base="http://Administrator:univention@$host:8888/udm"
ldap_base="dc%3Dschool%2Cdc%3Dlocal"
ldap_base="dc%3Dfbest%2Cdc%3Ddev"
ldap_base="dc%3Ddev%2Cdc%3Dlocal"

_curl() {
	curl -s -f "$@" > /dev/null || echo curl "$@"
}

_curl -i "$base/"
_curl -i "$base/users/"
_curl -i "$base/computers/"
_curl -i "$base/navigation/"
_curl -i "$base/users/user/"
_curl -i "$base/users/user/options"
_curl -i "$base/users/user/templates"
_curl -i "$base/users/user/default-containers"
_curl -i "$base/users/user/containers"
_curl -i "$base/users/user/policies"
_curl -i "$base/users/user/report-types"
curl -s -f "$base/users/user/report/PDF%20Document/?dn=uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base&dn=uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base" | file - | grep -q PDF || echo "PDF-Report-fail"
curl -s -f "$base/users/user/report/CSV%20Report/?dn=uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base&dn=uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base" | file - | grep -q ASCII || echo "CSV-Report-fail"
_curl -i "$base/users/user/properties/mailPrimaryAddress/default"
_curl -i "$base/users/user/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base/properties/"
_curl -i "$base/users/user/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base/properties/primaryGroup/choices"
_curl -i "$base/users/user/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base/policies/umc/"
_curl -i "$base/users/user/policies/umc/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base/"
_curl -i "$base/users/user/policies/umc/cn%3Dusers%2C$ldap_base/?container=yes"
_curl -i "$base/users/user/policies/umc/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base/?policy=cn%3Ddefault-umc-users%2Ccn%3DUMC%2Ccn%3Dpolicies%2C$ldap_base"
_curl -i "$base/users/user/policies/umc/cn%3Dusers%2C$ldap_base/?container=yes&policy=cn%3Ddefault-umc-users%2Ccn%3DUMC%2Ccn%3Dpolicies%2C$ldap_base"
_curl -i "$base/users/user/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base/layout"

# search for users:
_curl -i "$base/users/user/"

# create a user:
_curl -XPOST -i "$base/users/user/" -H 'Content-Type: application/json' -d '{"container":"cn=users,dc=dev,dc=local","objectType":"users/user","objectTemplate":null, "disabled":false,"lastname":"Lastname","password":"univention","oxTimeZone":"Europe/Berlin","oxDisplayName":"Firstname Lastname","unlock":false,"oxLanguage":"de_DE","mailForwardCopyToSelf":"0","overridePWHistory":false,"pwdChangeNextLogin":false,"primaryGroup":"cn=Domain Users,cn=groups,dc=dev,dc=local","username":"Username'$RANDOM'","shell":"/bin/bash","mailHomeServer":"master20.dev.local","oxAccess":"premium","mailUserQuota":"0","homeSharePath":"Username","unixhome":"/home/Username","firstname":"Firstname","overridePWLength":false,"displayName":"Firstname Lastname","options": ["oxUser"], "$options$":{"oxUser":true,"owncloudEnabled":true,"pki":false}}'

# get a specific user:
_curl -i "$base/users/user/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base"

# modify a specific user:
#_curl -X PUT -i "$base/users/user/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base"
#_curl -X PATCH -i "$base/users/user/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base"
#
## remove a specific user:
#_curl -X DELETE -i "$base/users/user/uid%3DAdministrator%2Ccn%3Dusers%2C$ldap_base"

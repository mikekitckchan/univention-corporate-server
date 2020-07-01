#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
#
# Copyright 2020 Univention GmbH
#
# https://www.univention.de/
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
# <https://www.gnu.org/licenses/>.

from univention.unittests import import_module
misc = import_module('misc', 'python/', 'univention.lib.misc')


def test_username():
	assert misc.custom_username('name') == 'name'
	assert misc.custom_username('domain admin', {'users/default/domainadmin': 'new_name'}) == 'new_name'


def test_groupname():
	assert misc.custom_groupname('name') == 'name'
	assert misc.custom_groupname('domain admins', {'groups/default/domainadmins': 'new_name'}) == 'new_name'


def test_password():
	# TODO: mock subprocess?
	assert len(misc.createMachinePassword()) == 20


def test_ldap_uris():
	pass


def test_ldap_servers():
	pass

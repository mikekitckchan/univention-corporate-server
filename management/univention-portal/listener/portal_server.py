#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
#
# Copyright 2017-2018 Univention GmbH
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

__package__ = ''  # workaround for PEP 366

from univention.config_registry import ConfigRegistry

ucr = ConfigRegistry()
ucr.load()

name = 'portal_server'
description = 'Tell portal server to refresh when something important changed'
filter = '(|(univentionObjectType=settings/portal)(univentionObjectType=settings/portal_category)(univentionObjectType=settings/portal_entry)(&(objectClass=univentionPortalComputer)(cn=%s)))' % ucr.get('hostname')
attributes = []

def handler(dn, new, old):
	open('/var/cache/univention-portal/refresh', 'w')

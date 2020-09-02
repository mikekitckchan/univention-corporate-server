#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
#
# Copyright 2020 Univention GmbH
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

import click
import os
import json


L10_FOLDER = "/usr/share/univention-customize-texts/l10n-files"
OVERWRITE_FOLDER = "/usr/share/univention-customize-texts/overwrites"


def parse_l10_file(file):
	with open(file) as fp:
		data = json.load(fp)
		for entry in data:
			yield "/{}".format(entry["destination"])


@click.command(help="Lists all possible packages")
def list_packages():
	"""
		lists all possible packages

	:return:
	"""
	assert os.path.isdir(L10_FOLDER)
	for file in os.listdir(L10_FOLDER):
		package = os.path.splitext((os.path.basename(file)))[0]
		for destination in parse_l10_file(os.path.join(L10_FOLDER, file)):
			click.echo("{}:{}".format(package, destination))

@click.command(help="Lists all overwrites")
def list_overwrites():
	for sub in os.listdir(OVERWRITE_FOLDER):
		if os.path.isdir(os.path.join(OVERWRITE_FOLDER, sub)):
			result = [os.path.join(dp, f) for dp, dn, filenames in os.walk(OVERWRITE_FOLDER) for f in filenames if
			          os.path.splitext(f)[1] == '.json']
			for file in result:
				locale = os.path.basename(os.path.dirname(file))
				print("{} {}".format(sub, locale))
				if 'diff' in file:
					with open(file) as fp:
						data = json.load(fp)
						for key in data:
							print("\t'{}' {} '{}'".format(key, locale, data[key]))


if __name__ == '__main__':
	# list_packages()
	list_overwrites()

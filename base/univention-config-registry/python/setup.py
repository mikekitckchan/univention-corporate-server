# -*- coding: utf-8 -*-

#
# Use only Python 2 and 3 compatible code here!
#

#
# Install: pip3 install .
#

import atexit
from email.utils import parseaddr
import io
import os

import setuptools
from debian.changelog import Changelog
from debian.deb822 import Deb822
from setuptools.command.install import install


class CustomInstall(install):
    """create required directories after installation"""
    def run(self):
        def _post_install():
            try:
                os.mkdir("/etc/univention")
            except OSError:
                pass
            try:
                os.mkdir("/var/cache/univention-config")
            except OSError:
                pass

        atexit.register(_post_install)
        install.run(self)


# path /tmp/univention-config-registry created during Docker build
dch = Changelog(io.open("/tmp/univention-config-registry/debian/changelog", "r", encoding="utf-8"))
dsc = Deb822(io.open("/tmp/univention-config-registry/debian/control", "r", encoding="utf-8"))
realname, email_address = parseaddr(dsc["Maintainer"])


setuptools.setup(
    name=dch.package,
    version=dch.version.full_version,
    maintainer=realname,
    maintainer_email=email_address,
    description="Python interface to configuration registry",
    long_description="Python interface to configuration registry",
    url="https://www.univention.de/",
    install_requires=["six"],
    packages=["univention", "univention.config_registry"],
    scripts=["univention-config-registry"],
    license="GNU Affero General Public License v3",
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: OS Independent",
    ],
    cmdclass={
        "develop": CustomInstall,
        "install": CustomInstall,
    },
)

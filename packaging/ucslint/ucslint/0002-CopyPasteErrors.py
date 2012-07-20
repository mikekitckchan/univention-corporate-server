# -*- coding: iso-8859-15 -*-

try:
	import univention.ucslint.base as uub
except:
	import ucslint.base as uub
import re, os

# 1) check if strings like "dc=univention,dc=qa" appear in debian/* and conffiles/*
# 2) check if strings like "univention.qa" appear in debian/* and conffiles/*

class UniventionPackageCheck(uub.UniventionPackageCheckDebian):
	def __init__(self):
		super(UniventionPackageCheck, self).__init__()
		self.name = '0002-CopyPasteErrors'

	def getMsgIds(self):
		return { '0002-1': [ uub.RESULT_WARN, 'cannot open file' ],
				 '0002-2': [ uub.RESULT_ERROR, 'found basedn used in QA' ],
				 '0002-3': [ uub.RESULT_ERROR, 'found domainname used in QA' ],
				 }

	def postinit(self, path):
		""" checks to be run before real check or to create precalculated data for several runs. Only called once! """
		pass

	def check(self, path):
		""" the real check """
		super(UniventionPackageCheck, self).check(path)

		fnlist_joinscripts = {}

		files = []
		# scan directory only
		for dir in [ 'debian' ]:
			for fn in os.listdir( os.path.join(path, dir) ):
				self.debug( os.path.join(path, dir, fn) )
				if not os.path.isdir( os.path.join(path, dir, fn) ):
					files.append( os.path.join( path, dir, fn ) )

		# scan directory recursively
		for dir in [ 'conffiles' ]:
			for dirpath, dirnames, filenames in os.walk( os.path.join(path, dir) ):
				if '/.svn/' in dirpath or dirpath.endswith('/.svn'):   # ignore svn files
					continue
				for fn in filenames:
					files.append( os.path.join( dirpath, fn ) )

		for fn in files:
			try:
				content = open(fn, 'r').read()
			except:
				self.addmsg( '0002-1', 'failed to open and read file', fn )
				continue

			for txt in [ 'dc=univention,dc=local', 'dc=univention,dc=qa', 'dc=univention,dc=test' ]:
				for line in self._searchString(content, txt):
					self.addmsg( '0002-2', 'contains invalid basedn', fn, line )

			for txt in [ 'univention.local', 'univention.qa', 'univention.test' ]:
				for line in self._searchString(content, txt):
					self.addmsg( '0002-3', 'contains invalid domainname', fn, line )


	def _searchString(self, content, txt):
		result = []
		flen = len(content)
		pos = 0
		while pos < flen:
			fpos = content.find( txt, pos )
			if fpos < 0:
				pos = flen+1
			else:
				line = content.count('\n', 0, fpos) + 1
				pos = fpos + len(txt) - 1
				result.append( line )
		return result

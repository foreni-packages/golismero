#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
$Id$

This file is part of the xsser project, http://xsser.sourceforge.net.

Copyright (c) 2011/2012 psy <root@lordepsylon.net> - <epsylon@riseup.net>

xsser is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 3 of the License.

xsser is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with xsser; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
from XSSer.main import xsser

class NullOutput(object):
    def write(self, text):
        pass
    def flush(self):
        pass

if __name__ == "__main__":
    app = xsser()
    options = app.create_options()
    if options:
        app.set_options(options)
        app.run()
    app.land(True)



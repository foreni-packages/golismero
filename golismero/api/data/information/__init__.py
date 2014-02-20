#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Information types.
"""

__license__ = """
GoLismero 2.0 - The web knife - Copyright (C) 2011-2013

Authors:
  Daniel Garcia Garcia a.k.a cr0hn | cr0hn<@>cr0hn.com
  Mario Vilas | mvilas<@>gmail.com

Golismero project site: https://github.com/golismero
Golismero project mail: golismero.project<@>gmail.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

__all__ = ["Information", "File", "Asset", "Capture", "Fingerprint"]

from .. import Data


#------------------------------------------------------------------------------
class Information(Data):
    """
    Base class for informational results.
    """


    #--------------------------------------------------------------------------
    # Categories of informational data.
    CATEGORY_UNKNOWN     = 0    # Not a real value!
    CATEGORY_FILE        = 1
    CATEGORY_ASSET       = 2
    CATEGORY_CAPTURE     = 3
    CATEGORY_FINGERPRINT = 4


    #--------------------------------------------------------------------------
    # Types of informational data.

    INFORMATION_UNKNOWN = 0  # Not a real value!

    # File Data: raw file contents.
    INFORMATION_HTML             = 1000  # HTML source code
    INFORMATION_FORM             = 1001  # HTML form
    INFORMATION_PLAIN_TEXT       = 1002  # Text file
    INFORMATION_BINARY           = 1003  # Binary file of unknown type
    ##INFORMATION_EXECUTABLE       = 1004  # Executable file (various platforms)
    INFORMATION_IMAGE            = 1005  # Image file
    ##INFORMATION_VIDEO            = 1006  # Video file
    ##INFORMATION_PDF              = 1007  # PDF file
    ##INFORMATION_FLASH            = 1008  # Flash file
    ##INFORMATION_DOCUMENT         = 1009  # Document file (various formats)

    # Assets: sensitive information captured from the targets.
    INFORMATION_USERNAME         = 1100  # Username
    INFORMATION_PASSWORD         = 1101  # Password
    ##INFORMATION_DATABASE_DUMP    = 1102  # Database dump in SQL format

    # Protocol captures: raw network protocol dumps.
    INFORMATION_HTTP_REQUEST     = 1200  # HTTP request
    INFORMATION_HTTP_RAW_REQUEST = 1201  # Raw HTTP request
    INFORMATION_HTTP_RESPONSE    = 1202  # HTTP response
    INFORMATION_DNS_REGISTER     = 1212  # DNS responses

    # Fingerprints: reconnaissance results.
    INFORMATION_WEB_SERVER_FINGERPRINT = 1300  # HTTP server fingerprint
    ##INFORMATION_WEB_APP_FINGERPRINT    = 1301  # Web application fingerprint
    INFORMATION_SERVICE_FINGERPRINT    = 1302  # Network service fingerprint
    INFORMATION_OS_FINGERPRINT         = 1303  # Operating system fingerprint
    INFORMATION_PORTSCAN               = 1304  # Portscan results
    INFORMATION_TRACEROUTE             = 1306  # Traceroute results
    INFORMATION_GEOLOCATION            = 1307  # Geographic location
    INFORMATION_BANNER                 = 1308  # Service banner
    INFORMATION_ASN                    = 1309  # ASN (ISP)


    #--------------------------------------------------------------------------

    data_type = Data.TYPE_INFORMATION
    information_type = INFORMATION_UNKNOWN
    information_category = CATEGORY_UNKNOWN


#------------------------------------------------------------------------------
class File(Information):
    """
    Base class for file data.
    """

    information_category = Information.CATEGORY_FILE


#------------------------------------------------------------------------------
class Asset(Information):
    """
    Base class for assets.
    """

    information_category = Information.CATEGORY_ASSET


#------------------------------------------------------------------------------
class Capture(Information):
    """
    Base class for protocol captures.
    """

    information_category = Information.CATEGORY_CAPTURE


#------------------------------------------------------------------------------
class Fingerprint(Information):
    """
    Base class for fingerprints.
    """

    information_category = Information.CATEGORY_FINGERPRINT

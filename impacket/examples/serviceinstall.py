# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Service Install Helper library used by psexec and smbrelayx
#   You provide an already established connection and an exefile
#   (or class that mimics a file class) and this will install and
#   execute the service, and then uninstall (install(), uninstall().
#   It tries to take care as much as possible to leave everything clean.
#
# Author:
#   Alberto Solino (@agsolino)
#

import os
import random

from impacket.dcerpc.v5 import transport, srvs, scmr
from impacket import smb,smb3, LOG
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_WRITE_DATA, FILE_DIRECTORY_FILE

# When no explicit service/binary name is supplied, impacket historically generated
# a random 4-char service name and an 8-char binary name. A purely random alpha
# string is itself an IOC (defenders flag the short high-entropy names psexec leaves
# behind). These pools of plausible-looking names blend in instead. They are chosen
# to resemble real Windows service infrastructure WITHOUT colliding with actual
# built-in services (collision would make the create fail).
#   IMPACKET_SERVICE_NAME       - pin one exact service name
#   IMPACKET_BINARY_NAME        - pin one exact binary name (.exe appended if missing)
#   IMPACKET_SERVICE_NAME_POOL  - comma-separated pool to pick from
#   IMPACKET_BINARY_NAME_POOL   - comma-separated pool to pick from
_DEFAULT_SERVICE_POOL = ['WinErrReport', 'NetProfMgr', 'TrustedHostSvc', 'WdiServiceHost',
                         'AppReadinessSvc', 'DiagTrackHelper', 'SysMainHelper', 'UsoSvcHost']
_DEFAULT_BINARY_POOL  = ['hostsvc', 'wdiwrap', 'netprof', 'trustedhost',
                         'appready', 'diagtrack', 'sysmainhost', 'usosvc']


def _name_pool(env_name, default):
    raw = os.environ.get(env_name)
    if raw:
        chosen = [x.strip() for x in raw.split(',') if x.strip()]
        if chosen:
            return chosen
    return default


def _benign_service_name():
    return os.environ.get('IMPACKET_SERVICE_NAME') or \
        random.choice(_name_pool('IMPACKET_SERVICE_NAME_POOL', _DEFAULT_SERVICE_POOL))


def _benign_binary_name():
    name = os.environ.get('IMPACKET_BINARY_NAME')
    if not name:
        name = random.choice(_name_pool('IMPACKET_BINARY_NAME_POOL', _DEFAULT_BINARY_POOL))
    return name if name.lower().endswith('.exe') else name + '.exe'


class ServiceInstall:
    def __init__(self, SMBObject, exeFile, serviceName='', binary_service_name=None):
        self._rpctransport = 0
        self.__service_name = serviceName if len(serviceName) > 0 else _benign_service_name()

        if binary_service_name is None:
            self.__binary_service_name = _benign_binary_name()
        else:
            self.__binary_service_name = binary_service_name
            
        self.__exeFile = exeFile

        # We might receive two different types of objects, always end up
        # with a SMBConnection one
        if isinstance(SMBObject, smb.SMB) or isinstance(SMBObject, smb3.SMB3):
            self.connection = SMBConnection(existingConnection = SMBObject)
        else:
            self.connection = SMBObject

        self.share = ''

    @property
    def serviceName(self):
        return self.__service_name

    @property
    def binaryServiceName(self):
        return self.__binary_service_name

    def getShare(self):
        return self.share

    def getShares(self):
        # Setup up a DCE SMBTransport with the connection already in place
        LOG.info("Requesting shares on %s....." % (self.connection.getRemoteHost()))
        try:
            self._rpctransport = transport.SMBTransport(self.connection.getRemoteHost(),
                                                        self.connection.getRemoteHost(),filename = r'\srvsvc',
                                                        smb_connection = self.connection)
            dce_srvs = self._rpctransport.get_dce_rpc()
            dce_srvs.connect()

            dce_srvs.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareEnum(dce_srvs, 1)
            return resp['InfoStruct']['ShareInfo']['Level1']
        except:
            LOG.critical("Error requesting shares on %s, aborting....." % (self.connection.getRemoteHost()))
            raise


    def createService(self, handle, share, path):
        LOG.info("Creating service %s on %s....." % (self.__service_name, self.connection.getRemoteHost()))

        # First we try to open the service in case it exists. If it does, we remove it.
        try:
            resp =  scmr.hROpenServiceW(self.rpcsvc, handle, self.__service_name+'\x00')
        except Exception as e:
            if str(e).find('ERROR_SERVICE_DOES_NOT_EXIST') >= 0:
                # We're good, pass the exception
                pass
            else:
                raise e
        else:
            # It exists, remove it
            scmr.hRDeleteService(self.rpcsvc, resp['lpServiceHandle'])
            scmr.hRCloseServiceHandle(self.rpcsvc, resp['lpServiceHandle'])

        # Create the service
        command = '%s\\%s' % (path, self.__binary_service_name)
        try:
            resp = scmr.hRCreateServiceW(self.rpcsvc, handle,self.__service_name + '\x00', self.__service_name + '\x00',
                                         lpBinaryPathName=command + '\x00', dwStartType=scmr.SERVICE_DEMAND_START)
        except:
            LOG.critical("Error creating service %s on %s" % (self.__service_name, self.connection.getRemoteHost()))
            raise
        else:
            return resp['lpServiceHandle']

    def openSvcManager(self):
        LOG.info("Opening SVCManager on %s....." % self.connection.getRemoteHost())
        # Setup up a DCE SMBTransport with the connection already in place
        self._rpctransport = transport.SMBTransport(self.connection.getRemoteHost(), self.connection.getRemoteHost(),
                                                    filename = r'\svcctl', smb_connection = self.connection)
        self.rpcsvc = self._rpctransport.get_dce_rpc()
        self.rpcsvc.connect()
        self.rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
        try:
            resp = scmr.hROpenSCManagerW(self.rpcsvc)
        except:
            LOG.critical("Error opening SVCManager on %s....." % self.connection.getRemoteHost())
            raise Exception('Unable to open SVCManager')
        else:
            return resp['lpScHandle']

    def copy_file(self, src, tree, dst):
        LOG.info("Uploading file %s" % dst)
        if isinstance(src, str):
            # We have a filename
            fh = open(src, 'rb')
        else:
            # We have a class instance, it must have a read method
            fh = src
        f = dst
        pathname = f.replace('/','\\')
        try:
            self.connection.putFile(tree, pathname, fh.read)
        except:
            LOG.critical("Error uploading file %s, aborting....." % dst)
            raise
        fh.close()

    def findWritableShare(self, shares):
        # Check we can write a file on the shares, stop in the first one
        writeableShare = None
        for i in shares['Buffer']:
            if i['shi1_type'] == srvs.STYPE_DISKTREE or i['shi1_type'] == srvs.STYPE_SPECIAL:
               share = i['shi1_netname'][:-1]
               tid = 0
               try:
                   tid = self.connection.connectTree(share)
                   self.connection.openFile(tid, '\\', FILE_WRITE_DATA, creationOption=FILE_DIRECTORY_FILE)
               except:
                   LOG.debug('Exception', exc_info=True)
                   LOG.critical("share '%s' is not writable." % share)
                   pass
               else:
                   LOG.info('Found writable share %s' % share)
                   writeableShare = str(share)
                   break
               finally:
                   if tid != 0:
                       self.connection.disconnectTree(tid)
        return writeableShare

    def install(self):
        if self.connection.isGuestSession():
            LOG.critical("Authenticated as Guest. Aborting")
            self.connection.logoff()
            del self.connection
        else:
            fileCopied = False
            serviceCreated = False
            # Do the stuff here
            try:
                # Let's get the shares
                shares = self.getShares()
                self.share = self.findWritableShare(shares)
                if self.share is None:
                    return False
                self.copy_file(self.__exeFile ,self.share,self.__binary_service_name)
                fileCopied = True
                svcManager = self.openSvcManager()
                if svcManager != 0:
                    serverName = self.connection.getServerName()
                    if self.share.lower() == 'admin$':
                        path = '%systemroot%'
                    else:
                        if serverName != '':
                           path = '\\\\%s\\%s' % (serverName, self.share)
                        else:
                           path = '\\\\127.0.0.1\\' + self.share
                    service = self.createService(svcManager, self.share, path)
                    serviceCreated = True
                    if service != 0:
                        # Start service
                        LOG.info('Starting service %s.....' % self.__service_name)
                        try:
                            scmr.hRStartServiceW(self.rpcsvc, service)
                        except:
                            pass
                        scmr.hRCloseServiceHandle(self.rpcsvc, service)
                    scmr.hRCloseServiceHandle(self.rpcsvc, svcManager)
                    return True
            except Exception as e:
                LOG.critical("Error performing the installation, cleaning up: %s" %e)
                LOG.debug("Exception", exc_info=True)
                try:
                    scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
                except:
                    pass
                if fileCopied is True:
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
                if serviceCreated is True:
                    try:
                        scmr.hRDeleteService(self.rpcsvc, service)
                    except:
                        pass
            return False

    def uninstall(self):
        fileCopied = True
        serviceCreated = True
        # Do the stuff here
        try:
            # Let's get the shares
            svcManager = self.openSvcManager()
            if svcManager != 0:
                resp = scmr.hROpenServiceW(self.rpcsvc, svcManager, self.__service_name+'\x00')
                service = resp['lpServiceHandle']
                LOG.info('Stopping service %s.....' % self.__service_name)
                try:
                    scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
                except:
                    pass
                LOG.info('Removing service %s.....' % self.__service_name)
                scmr.hRDeleteService(self.rpcsvc, service)
                scmr.hRCloseServiceHandle(self.rpcsvc, service)
                scmr.hRCloseServiceHandle(self.rpcsvc, svcManager)
            LOG.info('Removing file %s.....' % self.__binary_service_name)
            self.connection.deleteFile(self.share, self.__binary_service_name)
        except Exception:
            LOG.critical("Error performing the uninstallation, cleaning up" )
            try:
                scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
            except:
                pass
            if fileCopied is True:
                try:
                    self.connection.deleteFile(self.share, self.__binary_service_name)
                except:
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
                    pass
            if serviceCreated is True:
                try:
                    scmr.hRDeleteService(self.rpcsvc, service)
                except:
                    pass

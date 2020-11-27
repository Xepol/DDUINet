Unit DDU.Inet.Socket.Consts;

//*****************************************************************************
//
// DDUINET (DDU.Inet.Socket.Consts)
// Copyright 2020 Clinton R. Johnson (xepol@xepol.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Version : 1.0
//
// Purpose :
//
// History : <none>
//
//*****************************************************************************

Interface

{$Define English}

{$IfDef English}
ResourceString
  sCannotCreateSocket       = 'Can''t create new socket';
  sCannotListenOnOpen       = 'Can''t listen on an open socket';
  sCantChangeWhileActive    = 'Can''t change value while socket is active';
  sClientCannotListen       = 'Client socket can not listen';
  sNoAddress                = 'No address specified';
  sNoSocket                 = 'No Socket created';
  sNoUDPProxy               = 'Proxy not supported for UDP';
  sServerCannotOpen         = 'Server socket can not open';
  sSocketAlreadyOpen        = 'Socket already open';
  sUDPBroadcastCannotListen = 'UDP Broadcast sockets can not listen.';
  sWindowsSocketError       = 'Windows socket error: %s (%d), on API ''%s'''#13'%s';

ResourceString
  sWSANoError               = ' - No error';
  sWSAEINTR                 = ' - WSAEINTR (The (blocking) call was canceled via WSACancelBlockingCall())';
  sWSAEBADF                 = ' - WSAEBADF';
  sWSAEFAULT                = ' - WSAEFAULT (Call specific error)';
  sWSAEINVAL                = ' - WSAEINVAL (Call specific error)';
  sWSAEMFILE                = ' - WSAEMFILE (No more file descriptors are available)';
  sWSAEWOULDBLOCK           = ' - WSAEWOULDBLOCK (Call would block)';
  sWSAEINPROGRESS           = ' - WSAEINPROGRESS (Blocking call in progress)';
  sWSAEALREADY              = ' - WSAEALREADY (The asynchronous routine being canceled has already completed)';
  sWSAENOTSOCK              = ' - WSAENOTSOCK (The descriptor is not a socket)';
  sWSAEDESTADDRREQ          = ' - WSAEDESTADDRREQ (A destination address is required)';
  sWSAEMSGSIZE              = ' - WSAEMSGSIZE (The datagram was too large to fit into the specified buffer and was truncated)';
  sWSAEPROTOTYPE            = ' - WSAEPROTOTYPE (The specified protocol is the wrong type for this socket)';
  sWSAENOPROTOOPT           = ' - WSAENOPROTOOPT (The option is unknown or unsupported)';
  sWSAEPROTONOSUPPORT       = ' - WSAEPROTONOSUPPORT (The specified protocol is not supported)';
  sWSAESOCKTNOSUPPORT       = ' - WSAESOCKTNOSUPPORT (The specified socket type is not supported in this address family)';
  sWSAEOPNOTSUPP            = ' - WSAEOPNOTSUPP (Socket not of type that supports operation)';
  sWSAEPFNOSUPPORT          = ' - WSAEPFNOSUPPORT (Protocols in the specified family cannot be used with this socket)';
  sWSAEAFNOSUPPORT          = ' - WSAEAFNOSUPPORT (Addresses in the specified family cannot be used with this socket)';
  sWSAEADDRINUSE            = ' - WSAEADDRINUSE (The specified address is already in use)';
  sWSAEADDRNOTAVAIL         = ' - WSAEADDRNOTAVAIL (The specified address is not available from the local machine)';
  sWSAENETDOWN              = ' - WSAENETDOWN (Net down)';
  sWSAENETUNREACH           = ' - WSAENETUNREACH (Net unreachable)';
  sWSAENETRESET             = ' - WSAENETRESET (The connection must be reset because the Windows Sockets implementation dropped it)';
  sWSAECONNABORTED          = ' - WSAECONNABORTED (The virtual circuit was aborted due to timeout or other failure)';
  sWSAECONNRESET            = ' - WSAECONNRESET (The virtual circuit was reset by the remote side)';
  sWSAENOBUFS               = ' - WSAENOBUFS (No buffer space is available)';
  sWSAEISCONN               = ' - WSAEISCONN (The socket is already connected)';
  sWSAENOTCONN              = ' - WSAENOTCONN (The socket is not connected)';
  sWSAESHUTDOWN             = ' - WSAESHUTDOWN (The socket has been shutdown)';
  sWSAETOOMANYREFS          = ' - WSAETOOMANYREFS';
  sWSAETIMEDOUT             = ' - WSAETIMEDOUT (Operation failed due to timeout)';
  sWSAECONNREFUSED          = ' - WSAECONNREFUSED (Connection Refused)';
  sWSAELOOP                 = ' - WSAELOOP';
  sWSAENAMETOOLONG          = ' - WSAENAMETOOLONG';
  sWSAEHOSTDOWN             = ' - WSAEHOSTDOWN (Host down)';
  sWSAEHOSTUNREACH          = ' - WSAEHOSTUNREACH (Host unreachable)';
  sWSAENOTEMPTY             = ' - WSAENOTEMPTY';
  sWSAEPROCLIM              = ' - WSAEPROCLIM';
  sWSAEUSERS                = ' - WSAEUSERS';
  sWSAEDQUOT                = ' - WSAEDQUOT';
  sWSAESTALE                = ' - WSAESTALE';
  sWSAEREMOTE               = ' - WSAEREMOTE';
  sWSASYSNOTREADY           = ' - WSASYSNOTREADY (Network subsystem unstable)';
  sWSAVERNOTSUPPORTED       = ' - WSAVERNOTSUPPORTED (Version not supported)';
  sWSANOTINITIALISED        = ' - WSANOTINITIALISED (WinSock not initialized by call to WSAStartup())';
  sWSAHOST_NOT_FOUND        = ' - WSAHOST_NOT_FOUND (Authoritative Answer Host not found)';
  sWSATRY_AGAIN             = ' - WSATRY_AGAIN (Non authoritive answer, try again)';
  sWSANO_RECOVERY           = ' - WSANO_RECOVERY (Non recoverable error)';
  sWSANO_DATA               = ' - WSANO_DATA (Valid name, no data record of requested type)';
  sWSAUndefined             = ' - Undefined error';

ResourceString
  sDNSLinked                = 'DNS Control %s already linked to %s';
  sDNSCancelled             = 'DNS Cancelled';
  sDNSFailed                = 'No IP for hostname found';
  
ResourceString
  sSocks4ConnectError       = 'SOCKS4 connect version error : %d';
  sSocks4BindError          = 'SOCKS4 bind version error : %d';
  sSocks4BindConnectError   = 'SOCKS4 bind connect version error : %d';
  sSocks4Error91            = 'Request rejected or failed.';
  sSocks4Error92            = 'Request rejected because SOCKS server could not find identd on the client.';
  sSocks4Error93            = 'request rejected because the client program and identd report different user-ids';
  sSocks4ErrorUnknown       = 'unassigned SOCKS4 errror code : %d';
  sSocks5AuthError          = 'SOCKS5 authentication version error : %d';
  sSocks5AuthFailed         = 'SOCKS5 authentication failed';
  sSocks5ConnectError       = 'SOCKS5 connect version error : %d';
  sSocks5BindError          = 'SOCKS5 bind version error : %d';
  sSocks5BindConnectError   = 'SOCKS5 bind connect version error : %d';
  sSocks5MethodsError       = 'SOCKS5 methods version error : %d';
  sSocks5MethodsNoMethods   = 'No login methods available.';
  sSocks5MethodsUnknown     = 'Unknown SOCKS5 method';
  sSocks5IPV6Fail           = 'IP V6 not supported';
  sSocks5Error1             = 'General SOCKS server failure';
  sSocks5Error2             = 'Connection not allowed by ruleset';
  sSocks5Error3             = 'Network unreachable';
  sSocks5Error4             = 'Host unreachable';
  sSocks5Error5             = 'Connection refused';
  sSocks5Error6             = 'TTL Expired';
  sSocks5Error7             = 'Command not supported';
  sSocks5Error8             = 'Address type not supported';
  sSocks5ErrorUnknown       = 'unassigned SOCKS5 errror code : %d';

{$EndIf}

Implementation

end.


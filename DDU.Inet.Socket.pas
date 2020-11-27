unit DDU.Inet.Socket;

//*********************************************************************************************************************
//
// DDUINET (DDU.INet.Socket)
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
// Version : 5.0 ALPHA***
//
// History
//*****************
//
// Version 1.0 - November 1997 First release
//
//            - Uses sockets provided by Inprise.
//
// Version 2.0 - March 1999
//
//            - Custom written sockets implementation, replaced TTextSocket with TDDUSocket
//            - Ground up rewrite, totally restructured.
//            - Corrected previous logic error causing some errors during
//                connect to not issue a disconnect event.
//            - DNS can now be resolved in a linked non blockinging
//                TDDUCUSTOMDNS control.
//            - Throttle V1.0 added (speed meter, limiting, block sizes)
//            - Proxy support via a TDDUCustomProxyObject.
//            - SOCKS4,SOCKS5 Proxy support added.
//            - ACTIVE property is now read only.  Previously you would set the
//                active property to establish and terminate connections.  Now
//                use the CONNECT, DISCONNECT, SUDDENDISCONNECT methods.
//                ACTIVE now reflects the protocol is active, even during a
//                connection attempt, instead of simply being another connected flag.
//                Since using a seperate object to to DNS would delay attempting to connect,
//                this change was absolutely required.
//            - Made socket draining optional. With some fast connections, draining the
//                socket during a disconnect would result in a disconnect packet never
//                being issued.  SUDDENDISCONNECT causes the socket to not be drained
//                during a disconnect regardless of the DRAIN setting.
//
// Version 2.1 - February 2001
//
//            - Exposed InBuffer as a protected property for descendant objects
//
// Version 2.2 - March 2001
//
//            - Changed TDDUSocket to TCustomDDUSocket
//            - Added TDDUSocket with Connect/Disconnect exposed.
//            - Moved Connect,Disconnect to protected fields to allow
//                different session management routines in descendants.
//
// Version 2.3 - May 2001
//
//            - Added in OnAcceptEx
//            - Added Signals
//
// Version 2.4 - April 2002
//
//            - Added EndServer
//            - Added TSocketList
//            - Added Client list for unmanaged dispatch server.
//            - Added ClientCount
//            - Added DisconnectClients,SuddenDisconnectClients
//
// Version 2.4 - July 2002
//
//            - Changed order of Application.HandleException and SuddenDisconnect
//            - Removed unrequired USES references
//            - Moved TDataMode,TSocketMode,TSocketProcotol,TSocketOption,TSocketOptions,
//              TSocksMode,TTextMode,TTextModeSet to DDUSocketTypes
//            - Move SocketErrorMessage, CheckSocketResult to DDUSocketTypes
//
// Version 2.5 - February 2003
//
//            - Modified AcceptEX to provide an addition field for marking sockets as asynchronous
//            - Improved support for server dispatching of blocking, not TDDUSocket handled
//                sockets.
//
// Version 2.6 - January 2004
//
//             - Changed read functions from INTEGER to CARDINAL since negative data is never possible.
//
// Version 3.0 - October 2006
//
//             - Added support for block (file) based transfers with auto-initiation
//             - Extended control over throttle speed readings
//
// Version 3.1 - November 2006
//
//             - Dramatically improved UDP support.  SendTos are accomplished by assigning RemoteAddress
//               before sending data instead of just replying on direct ReplyTo.  SendTo Address is cached
//               as part of the output buffer so that REmoteAddress can be changed before the buffered packet
//               is sent.
//             - Added Redirection support to improve custom protocol support
//
//
// Version 3.2 - January 2008
//
//             - Added AbandonSocket and AdoptSocket to allow for handling handoffs.
//
// Version 4.0 - August 2013
//
//             - Change storage mechanism over to DDUBuffer from AnsiStrings to start unicode migration.
//             - Changed block events to more clearly communicate direction.
//                 OnBlockFinish   To OnBlockReceiveDone
//                 OnBlockStart    To OnBlockReceiveStart
//                 OnBlockArrived  To OnBlockReceiveStart
//                 OnBlockProgress To OnBlockReceiveProgress
//             - Added OnSendBlockStart to parallel OnBlockReceiveStart.  Just notifies you the block is about to
//                 start rolling out.  In theory, you could modify the stream just at this point.
//             - To improve direction clarity, the following block related items have been changed:
//                 CurrentBlockName   -> ReceiveCurrentBlockName
//                 CurrentBlockSize   -> ReceiveCurrentBlockSize
//                 CurrentBlockStream -> ReceiveCurrentBlockStream
//             - SendCurrent* items have been added to parallel the ReceiveCurrent* items
//             - To improve direction clarity, the following stream related items have been changed:
//                 Stream -> ReceiveStream
//             - To improve direction clarity, the following data handling routines have been renamed.
//                 DispatchData   -> DispatchIncomingData
//                 DispatchBlock  -> DispatchIncoming_ToBlock
//                 DispatchRaw    -> DispatchIncoming_ToRaw
//                 DispatchStream -> DispatchIncoming_ToStream
//                 DispatchText   -> DispatchIncoming_ToText
//
// Version 5.0 - October, 2014
//
//             - Changed string handling to "string" instead of rawByteString or ansiString to
//               complete the compatibility with Unicode.
//             - Removed UTF8 in lieu of ReadMode and WriteMode, which can be Ansi, UTf8 or UTF16.
//               Note, this works in Delphi 2007 and up.
//             - Removed *ALL* char based handling and moved to TBytes byte style handling.
//
// Future plans
//             - WinSock2, IP6 support
//             - Added blocking calls for reads
//             - Added OnBlocking and OnUnBlocking support to handle custom UI blocking methods
//
//*********************************************************************************************************************

//*********************************************************************************************************************
//
// TDDUSocket
//*****************
//
//            - Raw,Text,Stream and block modes for data.
//            - Cooked mode for raw and text data modes - improves debugging.
//            - EOL marker detection
//            - SOCKS4 and SOCKS5(rfc1928,rfc1929) compliant
//            - Proxy primitives (without high level negotiations)
//            - Non blocking, Fully event driven.
//            - Symetrically Buffered
//            - Multiple simultaneous session capable.
//            - Throttling controls (Speed meter [flow,average], speed limiting)
//            - ConnectFailed and Disconnect events simulated for fully symeterical event model.
//            - Sockets can be drained before disconnecting.
//
// Known Issues
//*****************
//
//            - Blocks during normal DNS LOOKUP, use a linked TDDUCUSTOMDNS component
//                for resolving.
//
//
// Future Changes
//*****************
//
//            - None yet.
//
// Notes
//*****************
//
//            - SOCKS5 is a registered trademark of NEC Corporation (http://www.socks.nec.com)
//            - Winsock references are available at http://www.sockets.com/
//
//*********************************************************************************************************************

interface

{$I DVer.inc}

{.$DEFINE WINSOCK2}
{.$DEFINE DSI}

uses
  WinAPI.Windows,
  WinAPI.Messages,
{$IFDEF WINSOCK2}
  DDU.Inet.WinAPI.WinSock2,
{$ELSE}
  WinAPI.WinSock,
{$ENDIF}
  System.SysUtils,
  System.Classes,
//  VCL.Forms,
  DDU.Buffer,
  DDU.Buffer.Support,
  DDU.Inet.Socket.Consts, //WebConsts
  DDU.Inet.Socket.Types,
  DDU.Inet.DNS,
  DDU.Inet.Proxy
{$IF defined(DSI)},DSIWin32{$ENDIF}
     ;

{$I DTypes.inc}


{$DEFINE NewInBuffer}
{$DEFINE NewOutBuffer}

{$IFDEF UNICODE}
  {$DEFINE NewInBuffer}
  {$DEFINE NewOutBuffer}
{$ENDIF}

Const
  _Max_MTU  = 9000;


Type
  TSocksAction = (saIdle,saResolveDNS,
                  saSOCKS4ConnectRequest,
                  saSOCKS4BindRequest,
                  saSOCKS4BindConnect,
                  saSOCKS5MethodRequest,
                  saSOCKS5Authentication,
                  saSOCKS5ConnectRequest,
                  saSOCKS5BindRequest,
                  saSOCKS5BindConnect);

Type
  TErrorEvent = (eeGeneral, eeAccept,eeConnect, eeDisconnect,eeRead, eeWrite,
                 eeSocksDNS, eeSocksGeneral, eeSocksVersion,
                 eeSocks4Connect,eeSocks4Bind,eeSocks4BindConnect,
                 eeSocks5Methods,eeSocks5Authentication,
                 eeSocks5Connect,eeSocks5Bind,eeSocks5BindConnect);

Type
  TSockAddrIn=TSockAddr;

Type
  TDDUCustomSocket = Class;

  TDDUSocketErrorEvent        = Procedure (Sender : TObject; ErrorEvent: TErrorEvent; ErrorCode: Integer) of Object;
  TDDUSocketFreeStreamEvent   = Procedure (Sender : TObject; Stream : TStream; Var Free : Boolean) Of Object;
  TDDUSocketFreeBlockEvent    = Procedure (Sender : TObject; Stream : TStream; aName : String; Var Free : Boolean) Of Object;
  TDDUSocketStreamEvent       = Procedure (Sender : TObject; Var Stream : TStream) Of Object;
  TDDUSocketGetStreamEvent    = TDDUSocketStreamEvent;
  TDDUSocketProgressEvent     = Procedure (Sender : TObject; Read : Cardinal; Total : Cardinal) Of Object;
  TDDUSocketBlockProgressEvent= Procedure (Sender : TObject; aName : String; Read : Cardinal; Total : Cardinal) Of Object;

  TResumeDetectEvent          = Procedure (Sender : TObject; ResumeSupported : Boolean) Of Object;
  TDDUSocketAccept            = Procedure (Sender : TObject; S : TSocket; Var Socket : TDDUCustomSocket) Of Object;
  TDDUSocketAcceptEx          = Procedure (Sender : TObject; S : TSocket; SockAddr : TSockAddrIn; Var Socket : TDDUCustomSocket; Var Handled,Async : Boolean) Of Object;
  TDDUSocketFileDoneEvent     = Procedure (Sender : TObject; FileOk : Boolean) Of Object;
  TDDUSocketCallback          = Procedure (Sender : TObject; Text : String) Of Object;
  TDDUSocketTimeoutEvent      = Procedure (Sender : TObject; Causes : TTimeoutCauses; Var ForceDisconnect : Boolean) Of Object;
  TDDUSocketSignal            = Procedure (Sender : TObject; Signal : Cardinal) Of Object;
  TDDUClientNotifyEvent       = Procedure (Sender : TObject; Client : TDDUCustomSocket) Of Object;
  TDDUSocketText              = Procedure (Sender : TObject; Text : String) Of Object;
  TClientInitEvent            = Procedure (Sender : TObject; Client : TDDUCustomSocket; Var Handled : Boolean) Of Object;
  TDDUSocketBlockEvent        = Procedure (Sender : TObject; aStream : TStream; aName : String; aSize : Cardinal) Of Object;
  TDDUSocketRawEvent          = Procedure (Sender : TObject; Var Buffer : String) Of Object;

  TDDUSocketList = Class;

  TDDUCustomSocketClass = Class Of TDDUCustomSocket;

  TGetClientClassEvent = Procedure (Sender : TObject; Var ClientClass : TDDUCustomSocketClass) Of Object;

  TExceptionEvent      = Procedure(Sender : TObject; E : Exception) Of Object;

  TDDUSocketMemoryStream=Class(TMemoryStream)
  Private
    fID       : String;   
    fSeq      : Cardinal; 
    fAutoFree : Boolean;  
  Protected
  Public
    Constructor Create(aID : String); Virtual;
    Destructor Destroy; Override;
    Property ID       : String   Read fID;
    Property Seq      : Cardinal Read fSeq;
    Property AutoFree : Boolean  Read fAutoFree Write fAutoFree;
  End;

  TDDUCustomSocket = class(TComponent)
  private
//*****************************************************************************
//
//*****************************************************************************
    fActive                : Boolean;
    fAddress               : TDDUSocketAddress; 
    fAddressDNS            : TDDUSocketAddress; 
    fAddressLocal          : TDDUSocketAddress; 
    fAddressRemote         : TDDUSocketAddress; 
    fAutoDisconnectClients : Boolean;
    fBindToAddress         : Boolean;           
    fBlockAutoStart        : Boolean;           
    fBlockAutoStartPrefix  : String;            
    fClients               : TDDUSocketList;     // List of client sockets created by this socket if it is a dispatch server.
    fConnected             : Boolean;
    fConnectFailed         : Boolean;           
    fConnecting            : Boolean;


    fSendCurrentBlockName      : String;
    fSendCurrentBlockSize      : Cardinal;
    fSendCurrentBlockStream    : TStream;

    fReceiveCurrentBlockName   : String;
    fReceiveCurrentBlockSize   : Cardinal;
    fReceiveCurrentBlockStream : TStream;

    fOnBlockSendStart          : TDDUSocketBlockEvent;

    fDataMode              : TDataMode;
    fDataRead              : UInt64;
    fDataWrote             : UInt64;
    fDeferReading          : Boolean;           
    fDeferWriting          : Boolean;
    fDisconnecting         : Boolean;           
    fDNS                   : TDDUCustomDNS;
    fDrain                 : Boolean;
    fEOL                   : TDDUEOL;           
    fErrorText             : String;            
    fException             : Boolean;           
    fFreeingParent         : TDDUCustomSocket;  
    fFreeOnDisconnect      : Boolean;           
    fHandle                : HWnd;              
    fIsServer              : Boolean;           
    fLingerTime            : Integer;           
    fMax_MTU               : Cardinal;          
    fNote                  : String;
    fPostWaiting           : Boolean;
    fProxy                 : TDDUCustomProxy;
    fRedirectParent        : TDDUCustomSocket;
    fRedirectSocket        : TDDUCustomSocket;
    fRelatedComponent      : TComponent;
    fRelatedSocket         : TDDUCustomSocket;
    fSkipReset             : Boolean;
    fSocket                : TSocket;
    fSocketList            : TDDUSocketList;     // List to which this socket belongs.
    fSocketMode            : TSocketMode;
    fSocketOptions         : TSocketOptions;
    fSocketProtocol        : TSocketProtocol;
    fSocksAction           : TSocksAction;
    fSocksAddress          : String;
    fSocksMode             : TSocksMode;
    fReceiveStream         : TStream;
    fStreamIncreaseSize    : Cardinal;
    fSuddenDisconnect      : Boolean;           
    fText                  : String;     
    fTextMode              : TTextModeSet;
    fThrottle              : TDDUThrottle;
    fThrottleOwner         : Boolean;           
    fUDPSendAddress        : String;            
    fUser                  : TDDUSocketUser;    
//*****************************************************************************
// Events
//*****************************************************************************
    fOnAccept               : TDDUSocketAccept;             
    fOnAcceptEx             : TDDUSocketAcceptEx;           
    fOnAddClient            : TDDUClientNotifyEvent;        
    fOnAfterRead            : TNotifyEvent;
    fOnBeforeRead           : TNotifyEvent;                 
    fOnBlockReceiveAbort    : TDDUSocketBlockEvent;
    fOnBlockReceiveDone     : TDDUSocketBlockEvent;         
    fOnBlockReceiveProgress : TDDUSocketBlockProgressEvent; 
    fOnBlockReceiveStart    : TDDUSocketBlockEvent;         
    fOnBlockSendDone        : TDDUSocketFreeBlockEvent;     
    fOnBlockSendProgress    : TDDUSocketBlockProgressEvent; 
    fOnCallback             : TDDUSocketCallback;           
    fOnClientInit           : TClientInitEvent;             
    fOnConnect              : TNotifyEvent;
    fOnConnectFailed        : TNotifyEvent;
    fOnConnecting           : TNotifyEvent;                 
    fOnDisconnect           : TNotifyEvent;                 
    fOnError                : TDDUSocketErrorEvent;         
    fOnFreeStream           : TDDUSocketFreeStreamEvent;
    fOnGetClientClass       : TGetClientClassEvent;         
    fOnGetStream            : TDDUSocketGetStreamEvent;
    fOnListen               : TNotifyEvent;                 
    fOnLookup               : TNotifyEvent;                 
    fOnProgress             : TDDUSocketProgressEvent;
    fOnProgressStream       : TDDUSocketProgressEvent;
    fOnRead                 : TNotifyEvent;
    fOnRemoveClient         : TDDUClientNotifyEvent;
    fOnSendStreamDone       : TDDUSocketFreeStreamEvent;
    fOnSignal               : TDDUSocketSignal;
    fOnText                 : TNotifyEvent;
    fOnTextEx               : TDDUSocketText;
    fOnThrottle             : TNotifyEvent;
    fOnThrottleReadOff      : TNotifyEvent;
    fOnThrottleReadOn       : TNotifyEvent;
    fOnThrottleWriteOff     : TNotifyEvent;
    fOnThrottleWriteOn      : TNotifyEvent;
    fOnTimeout              : TDDUSocketTimeoutEvent;
    fOnWrite                : TNotifyEvent;
  Private
    fWriteBuffer         : Pointer;
{$IfDef NewOutBuffer}
    fNewOutBuffer        : TDDUBuffer;
{$ELSE}
    fOutBuffer           : TStringList;
{$EndIf}

{$IfDef NewInBuffer}
    fNewInBuffer           : TDDUBuffer;
{$ELSE}
    fInBuffer              : String;
{$ENDIF}

    Function GetOutBufferLength : UInt64;
    Function GetInBufferLength : Uint64;
{$IfDef NewInBuffer}
    function GetInBuffer: String;
    procedure SetInBuffer(const Value: String);
{$ENDIF}
    function GetInBufferBytes: TBytes;
    procedure SetInBufferBytes(const Value: TBytes);
  Private
//*****************************************************************************
// Methods for property manipulation.
//*****************************************************************************
    function  GetClient(Index : Integer) : TDDUCustomSocket;
    function  GetClientCount : Integer;
    Function  GetCookedText : String;
    Function  GetUseProxy : Boolean;
    Procedure SetDataMode(Const NewValue : TDataMode);
    Procedure SetDeferReading(Const NewValue : Boolean);
    Procedure SetDeferWriting(Const NewValue : Boolean);
    Procedure SetDNS(Const NewValue : TDDUCustomDNS);
    Procedure SetProxy(Const NewValue : TDDUCustomProxy);
    Procedure SetRelatedComponent(Const NewValue : TComponent);
    Procedure SetRelatedSocket(Const NewValue : TDDUCustomSocket);
    Procedure SetSocketOptions(Const NewValue : TSocketOptions);
    Procedure SetSocketProtocol(Const NewValue : TSocketProtocol);
  Private
    Property FreeOnDisconnect : Boolean           Read fFreeOnDisconnect Write fFreeOnDisconnect;
  Private
    fOnException: TExceptionEvent;
    procedure WndProc(Var Msg : TMessage);

    procedure CMDispatchIncomingData(var Message: TCMSocketMessage); message CM_DispatchIncomingData;
    procedure CMSocketMessage(var Message: TCMSocketMessage);        message CM_SOCKETMESSAGE;
    procedure CMWaitForConnect(var Message: TMessage);               message CM_WaitForConnect;
    Procedure WMFreeChild (Var Message : TMessage);                  Message wm_FreeChild;

    procedure SetMax_MTU(const Value: Cardinal);
    function GetOutBufferEmpty: Boolean;
    function GetReadMode: TStringMode;
    function GetWriteMode: TStringMode;
    procedure SetReadMode(const Value: TStringMode);
    procedure SetWriteMode(const Value: TStringMode);
  Protected
    Procedure BlockSendAbort ; Virtual;
    Procedure BlockReceiveAbort ; Virtual;
    Procedure BlockReceiveDone ; Virtual;
    PRocedure BlockReceiveStart ; Virtual;
    Function  CanReadWrite : Boolean ; Virtual;
    Function  CreateSocket : TSocket ; Virtual;

    Procedure DispatchIncomingData ; Virtual;
    Procedure DispatchIncoming_ToBlock ; Virtual;
    Procedure DispatchIncoming_ToRaw ; Virtual;
    Procedure DispatchIncoming_ToStream ; Virtual;
    Procedure DispatchIncoming_ToText ; Virtual;

    Procedure DNSCancel(Sender : TObject) ; Virtual;
    Procedure DNSDone(Sender : TObject) ; Virtual;
    procedure DoAccept(S : TSocket; SockAddr : TSockAddrIn; Var Socket : TDDUCustomSocket; Var Handled,Async : Boolean) ; Virtual;
    Procedure DoAddClient(Client : TDDUCustomSocket) ; Virtual;

    Procedure DoAfterRead;
    Procedure DoBeforeRead;

    Procedure DoBlockReceiveAbort(aStream : TStream; aName : String; aSize : Cardinal) ; Virtual;
    Procedure DoBlockReceiveDone(aStream : TStream; aName : String; aSize : Cardinal) ; Virtual;
    Procedure DoBlockReceiveProgress(S : TStream; aName : String) ; Virtual;
    Procedure DoBlockReceiveStart(aStream : TStream; aName : String; aSize : Cardinal) ; Virtual;

    Procedure DoBlockSendDone(S : TStream; aName : String) ; Virtual;
    Procedure DoBlockSendProgress(S : TStream; aName : String) ; Virtual;
    Procedure DoBlockSendStart(aStream : TStream; aName : String; aSize : Cardinal) ; Virtual;

    Procedure DoCallback(Text : String) ; Virtual;
    Procedure DoClientInit(Client : TDDUCustomSocket) ; Virtual;
    procedure DoConnect ; Virtual;
    procedure DoConnectFailed ; Virtual;
    procedure DoConnecting ; Virtual;
    procedure DoDisconnect ; Virtual;
    procedure DoError(ErrorEvent : TErrorEvent; ErrorCode : Integer) ; Virtual;
    Procedure DoFreeReceiveStream ; Virtual;
    Procedure DoGetClientClass(Var ClientClass : TDDUCustomSocketClass) ; Virtual;
    Procedure DoGetReceiveStream ; Virtual; // In response to switching to dmStream
    Procedure DoListen ; Virtual;
    Procedure DoLookup ; Virtual;
    Procedure DoProgress(Read : Cardinal; Total : Cardinal) ; Virtual;
    Procedure DoProgressStream(Wrote : Cardinal; Total : Cardinal) ; Virtual;
    Procedure DoRead ; Virtual;
    Procedure DoReadRequest ; Virtual;
    Procedure DoRemoveClient(Client : TDDUCustomSocket) ; Virtual;
    Procedure DoSeekStream ; Virtual;
    Procedure DoSendStreamDone(S : TStream; IsPrivateMemoryStream : Boolean) ; Virtual;
    Procedure DoSignal(Signal : Cardinal) ; Virtual;
    procedure DoSocketAccept ; Virtual;
    procedure DoSocketConnect ; Virtual;
    procedure DoSocketDisconnect ; Virtual;
    procedure DoSocketRead ; Virtual;
    procedure DoSocketWrite ; Virtual;
    Procedure DoSOCKS4BindConnect(SockAddrIn : TSockAddrIn) ; Virtual;
    Procedure DoSOCKS4BindReply(SockAddrIn : TSockAddrIn) ; Virtual;
    Procedure DoSOCKS4BindRequest ; Virtual;
    Procedure DoSOCKS4ConnectReply(SockAddrIn : TSockAddrIn) ; Virtual;
    Procedure DoSOCKS4ConnectRequest ; Virtual;
    Procedure DoSOCKS4Reply ; Virtual;
    procedure DoSOCKS5AuthenticationReply ; Virtual;
    procedure DoSOCKS5AuthenticationRequest ; Virtual;
    procedure DoSOCKS5BindConnect(SockAddrIn : TSockAddrIn) ; Virtual;
    procedure DoSOCKS5BindReply(SockAddrIn : TSockAddrIn) ; Virtual;
    procedure DoSOCKS5BindRequest ; Virtual;
    Procedure DoSOCKS5ConnectReply(SockAddrIn : TSockAddrIn) ; Virtual;
    Procedure DoSOCKS5ConnectRequest ; Virtual;
    Procedure DoSOCKS5MethodReply ; Virtual;
    Procedure DoSOCKS5MethodRequest ; Virtual;
    Procedure DoSOCKS5Reply ; Virtual;
    Procedure DoSocksConnect ; Virtual;
    Procedure DoText(Const Text : String) ; Virtual;
    Procedure DoThrottle(Sender : TObject) ; Virtual;
    Procedure DoThrottleReadOff(Sender : TObject) ; Virtual;
    Procedure DoThrottleReadOn(Sender : TObject) ; Virtual;
    Procedure DoThrottleTimeout(Sender : TObject; Causes : TTimeoutCauses) ; Virtual;
    Procedure DoThrottleWriteOff(Sender : TObject) ; Virtual;
    Procedure DoThrottleWriteOn(Sender : TObject) ; Virtual;
    Procedure DoWriteRequest ; Virtual;
    Procedure EOLDetection ; Virtual;
    function  GetAvailableReadCount : UInt64;
    Function  GetStream : TStream ; Virtual;
    Procedure InternalConnect ; Virtual;
    Procedure InternalDisconnect ; Virtual;
    Procedure InternalWaitForConnect ; Virtual;
    Function  Internal_DoWrite(aWriteBuffer : Pointer; ToWrite : Cardinal) : Cardinal;
    Function  Internal_DoWrite_ToWrite(TotalAvailable : UInt64) : UInt64;
    Procedure Internal_StreamDone({$IFDEF NewOutBuffer}SignalID : Integer; Name : String;{$ELSE}OutBufferString : String;{$ENDIF} S : Pointer);
    procedure Internal_StreamProgress({$IFDEF NewOutBuffer}SignalID : Integer;SignalName : String;{$ELSE}OutBufferString : String;{$ENDIF} S : Pointer);
    Procedure InternalFreeStream; Virtual;
    procedure Listen(QueueSize : Integer) ; Virtual;
    Procedure LoadAddressLocal;
    Procedure LoadAddressRemote;
    Procedure NewDoWrite ; Virtual;
    Procedure Notification(AComponent : TComponent; Operation : TOperation) ; Override;
    procedure Open ; Virtual;
    Procedure OpenFinish(Var SockAddrIn : TSockAddrIn) ; Virtual;
    procedure OpenWithSocket(Async : Boolean = False) ; Virtual;
    Procedure PreConnect ; Virtual;
    Procedure PreDisconnect ; Virtual;
    function  PrepareAddress(Var SockAddrIn : TSockAddrIn) : Boolean ; Virtual;
    Procedure PrepareAsync(AsyncOn : Boolean) ; Virtual;
    Procedure PreparePort(Var SockAddrIn : TSockAddrIn) ; Virtual;
    Procedure PrepareSocketOptions ; Virtual;
    procedure PreWaitForConnect ; Virtual;
    Procedure SendBlock(BlockName : String; Block : TStrings) ; Overload ; Virtual;
    Procedure SendBlock(BlockName : String; Data : String) ; Overload ; Virtual;
    Procedure SendBlock(BlockName : String; Stream : TStream) ; Overload ; Virtual;
    Procedure SetStream(S : TStream) ; Virtual;
    Procedure SyncSocketOptionsToProtocol ; Virtual;
    Procedure TakeBuffers(Source : TDDUCustomSocket);
  Protected
    property IsSuddenDisconnect : Boolean Read fSuddenDisconnect;
{$IfDef NewInBuffer}
    Property InBuffer           : String Read GetInBuffer Write SetInBuffer;
{$else}
    Property InBuffer           : String  Read fInBuffer  Write fInBuffer;
{$EndIF}
    Property InBufferBytes      : TBytes  Read GetInBufferBytes Write SetInBufferBytes;

    Property OutBufferEmpty  : Boolean Read GetOutBufferEmpty;
  Protected  // Connection management maybe different for protocols.
    Procedure Connect; Virtual;
    Procedure Disconnect; Virtual;
    Procedure WaitForConnect; Virtual;
    Procedure WriteRemoteAddress; Virtual;
  Public
    Procedure ReceiveBlock(BlockSize : Cardinal; BlockName : String); Virtual;
  Public
    Procedure SuddenDisconnect; Virtual;
    Procedure DisconnectClients; Virtual;
    Procedure SuddenDisconnectClients; Virtual;
  public
    Constructor Create(AnOwner : TComponent); Override;
    destructor Destroy; override;

    Function  AbandonSocket : TSocket;
    Procedure AdoptSocket(aSocket : TSocket);
    Procedure CopyEvents(Source : TDDUCustomSocket); Virtual;
    procedure DefaultHandler(Var Message); override;
    Procedure EndServer; Virtual;
    Procedure Flush; Virtual;
    Procedure FlushInput; Virtual;
    Procedure FlushOutput; Virtual;
    Procedure ForceRead; Virtual;
    Procedure ForceWrite; Virtual;
    function  LookupName(const name: string) : TInAddr;
    Function  LookupPort(Const port : Integer) : String;
    function  LookupService(const service: string): Integer;

    function  FindBytes(Bytes: TBytes; Out At : UInt64): Boolean;
    function  PeekBuffer(var Buf; Count: Cardinal): Integer;
    Function  PeekBytes : TBytes; Overload;
    Function  PeekBytes(Count : Cardinal) : TBytes; Overload;
    Procedure PushOutput;
    function  ReadBuffer(var Buf; Count: Cardinal): Cardinal;
    function  ReadLength : Cardinal;
    function  ReadRawText : String;

    Function  ReadBytes : TBytes; Overload;
    Function  ReadBytes(Count : Integer) : TBytes; Overload;

    function  ReadRawTextMax(Max : Cardinal) : String;
    Procedure RedirectTo(Socket : TDDUCustomSocket);
    Procedure ReleaseRedirection;
    Procedure UseThrottle(Throttle : TDDUThrottle);

    Procedure WriteBlock(BlockName : String; Block : TStrings); Overload; Virtual;
    Procedure WriteBlock(BlockName : String; Data : String); Overload; Virtual;
    Procedure WriteBlock(BlockName : String; Stream : TStream); Overload; Virtual;
    Procedure WriteBuffer(var Buf; Count: Integer); Virtual;
    Procedure WriteBytes(Bytes : TBytes);
    Procedure WriteCallback(Const Text : String); Virtual;
    Procedure WriteDisconnect; Virtual;
    Procedure WriteFormat(const Format: string; const Args: array of const);
    Procedure WriteOpenArray(Const Args : Array Of Const); Virtual;
    procedure WriteRawText(const Text : string); Virtual;
    Procedure WriteSignal(Signal : Cardinal); Virtual;
    Procedure WriteSocket(Socket : TDDUCustomSocket);
    Procedure WriteStream(Stream : TStream); Virtual;
    Procedure WriteStreamData(Stream : TStream); Virtual;
    procedure WriteText(const Text : string); Virtual;
  Protected
    Function Stored_BlockAutoStartPrefix : Boolean;
    Function Stored_Note : Boolean;
    Function Stored_TextMode : Boolean;
    Function Stored_SocketOptions : Boolean;
  Public


    Property Active                : Boolean           Read fActive;
    property AddressLocal          : TDDUSocketAddress Read fAddressLocal          Write fAddressLocal;
    property AddressRemote         : TDDUSocketAddress Read fAddressRemote         Write fAddressRemote;
    Property BlockAutoStart        : Boolean           Read fBlockAutoStart        Write fBlockAutoStart        Default False;
    Property BlockAutoStartPrefix  : String            Read fBlockAutoStartPrefix  Write fBlockAutoStartPrefix  Stored Stored_BlockAutoStartPrefix;
    Property AutoDisconnectClients : Boolean           Read fAutoDisconnectClients Write fAutoDisconnectClients Default True;
    property Connected             : Boolean           Read fConnected;
    Property ConnectFailed         : Boolean           Read fConnectFailed;
    Property Connecting            : Boolean           Read fConnecting;
    Property CookedText            : String            Read GetCookedText;
    Property DataAvailable         : UInt64            Read GetInBufferLength;
    Property DataRead              : UInt64            Read fDataRead;
    Property DataWrote             : UInt64            Read fDataWrote;
    Property DeferReading          : Boolean           Read fDeferReading          Write SetDeferReading  Default False;
    Property DeferWriting          : Boolean           Read fDeferWriting          Write SetDeferWriting  Default False;
    Property Disconnecting         : Boolean           Read fDisconnecting;
    property ErrorText             : String            Read fErrorText;
    property Handle                : HWnd              Read fHandle;
    property IsServer              : Boolean           Read fIsServer;
    property SocketHandle          : TSocket           Read fSocket;
    Property Stream                : TStream           Read fReceiveStream;
    Property Text                  : String            Read fText;
    Property UseProxy              : Boolean           Read GetUseProxy;

    Property InBufferLength        : UInt64            Read GetInBufferLength;
    Property OutBufferLength       : UInt64            Read GetOutBufferLength;
  Public
    Property Client[Index : Integer] : TDDUCustomSocket Read GetClient;
    Property ClientCount : Integer Read GetClientCount;
  Public
//*****************************************************************************
// Properties
//*****************************************************************************
    property Address                    : TDDUSocketAddress            Read fAddress                     Write fAddress;
    Property BindToAddress              : Boolean                      Read fBindToAddress               Write fBindToAddress          Default False;

    Property ReceiveCurrentBlockName    : String                       Read fReceiveCurrentBlockName;
    Property ReceiveCurrentBlockSize    : Cardinal                     Read fReceiveCurrentBlockSize;
    Property ReceiveCurrentBlockStream  : TStream                      Read fReceiveCurrentBlockStream;
    Property SendCurrentBlockName       : String                       Read fSendCurrentBlockName;
    Property SendCurrentBlockSize       : Cardinal                     Read fSendCurrentBlockSize;
    Property SendCurrentBlockStream     : TStream                      Read fSendCurrentBlockStream;

    Property DataMode                   : TDataMode                    Read fDataMode                    Write SetDataMode;//              Default dmRaw;
    Property DNS                        : TDDUCustomDNS                Read fDNS                         Write SetDNS;
    Property Drain                      : Boolean                      Read fDrain                       Write fDrain                   Default False;
    Property EOL                        : TDDUEOL                      Read fEOL                         Write fEOL;
    Property LingerTime                 : Integer                      Read fLingerTime                  Write fLingerTime              Default 10;
    Property Max_MTU                    : Cardinal                     Read fMax_MTU                     Write SetMax_MTU               Default _Max_MTU;
    Property Note                       : String                       Read fNote                        Write fNote                    Stored Stored_Note;
    Property Proxy                      : TDDUCustomProxy              Read fProxy                       Write SetProxy;
    Property RelatedComponent           : TComponent                   Read fRelatedComponent            Write SetRelatedComponent;
    Property RelatedSocket              : TDDUCustomSocket             Read fRelatedSocket               Write SetRelatedSocket;
    Property SocketMode                 : TSocketMode                  Read fSocketMode                  Write fSocketMode              Default smClient;
    Property SocketOptions              : TSocketOptions               Read fSocketOptions               Write SetSocketOptions         Stored  Stored_SocketOptions;
    Property SocketProtocol             : TSocketProtocol              Read fSocketProtocol              Write SetSocketProtocol        Default spTCP;
    Property TextMode                   : TTextModeSet                 Read fTextMode                    Write fTextMode                Stored  Stored_TextMode;
    property Throttle                   : TDDUThrottle                 Read fThrottle                    Write fThrottle;
    Property User                       : TDDUSocketUser               Read fUser                        Write fUser;

    Property WriteMode                  : TStringMode                  read GetWriteMode                 Write SetWriteMode             Default smAnsi;
    Property ReadMode                   : TStringMode                  read GetReadMode                  Write SetReadMode              Default smAnsi;
  Public
    property OnAccept                   : TDDUSocketAccept             Read fOnAccept                    Write fOnAccept;
    property OnAcceptEx                 : TDDUSocketAcceptEx           Read fOnAcceptEx                  Write fOnAcceptEx;             
    Property OnAddClient                : TDDUClientNotifyEvent        Read fOnAddClient                 Write fOnAddClient;            
    property OnAfterRead                : TNotifyEvent                 read fOnAfterRead                 write fOnAfterRead;            
    property OnBeforeRead               : TNotifyEvent                 read fOnBeforeRead                write fOnBeforeRead;           
    Property OnBlockReceiveAbort        : TDDUSocketBlockEvent         Read fOnBlockReceiveAbort         Write fOnBlockReceiveAbort;
    Property OnBlockReceiveDone         : TDDUSocketBlockEvent         Read fOnBlockReceiveDone          Write fOnBlockReceiveDone;
    Property OnBlockReceiveStart        : TDDUSocketBlockEvent         Read fOnBlockReceiveStart         Write fOnBlockReceiveStart;
    Property OnBlockReceiveProgress     : TDDUSocketBlockProgressEvent Read fOnBlockReceiveProgress      Write fOnBlockReceiveProgress;
    Property OnBlockSendDone            : TDDUSocketFreeBlockEvent     Read fOnBlockSendDone             Write fOnBlockSendDone;
    Property OnBlockSendProgress        : TDDUSocketBlockProgressEvent Read fOnBlockSendProgress         Write fOnBlockSendProgress;
    Property OnBlockSendStart           : TDDUSocketBlockEvent         Read fOnBlockSendStart            Write fOnBlockSendStart;
    Property OnCallback                 : TDDUSocketCallback           Read fOnCallback                  Write fOnCallback;
    Property OnClientInit               : TClientInitEvent             Read fOnClientInit                Write fOnClientInit;           
    Property OnConnect                  : TNotifyEvent                 Read fOnConnect                   Write fOnConnect;              
    Property OnConnectFailed            : TNotifyEvent                 Read fOnConnectFailed             Write fOnConnectFailed;        
    Property OnConnecting               : TNotifyEvent                 Read fOnConnecting                Write fOnConnecting;           
    Property OnDisconnect               : TNotifyEvent                 Read fOnDisconnect                Write fOnDisconnect;           
    Property OnError                    : TDDUSocketErrorEvent         Read fOnError                     Write fOnError;                
    Property OnFreeStream               : TDDUSocketFreeStreamEvent    Read fOnFreeStream                Write fOnFreeStream;           
    Property OnGetClientClass           : TGetClientClassEvent         Read fOnGetClientClass            Write fOnGetClientClass;       
    Property OnGetStream                : TDDUSocketGetStreamEvent     Read fOnGetStream                 Write fOnGetStream;            
    Property OnListen                   : TNotifyEvent                 Read fOnListen                    Write fOnListen;               
    Property OnLookup                   : TNotifyEvent                 Read fOnLookup                    Write fOnLookup;               
    Property OnProgress                 : TDDUSocketProgressEvent      Read fOnProgress                  Write fOnProgress;
    Property OnProgressStream           : TDDUSocketProgressEvent      Read fOnProgressStream            Write fOnProgressStream;
    Property OnRead                     : TNotifyEvent                 Read fOnRead                      Write fOnRead;
    Property OnRemoveClient             : TDDUClientNotifyEvent        Read fOnRemoveClient              Write fOnRemoveClient;
    Property OnSendStreamDone           : TDDUSocketFreeStreamEvent    Read fOnSendStreamDone            Write fOnSendStreamDone;
    Property OnSignal                   : TDDUSocketSignal             Read fOnSignal                    Write fOnSignal;
    Property OnText                     : TNotifyEvent                 Read fOnText                      Write fOnText;
    Property OnTextEx                   : TDDUSocketText               Read fOnTextEx                    Write fOnTextEx;
    Property OnThrottle                 : TNotifyEvent                 Read fOnThrottle                  Write fOnThrottle;
    Property OnThrottleReadOff          : TNotifyEvent                 Read fOnThrottleReadOff           Write fOnThrottleReadOff;
    Property OnThrottleReadOn           : TNotifyEvent                 Read fOnThrottleReadOn            Write fOnThrottleReadOn;
    Property OnThrottleWriteOff         : TNotifyEvent                 Read fOnThrottleWriteOff          Write fOnThrottleWriteOff;
    Property OnThrottleWriteOn          : TNotifyEvent                 Read fOnThrottleWriteOn           Write fOnThrottleWriteOn;
    Property OnTimeout                  : TDDUSocketTimeoutEvent       Read fOnTimeout                   Write fOnTimeout;
    Property OnWrite                    : TNotifyEvent                 Read fOnWrite                     Write fOnWrite;
    Property OnException                : TExceptionEvent              Read fOnException                 Write fOnException;
  End;

  TDDUSocket = class(TDDUCustomSocket)
  Public
    Procedure Connect; Override;
    Procedure Disconnect; Override;
    Procedure WaitForConnect; Override;
  End;

  TDDUSocketList = Class(TList)
  Private
    fOwner      : TDDUCustomSocket;

    Function GetItem(Index : Integer) : TDDUCustomSocket;
    Procedure SetItem(Index : Integer; Const Value : TDDUCustomSocket);
  Protected
  Public
    Function Add(item : TDDUCustomSocket) : Integer;
    Function First : TDDUCustomSocket;
    Function IndexOf(Item : TDDUCustomSocket) : Integer;
    Procedure Insert(Index : Integer; Item : TDDUCustomSocket);
    Function Last : TDDUCustomSocket;
    Function Remove(Item : TDDUCustomSocket) : Integer;
    Property Items[Index : Integer] : TDDUCustomSocket Read GetItem Write SetItem; Default;
  End;

Implementation

Const
  DEFAULT_BlockAutoStartPrefix = #26#26#26'BLOCKMODE'#2;


resourcestring
  constBLOCKMarker               = 'BLOCK::';
  constSIGNALMarker              = 'SIGNAL';
  constDisconnectMarker          = 'DISCONNECT';
  constCALLBACKMarker            = 'CALLBACK';
  constSTREAMMarker              = 'STREAM';
  constPRIVATEMEMORYSTREAMMarker = 'PRIVATEMEMORYSTREAM';
  constSETUPSENDADDRESSMarker    = 'SETUPSENDADDRESS ';

Const
  signalSendBLOCKMarker           = 1;
  signalSIGNALMarker              = 2;
  signalDisconnectMarker          = 3;
  signalCALLBACKMarker            = 4;
  signalSTREAMMarker              = 5;
  signalPRIVATEMEMORYSTREAMMarker = 6;
  signalSETUPSENDADDRESSMarker    = 7;

Var
  MSSeq : Integer;


Function Min(A,B : UInt64) : UInt64; inline;

Begin
  If A<B Then Result := A Else Result := B;
End;


(*!!!**********************)

Procedure SafeFreeAndNil(Var O);

Begin
  Try
    FreeAndNil(O);
  Except
  End;
End;

Function StartsWith(Const Source : String; Const Prefix: String) : Boolean;

Begin
  Result := SameText( Copy(Source,1,Length(Prefix)),Prefix);
End;

Function TextAfter(Const Source : string; Const Prefix: String) : String;

Var
  At                      : Integer;

Begin
  If StartsWith(Source,Prefix) Then
  Begin
    Result := Copy(Source,Length(Prefix)+1,Length(Source)-Length(Prefix));
  End
  Else
  Begin
    At := Pos(Prefix,Source);
    If At=0 Then
    Begin
      Result := '';
    End
    Else
    begin
      Result := Copy(Source,At+Length(Prefix),Length(Source)-(At+Length(Prefix)-1));
    end;
  End;
End;

(*!!!**********************)


Constructor TDDUCustomSocket.Create(AnOwner : TComponent);

Begin
  inherited Create(AnOwner);

  fMax_MTU := _Max_MTU;
  If (fMax_MTU<>0) Then
  Begin
    GetMem(fWriteBuffer,fMax_MTU);
  End;

{$IFDEF NewOutBuffer}
  fNewOutBuffer := TDDUBuffer.Create;
{$ELSE}  
  fOutBuffer := TStringList.Create;
{$ENDIF}

{$IFDEF NewInBuffer}
  fNewInBuffer := TDDUBuffer.Create;
{$ENDIF}

  fBlockAutoStartPrefix := DEFAULT_BlockAutoStartPrefix;


  fAutoDisconnectClients := True;

  fClients := TDDUSocketList.Create;
  fClients.fOwner := Self;


  fSocket := INVALID_SOCKET;
  fSocketProtocol := spTCP;

{$IF defined(DSI)}
  fHandle := DSiAllocateHwnd(WndProc);
{$ELSE}
  fHandle := AllocateHwnd(WndProc);
{$ENDIF}

  fLingerTime := 10;

  fSocketMode := smClient;
  fDataMode   := dmRaw;

  fTextMode   := [];

  fAddress       := TDDUSocketAddress.Create;
  fAddressDNS    := TDDUSocketAddress.Create;
  fAddressLocal  := TDDUSocketAddress.Create;
  fAddressRemote := TDDUSocketAddress.Create;

  fEOL           := TDDUEol.Create;

  fUser          := TDDUSocketUser.Create;

  UseThrottle(Nil);

End;

destructor TDDUCustomSocket.Destroy;

Var
  Loop                    : Integer;

Begin
  If Assigned(fSocketList) Then
  Begin
    fSocketList.Remove(Self);
  End;

  // Ensure that all clients are destroyed before we are.
  If AutoDisconnectClients Then
  Begin
    SuddenDisconnectClients;
  End;

  For Loop := ClientCount-1 DownTo 0 Do
  Begin
    If Client[Loop].FreeOnDisconnect Then
    Begin
      Client[Loop].Free;
    End;
  End;

  fFreeOnDisconnect := False;
//*****************************************************************************
// Disable all events
//*****************************************************************************
  CopyEvents(Nil);
//*****************************************************************************
// Disconnect the socket if we are connected.
//*****************************************************************************
  If Not (SocketHandle=INVALID_SOCKET) Then
  Begin
    fSuddenDisconnect := True; // Do not drain the socket.
    DoSocketDisconnect;
  End;
//*****************************************************************************
// Destroy the window.
//*****************************************************************************
{$IF defined(DSI)}
  DSiDeallocateHWnd(FHandle);
{$ELSE}
  DeallocateHWnd(FHandle);
{$ENDIF}
  FreeAndNil(fUser);
  FreeAndNil(fEOL);
  FreeAndNil(fAddressLocal);
  FreeAndNil(fAddressRemote);
  FreeAndNil(fAddressDNS);
  FreeAndNil(fAddress);

  If fThrottleOwner Then
  Begin
    FreeAndNil(fThrottle);
  End;
  FreeAndNil(fClients);

{$IFDEF NewInBuffer}
  FreeAndNil(fNewInBuffer);
{$ENDIF}

{$IFDEF NewOutBuffer}
  FreeAndNil(fNewOutBuffer);
{$ELSE}  
  FreeAndNil(fOutBuffer);
{$ENDIF}

  If Assigned(fWriteBuffer) Then
  Begin
    freeMem(fWriteBuffer,fMax_MTU);
  End;
  inherited Destroy;
End;

Procedure TDDUCustomSocket.CopyEvents(Source : TDDUCustomSocket);

Begin
  If Assigned(Source) Then
  Begin
    fOnAccept            := Source.fOnAccept;
    fOnAcceptEx          := Source.fOnAcceptEx;
    fOnAddClient         := Source.fOnAddClient;         
    fOnBlockReceiveAbort        := Source.fOnBlockReceiveAbort;
    fOnBlockReceiveDone  := Source.fOnBlockReceiveDone;
    fOnBlockReceiveProgress     := Source.fOnBlockReceiveProgress;
    fOnBlockReceiveStart := Source.fOnBlockReceiveStart;
    fOnBlockSendDone     := Source.fOnBlockSendDone;
    fOnBlockSendProgress := Source.fOnBlockSendProgress;
    fOnBlockSendStart    := Source.fOnBlockSendStart;
    fOnCallback          := Source.fOnCallback;
    fOnClientInit        := Source.fOnClientInit;
    fOnConnect           := Source.fOnConnect;
    fOnConnectFailed     := Source.fOnConnectFailed;
    fOnConnecting        := Source.fOnConnecting;        
    fOnDisconnect        := Source.fOnDisconnect;        
    fOnError             := Source.fOnError;             
    fOnFreeStream        := Source.fOnFreeStream;        
    fOnGetClientClass    := Source.fOnGetClientClass;    
    fOnGetStream         := Source.fOnGetStream;         
    fOnListen            := Source.fOnListen;            
    fOnLookup            := Source.fOnLookup;            
    fOnProgress          := Source.fOnProgress;          
    fOnProgressStream    := Source.fOnProgressStream;    
    fOnRead              := Source.fOnRead;
    fOnRemoveClient      := Source.fOnRemoveClient;      
    fOnSendStreamDone    := Source.fOnSendStreamDone;    
    fOnSignal            := Source.fOnSignal;            
    fOnText              := Source.fOnText;              
    fOnTextEx            := Source.fOnTextEx;            
    fOnThrottle          := Source.fOnThrottle;          
    fOnThrottleReadOff   := Source.fOnThrottleReadOff;   
    fOnThrottleReadOn    := Source.fOnThrottleReadOn;    
    fOnThrottleWriteOff  := Source.fOnThrottleWriteOff;  
    fOnThrottleWriteOn   := Source.fOnThrottleWriteOn;
    fOnTimeout           := Source.fOnTimeout;
    fOnWrite             := Source.fOnWrite;
  End
  Else
  Begin
    fOnAccept            := Nil;
    fOnAcceptEx          := Nil;
    fOnAddClient         := Nil; 
    fOnBlockReceiveAbort        := Nil;
    fOnBlockReceiveDone       := Nil;
    fOnBlockReceiveProgress     := Nil;
    fOnBlockSendDone     := Nil;
    fOnBlockSendProgress := Nil;
    fOnBlockSendStart    := Nil;
    fOnBlockReceiveStart := Nil;
    fOnCallback          := Nil; 
    fOnClientInit        := Nil; 
    fOnConnect           := Nil; 
    fOnConnectFailed     := Nil; 
    fOnConnecting        := Nil; 
    fOnDisconnect        := Nil; 
    fOnError             := Nil; 
    fOnFreeStream        := Nil; 
    fOnGetClientClass    := Nil; 
    fOnGetStream         := Nil; 
    fOnListen            := Nil; 
    fOnLookup            := Nil; 
    fOnProgress          := Nil; 
    fOnProgressStream    := Nil; 
    fOnRead              := Nil;
    fOnRemoveClient      := Nil; 
    fOnSendStreamDone    := Nil; 
    fOnSignal            := Nil; 
    fOnText              := Nil; 
    fOnTextEx            := Nil; 
    fOnThrottle          := Nil; 
    fOnThrottleReadOff   := Nil; 
    fOnThrottleReadOn    := Nil; 
    fOnThrottleWriteOff  := Nil; 
    fOnThrottleWriteOn   := Nil;
    fOnTimeout           := Nil;
    fOnWrite             := Nil;
  End;
End;

Function TDDUCustomSocket.CanReadWrite : Boolean;

Begin
  Result := Connected Or (Active And (fSocksAction<>saIdle));
End;

procedure TDDUCustomSocket.CMDispatchIncomingData(var Message: TCMSocketMessage);

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    fRedirectSocket.DispatchIncomingData;
    Exit;
  End;
  DispatchIncomingData;
End;

procedure TDDUCustomSocket.CMSocketMessage(var Message: TCMSocketMessage);

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    fRedirectSocket.CMSocketMessage(Message);
    Exit;
  End;

  If Message.Socket<>fSocket Then //async
  Begin
    Exit;
  End;

  If fException Then
  Begin
    Try
      Case Message.SelectEvent of
        FD_CONNECT : Begin
                       SuddenDisconnect;
                     End;
        FD_CLOSE   : Begin
                       DoSocketDisconnect;
                     End;
        FD_READ    : Begin
                       DoSocketRead;
                     End;
        FD_WRITE   : Begin
                     End;
        FD_ACCEPT  : Begin
                       SuddenDisconnect;
                     End;
      End;
    Except
    End;
    Exit;
  End;

  Try
    If Not (Message.SelectError=0) Then
    Begin
      Case Message.SelectEvent of
        FD_CONNECT : Begin
                       DoError(eeConnect, Message.SelectError);
                       SuddenDisconnect;
                     End;
        FD_CLOSE   : Begin
                       If Not(Message.SelectError=WSAECONNRESET) Then
                       Begin
                         DoError(eeDisconnect,Message.SelectError);
                       End;
                       DoSocketDisconnect;
                     End;
        FD_READ    : DoError(eeRead,Message.SelectError);
        FD_WRITE   : DoError(eeWrite,Message.SelectError);
        FD_ACCEPT  : DoError(eeAccept,Message.SelectError);
      Else
        DoError(eeGeneral,Message.SelectError);
      End;
    End
    Else
    Begin
      Case Message.SelectEvent of
        FD_CONNECT : Begin
                       If UseProxy And Proxy.UseSocks Then
                       Begin
                         fSocksAddress := fAddressDNS.Address;
                         fAddressDNS.Clear;
                         fAddressDNS.Text := Address.Text;
                         fAddressDNS.Assign(Address);
                         LoadAddressLocal;
                         DoSocksConnect;
                       End
                       Else
                       Begin
                         LoadAddressLocal;
                         LoadAddressRemote;
                         DoSocketConnect;
                       End;
                     End;
        FD_CLOSE   : Begin
                       DoSocketDisconnect;
                     End;
        FD_READ    : DoSocketRead;
        FD_WRITE   : DoSocketWrite;
        FD_ACCEPT  : DoSocketAccept;
      End;
    End;
  Except
    On E:Exception Do
    Begin
      fException := True;
      SuddenDisconnect;
      If Assigned(fOnException) Then
      Begin
        fOnException(Self,E);
      End;
//      Application.HandleException(E);
    End;
  End;
End;

procedure TDDUCustomSocket.CMWaitForConnect(var Message: TMessage);

Begin
  If (fPostWaiting) Then
  Begin
    fActive := False;
    fPostWaiting := False;
    Try
      WaitForConnect;
    Except
      If (Message.LParam>0) Then
      Begin
        fActive := True;
        fPostWaiting := True;
        PostMessage(fHandle,cm_WaitForConnect,0,Message.LParam-1);
      End;
    End;
  End;
End;

Procedure TDDUCustomSocket.Connect;

Begin
  If (SocketMode in [smAuto,smAutoReset]) and Active And Connecting Then
  Begin
    If Not (SocketHandle=INVALID_SOCKET) Then
    Begin
      PrepareAsync(False);
      closesocket(SocketHandle);
    End;
    fSocket := INVALID_SOCKET;
    fActive := False;
  End;

  If (SocketMode In [smServerSingle,smServerSingleReset,smServerDispatch]) Then
  Begin
    Raise eSocketError.Create(sServerCannotOpen);
  End;
  If (SocketProtocol in [spUDP,spUDPBroadcast]) And UseProxy Then
  Begin
    Raise ESocketError.Create(sNoUDPProxy);
  End;
  If Not Active Then
  Begin
    PreConnect;
    InternalConnect;
  End;
End;

Function TDDUCustomSocket.CreateSocket : TSocket;

Begin
  If Not (SocketHandle=INVALID_SOCKET) Then
  Begin
    Raise ESocketError.Create(sSocketAlreadyOpen);
  End;

  Case SocketProtocol Of
    spTCP : Result := socket(AF_INET, SOCK_STREAM, 0);
    spUDPBroadcast,
    spUDP : Result := socket(AF_INET, SOCK_DGRAM, 0);
  Else
    Result := INVALID_SOCKET;
  End;

  If (Result=INVALID_SOCKET) Then
  Begin
    SuddenDisconnect;
    Raise ESocketError.Create(sCannotCreateSocket);
  End;
End;

Procedure TDDUCustomSocket.Disconnect;

Begin
  If (Active) Then
  Begin
    If (fPostWaiting) Then
    Begin
      fPostWaiting := False;
    End;
    Predisconnect;
    InternalDisconnect;
  End;
End;

procedure TDDUCustomSocket.DispatchIncoming_ToBlock;

Var
  DataToRead              : Cardinal;
{$IFDEF NewInBuffer}
  BufferData              : PByte;
{$ENDIF}

begin
  DataToRead := fReceiveCurrentBlockSize-fReceiveCurrentBlockStream.Position;
  If InBufferLength<DataToRead Then
  Begin
    DataToRead := InBufferLength;
  End;

{$IFDEF NewInBuffer}
  If (DataToRead<>0) Then
  Begin
    GetMem(BufferData,DataToRead);
    Try
      fNewInBuffer.ReadData(BufferData,DataToRead);
      fReceiveCurrentBlockStream.Write(BufferData^,DataToRead);
    Finally
      FreeMem(BufferData,DataToRead);
    End;
  End;
{$Else}
  If (DataToRead<>0) Then
  Begin
    fReceiveCurrentBlockStream.Write(fInBuffer[1],DataToRead);
    Delete(fInBuffer,1,DataToRead);
  End;
{$ENDIF}

  DoBlockReceiveProgress(fReceiveCurrentBlockStream,fReceiveCurrentBlockName );

  If (fReceiveCurrentBlockStream.Position>=fReceiveCurrentBlockSize) Then
  Begin
    BlockReceiveDone;
  End;
end;

Procedure TDDUCustomSocket.DispatchIncomingData;

Var                     
  OldDataMode             : TDataMode; 

Begin
// This code parses everything out of the buffer until :
// the buffer is empty -OR- The original datamode has not changed, indicating that data in the buffer should be ignored till a subsequent read
// or a defer reading flag is thrown.
  Repeat
    OldDataMode := DataMode;
    If (DataMode in [dmText,dmCookedText]) Then
    Begin
      DispatchIncoming_ToText;
    End;
    If (DataMode In [dmRaw,dmCookedRaw]) Then
    Begin
      OldDataMode := DataMode;
      DispatchIncoming_ToRaw;
    End;
    If (DataMode in [dmStream,dmRawStream]) Then
    Begin
      OldDataMode := DataMode;
      DispatchIncoming_ToStream;
    End;
    If (DataMode in [dmBlock]) Then
    Begin
      OldDataMode := DataMode;
      DispatchIncoming_ToBlock;
    End;
{$IFDEF NewInBuffer}
  Until (fNewInBuffer.Empty) Or (OldDataMode=DataMode) Or DeferReading;
{$ELSE}
  Until (fInBuffer='') Or (OldDataMode=DataMode) Or DeferReading;
{$ENDIF}

End;

Procedure TDDUCustomSocket.DispatchIncoming_ToRaw;

Begin
  If Not DeferReading Then
  Begin
    If (DataMode=dmCookedRaw) Then
    Begin
      SetInBufferBytes( bString( printableBytes( InBufferBytes ) ) );
    End;

    If (Not Assigned(fOnRead)) And (Disconnecting) Then
    Begin
      FlushInput;
    End;
    If Assigned(fOnRead) Then
    Begin
      fOnRead(Self);
    End;
  End;
End;

Procedure TDDUCustomSocket.DispatchIncoming_ToText;

Function GetEOLPosition (Var At : UInt64) : Boolean;

Begin
{$IFDEF NewInBuffer}
  Case EOL.Remote of
    emCRLF   : Result := fNewInBuffer.FindData( __CRLF ,At);
    emLFCR   : Result := fNewInBuffer.FindData(__LFCR ,At);
    emCROnly : Result := fNewInBuffer.FindData(__CR,At);
    emLFOnly : Result := fNewInBuffer.FindData(__LF,At);
    emCustom : Begin
                 If EOL.CustomRemoteEOL='' Then  // no EOL, every character is an EOL.
                 Begin
                   At := 0;
                   Result := (fNewInBuffer.Available>0)
                 End
                 Else
                 Begin
                   Result := fNewInBuffer.FindData(bString(EOL.CustomRemoteEOL,ReadMode ),At);
                 End;
               End;
  Else
    At := 0;
    Result := False;
  End;
{$ELSE}
  Case EOL.Remote of
    emCRLF   : At := Pos(#13#10,fInBuffer);
    emLFCR   : At := Pos(#10#13,fInBuffer);
    emCROnly : At := Pos(#13,fInBuffer);
    emLFOnly : At := Pos(#10,fInBuffer);
    emCustom : Begin
                 If EOL.CustomRemoteEOL='' Then
                 Begin
                   If InBufferLength>0 Then
                   Begin
                     At := 0;
                   End
                   Else
                   Begin
                     At := -1;
                   End;
                 End
                 Else
                 Begin
                   At := Pos(EOL.CustomRemoteEOL,fInBuffer);
                 End;
               End;
  Else
    At := 0;
  End;
  Result := (At<>0);
{$ENDIF}
End;

Var
  At                    : UInt64;
  Loop                  : Integer;
  Work                  : String;

Begin
  If DeferReading Then Exit;
  If (tmRawText In TextMode) Then
  Begin
//*****************************************************************************
// A truely raw text mode returns ALL characters input a single events.
// This allows the client total control over how it interprets the data.
//*****************************************************************************
    Work := InBuffer;
    For Loop := 1 To Length(Work) Do
    Begin
      DoText(Work[Loop]);
    End;
    InBuffer := '';
  End
  Else
  Begin
//*****************************************************************************
// We do not want to do EOLDetection while reading is defered, because binary
// data could be infrom of the text, and might be cleared out by another
// Dispatch routine before we should get this far.
//*****************************************************************************
    If (EOL.Remote=emUnknown) Then EOLDetection;
    If (EOL.Remote<>emUnknown) Then
    Begin
//*****************************************************************************
// Because multiple data events can be fired, we need to check for deferreading
// in each loop iteration.
//*****************************************************************************
      While (Not DeferReading) And (DataMode in [dmText,dmCookedText]) And (GetEOLPosition(At)) Do
      Begin
{$IFDEF NewInBuffer}
        Work := fNewInBuffer.ReadString(At);
        Case EOL.Remote of
          emCRLF   : fNewInBuffer.Seek(2);
          emLFCR   : fNewInBuffer.Seek(2);
          emCROnly : fNewInBuffer.Seek(1);
          emLFOnly : fNewInBuffer.Seek(1);
          emCustom : Begin
                       If (EOL.CustomRemoteEOL='') Then
                       Begin
                         fNewInBuffer.Seek(1);
                       End
                       Else
                       Begin
                         fNewInBuffer.Seek(Length(EOL.CustomRemoteEOL));
                       End;
                     End;
        End;
{$ELSE}
        Work := Copy(fInBuffer,1,At-1);
        Case EOL.Remote of
          emCRLF   : Delete(fInBuffer,1,At+1);
          emLFCR   : Delete(fInBuffer,1,At+1);
          emCROnly : Delete(fInBuffer,1,At);
          emLFOnly : Delete(fInBuffer,1,At);
          emCustom : Begin
                       If (EOL.CustomRemoteEOL='') Then
                       Begin
                         Delete(fInBuffer,1,1);
                       End
                       Else
                       Begin
                         Delete(fInBuffer,1,At-1+Length(EOL.CustomRemoteEOL));
                       End;
                     End;
        End;
{$ENDIF}
        DoText(Work);
      End;
    End;

{$IFDEF NewInBuffer}
    If ( ( Disconnecting And (DataMode in [dmText,dmCookedText]) And (Not DeferReading) ) Or (SocketProtocol In [spUDP,spUDPBroadCast]) )
        And (fNewInBuffer.Available<>0) Then
    Begin
      Work := fNewInBuffer.ReadString(fNewInBuffer.Available);
      fNewInBuffer.Flush;
      DoText(Work);
    End;
{$ELSE}
    If ( ( Disconnecting And (DataMode in [dmText,dmCookedText]) And (Not DeferReading) ) Or (SocketProtocol In [spUDP,spUDPBroadCast]) )
        And (fInBuffer<>'') Then
    Begin
      DoText(fInBuffer);
      fInBuffer := '';
    End;
{$ENDIF}
  End;
  If Disconnecting Then
  Begin
    FlushInput;
  End;
End;

Procedure TDDUCustomSocket.DispatchIncoming_ToStream;

Var
  DataAvailable           : UInt64;
{$IFDEF NewInBuffer}
  DataBuffer              : Pointer;
{$EndIf}

Begin
  If Not DeferReading Then
  Begin
    If (Not Assigned(fReceiveStream)) And (Disconnecting) Then
    Begin
      FlushInput;
    End;

    DataAvailable := InBufferLength;
{$IFDEF NewInBuffer}
    If (DataAvailable<>0) Then
    Begin
      fStreamIncreaseSize := fStreamIncreaseSize+DataAvailable;

      Getmem(DataBuffer,DataAvailable);
      Try
        fNewInBuffer.ReadData(DataBuffer,DataAvailable);
        If Assigned(fReceiveStream) Then
        Begin
          fReceiveStream.Write(DataBuffer^,DataAvailable);
        End;
      Finally
        FreeMem(DataBuffer,DataAvailable);
      End;
//      If (DataMode=dmRawStream) Then
//      Begin
//        DispatchRaw;
//      End;
      DoProgress(fStreamIncreaseSize,0);
    End;
{$ELSE}
    If (fInBuffer<>'') Then
    Begin
      fStreamIncreaseSize := fStreamIncreaseSize+DataAvailable;
      If Assigned(fIncomingStream) Then
      Begin
        fIncomingStream.Write(fInBuffer[1],DataAvailable);
      End;
      If (DataMode=dmRawStream) Then
      Begin
        DispatchRaw;
      End;
      fInBuffer := '';
      DoProgress(fStreamIncreaseSize,0);
    End;
{$ENDIF}
  End;
End;

Procedure TDDUCustomSocket.DNSCancel(Sender : TObject);

Var
  ErrorCode             : Integer;

Begin
//*****************************************************************************
// Clear the DNS control so that it can not re-issue commands to us.
//*****************************************************************************
  (Sender As TDDUCustomDNS).OnFoundAddress2 := Nil;
  (Sender As TDDUCustomDNS).OnCancel2       := Nil;
//*****************************************************************************
// Someone cancelled the DNS control while searching for the name, perhaps
// via a DNS time out.  Simulate a failed connect.
//*****************************************************************************
  If (fSOCKSaction=saResolveDNS) Then
  Begin
    fErrorText := sDNScancelled;
    ErrorCode := WSAHOST_NOT_FOUND;
    DoError(eeSocksDNS,ErrorCode);
    SuddenDisconnect;
  End
  Else
  Begin
    DoConnectFailed;
  End;
End;

Procedure TDDUCustomSocket.DNSDone(Sender : TObject);

Var
  SockAddrIn            : TSockAddrIn;
  ErrorCode             : Integer;

Begin
//*****************************************************************************
// Clear the DNS control so that it can not re-issue commands to us.
//*****************************************************************************
  (Sender As TDDUCustomDNS).OnFoundAddress2 := Nil;
  (Sender As TDDUCustomDNS).OnCancel2       := Nil;
  If (Sender As TDDUCustomDNS).OK Then
  Begin
//*****************************************************************************
// We have a valid address resolved from the host name.
//*****************************************************************************
    fAddressDNS.Address := (Sender As TDDUCustomDNS).Address;
    If (fSOCKSaction=saResolveDNS) Then
    Begin
      DoSocksConnect;
    End
    Else
    Begin
      Try
        If PrepareAddress(SockAddrIn) Then
        Begin
          OpenFinish(SockAddrIn);
        End;
      Except
        SuddenDisconnect;
      End;
    End;
  End
  Else
  Begin
//*****************************************************************************
// There was an invalid IP sent, simulate a failed connect.
//*****************************************************************************
    If (fSOCKSaction=saResolveDNS) Then
    Begin
      fErrorText := sDNSFailed;
      ErrorCode := 0;
      DoError(eeSocksDNS,ErrorCode);
      SuddenDisconnect;
    End
    Else
    Begin
//      DoConnectFailed;
      SuddenDisconnect;
    End;
  End;
End;

procedure TDDUCustomSocket.DefaultHandler(var Message);

Begin
  With TMessage(Message) do
  Begin
    Result := CallWindowProc(@DefWindowProc, Handle, Msg, wParam, lParam);
  End;
End;

Procedure TDDUCustomSocket.DoAccept(S : TSocket; SockAddr : TSockAddrIn; Var Socket : TDDUCustomSocket; Var Handled,Async : Boolean);

Begin
  Handled := False;
  If Assigned(fOnAcceptEx) Then
  Begin
    fOnAcceptEx(Self,S,SockAddr,Socket,Handled,Async);
  End;
  If (Not Handled) And (Socket=Nil) And Assigned(fOnAccept) Then
  Begin
    fOnAccept(Self,S,Socket);
  End;
End;

Procedure TDDUCustomSocket.DoCallback(Text : String);

Begin
  If Assigned(fOnCallback) Then
  Begin
    Delete(Text,1,9);
    fOnCallback(Self,Text);
  End;
End;

procedure TDDUCustomSocket.DoAddClient(Client: TDDUCustomSocket);
begin
  If Assigned(fOnAddClient) Then
  Begin
    fOnAddClient(Self,Client);
  End;
end;

procedure TDDUCustomSocket.DoAfterRead;
begin
  If Assigned(fOnAfterRead) Then
  Begin
    fOnAfterRead(Self);
  End;
end;

Procedure TDDUCustomSocket.DoConnect;

Begin
  fDataRead := 0;
  fDataWrote := 0;
  If Assigned(fOnConnect) Then
  Begin
    fOnConnect(Self);
  End;
End;

Procedure TDDUCustomSocket.DoConnectFailed;

Begin
  If Assigned(fOnConnectFailed) Then
  Begin
    fOnConnectFailed(Self);
  End;
End;

Procedure TDDUCustomSocket.DoConnecting;

Begin
  If Assigned(fOnConnecting) Then
  Begin
    fOnConnecting(Self);
  End;
End;

Procedure TDDUCustomSocket.DoDisconnect;

Begin
  If Assigned(fOnDisconnect) Then
  Begin
    fOnDisconnect(Self);
  End;
End;

procedure TDDUCustomSocket.DoError(ErrorEvent: TErrorEvent; ErrorCode: Integer);

Begin
  If Assigned(fOnError) Then
  Begin
    fOnError(Self, ErrorEvent, ErrorCode);
  End;
End;

Procedure TDDUCustomSocket.DoFreeReceiveStream;

Var
  FreeIt                : Boolean;

Begin
  If Assigned(fReceiveStream) Then
  Begin
    FreeIt := True;
    If Assigned(fOnFreeStream) Then
    Begin
      fReceiveStream.Seek(soFromBeginning,0);
      fOnFreeStream(Self,fReceiveStream,FreeIt);
    End;
    If FreeIt Then
    Begin
      If (fReceiveStream Is TDDUSocketMemoryStream) Then
      Begin
        //Debug('++Pre-Freeing(3) TDDUSocketMemoryStream [%0.8x] [%0.8x]  :: %s',[LongInt(fIncomingStream), TDDUSocketMemoryStream(fIncomingStream).Seq,TDDUSocketMemoryStream(fIncomingStream).ID]);
      End;
      FreeAndNil(fReceiveStream);
    End;
    InternalFreeStream;
  End;
  fReceiveStream := Nil;
End;

Procedure TDDUCustomSocket.DoGetReceiveStream;

Begin
  DoFreeReceiveStream;
  fReceiveStream := GetStream;
  If (Not Assigned(fReceiveStream)) And Assigned(fOnGetStream) Then
  Begin
    fOnGetStream(Self,fReceiveStream);
  End;
End;

Procedure TDDUCustomSocket.DoListen;

Begin
  If Assigned(fOnListen) Then
  Begin
    fOnListen(Self);
  End;
End;

Procedure TDDUCustomSocket.DoLookup;

Begin
  If Assigned(fOnLookup) Then
  Begin
    fOnLookup(Self);
  End;
End;

Procedure TDDUCustomSocket.DoProgress(Read : Cardinal; Total : Cardinal);

Begin
  If Assigned(fOnProgress) Then
  Begin
    fOnProgress(Self,Read,Total);
  End;
End;

Procedure TDDUCustomSocket.DoProgressStream(Wrote : Cardinal; Total : Cardinal);

Begin
  If Assigned(fOnProgressStream) Then
  Begin
    fOnProgressStream(Self,Wrote,Total);
  End;
End;

Procedure TDDUCustomSocket.DoRead;

Var
  AvailableToRead         : Cardinal;
  Data                    : TBytes;
  ErrorCode               : Integer;
  IncomingBuffer          : TBytes;
  Read                    : UInt64;
  RepeatFinished          : Boolean;
  SingleByteMode          : Boolean;
  Size                    : Integer;
  SockAddrIn              : {$IFDEF WINSOCK2}TSockAddr{$ELSE}TSockAddrIn{$ENDIF};

Begin
  DoBeforeRead;
  Try
    Repeat
      RepeatFinished  := True;          
      AvailableToRead := GetAvailableReadCount;  // Amount of data waiting in the socket.

      If (Throttle.BlockSize.Read<>0) And (Throttle.SpeedLimit.Read<>0) And
         (Throttle.BlockSize.Read<AvailableToRead) Then
      Begin
        AvailableToRead := Throttle.BlockSize.Read;
      End;
//*****************************************************************************
// Currently, the only way to correctly interpret a backspace is by reading
// the datastream one character at a time.  We compensate for this with the
// repeat/until loop. - this is obviously sub-optimal.
      SingleByteMode := (SocketProtocol=spTCP) And (DataMode in [dmText,dmCookedText]) And (TextMode<>[]);
      If SingleByteMode And (AvailableToRead>0) Then
      Begin
        AvailableToRead := 1;
      End;

      If (AvailableToRead<>0) Then
      Begin
        SetLength(IncomingBuffer,AvailableToRead);
        Case SocketProtocol Of
          spTCP          : Begin
                             Read := Recv(SocketHandle,IncomingBuffer[Low(IncomingBuffer)],AvailableToRead,0);
                           End;
          spUDP,
          spUDPBroadcast : Begin
                             Size := SizeOf(SockAddrIn);
                             FillChar(SockAddrIn,Size,0);

                             {$IFDEF WINSOCK2}
                             SockAddrIn.sa_family := AF_INET;
                             SockAddrIn.sa_family := AF_INET6;
                             {$ELSE}
                             SockAddrIn.sin_family := AF_INET;
                             {$ENDIF}
                             Read := RecvFrom(SocketHandle,IncomingBuffer[Low(IncomingBuffer)],AvailableToRead,0,SockAddrIn,Size);

                             {$IFDEF WINSOCK2}
                             {$ELSE}
                             AddressRemote.IP   := SockAddrIn.sin_addr.S_addr;
                             AddressRemote.Port := ntohs(SockAddrIn.sin_port);
                             {$ENDIF}
                           End;
        Else
          Read := 0;
        End;
        If (Read=SOCKET_ERROR) Then
        Begin
          SetLength(IncomingBuffer,0);
          ErrorCode      := WSAGetLastError;
          If (ErrorCode=0) Then
          Begin
            Read := 0;
            SetLength(IncomingBuffer,0);
          End Else If (ErrorCode<>WSAEWOULDBLOCK) Then
          Begin
            DoError(eeRead, ErrorCode);
            SuddenDisconnect;
            Exit;
          End;
        End
        Else
        Begin
          If (AvailableToRead<>Cardinal(Read)) Then
          Begin
            SetLength(IncomingBuffer,Read);
          End;
        End;

        // This is where demangling takes place.
        fDataRead := fDataRead+Cardinal(Read);
        Throttle.RegisterDataRead(Read);
{$IFDEF NewInBuffer}
        If (Length(IncomingBuffer)<>0) Then
        Begin
          fNewInBuffer.WriteBytes(IncomingBuffer);//,Read);
        End;
{$ELSE}
        If Length(IncomingBuffer)<>0 Then
        Begin
          At := InBufferLength;
          SetLength(fInBuffer,At+Read);
          Move(IncomingBuffer[Low(IncomingBuffer)],fInBuffer[At+1],Read);
        End;
{$ENDIF}

        If SingleByteMode And (Read<>0) Then
        Begin
          Data := IncomingBuffer;
          If (tmBackSpace In TextMode) And (length(Data)>0) And (Data[0]=8) Then
          Begin
            If (InBufferLength=1) Then
            Begin
              SetLength(Data,0);
{$IFDEF NewInBuffer}
              fNewInBuffer.Flush;
{$ELSE}
              fInBuffer := '';
{$EndIf}
            End
            Else
            Begin
              Data := Bytes([8,32,8]);
{$IFDEF NewInBuffer}
              fNewInBuffer.UnwriteData(2); // Remove #8 and the preceeding character.
{$ELSE}
              SetLength(fInBuffer,Length(fInBuffer)-2); // Remove #8 and the preceeding character.
{$ENDIF}
            End;
          End Else If (tmFlowControl in TextMode) Then
          Begin
            If (Length(Data)<>0) And (Data[0]=Byte(^s)) Then
            Begin
              DeferWriting := True;
{$IFDEF NewInBuffer}
              fNewInBuffer.UnwriteData(1);
{$ELSE}
              SetLength(fInBuffer,Length(fInBuffer)-1);
{$ENDIF}
              SetLength(Data,0);
            End;
            If (Length(Data)<>0) And (Data[0]=Byte(^q)) Then
            Begin
              DeferWriting := False;
{$IFDEF NewInBuffer}
              fNewInBuffer.UnwriteData(1);
{$ELSE}
              SetLength(fInBuffer,Length(fInBuffer)-1);
{$ENDIF}
              SetLength(Data,0);
            End;
          End;

          If (tmEcho in TextMode) Then
          Begin
            If Length(Data)<>0 Then
            Begin
              WriteBuffer(Data[Low(Data)],Length(Data));
            End;
          End;
  //*****************************************************************************
  // Since we are reading 1 byte at a time, try to get as much data possible
  // between messages to prevent flooding the message queue and peaking the
  // kernel usage.
          RepeatFinished := False;
        End;
      End;
    Until RepeatFinished;

    If {$IfDef NewInBuffer}(fNewInBuffer.Available<>0){$Else}(fInBuffer<>''){$EndIf}
      And (fSOCKSaction<>saIdle) Then // are we in a socks negotiation mode?
    Begin
      Case fSOCKSaction Of
        saSOCKS4ConnectRequest      : doSOCKS4Reply;
        saSOCKS4BindRequest         : doSOCKS4Reply;
        saSOCKS4BindConnect         : doSocks4Reply;
        saSOCKS5MethodRequest       : doSOCKS5MethodReply;
        saSOCKS5Authentication      : doSOCKS5AuthenticationReply;
        saSOCKS5ConnectRequest      : doSOCKS5Reply;
        saSOCKS5BindRequest         : doSOCKS5Reply;
        saSOCKS5BindConnect         : doSOCKS5Reply;
      End;
    End;

    If {$IfDef NewInBuffer}(fNewInBuffer.Available<>0){$Else}(fInBuffer<>''){$EndIf}
      And (fSOCKSaction=saIdle) Then // Either we were not negotiating socks, or it has ended and we have more data.
    Begin
      DispatchIncomingData;
    End;
  Finally
    DoAfterRead;
  End;
End;

Procedure TDDUCustomSocket.DoReadRequest;

Begin
  If (Connected Or (fSOCKSaction<>saIdle)) And (GetAvailableReadCount<>0) Then
  Begin
    PostMessage(Handle,cm_SocketMessage,SocketHandle,fd_read);
  End;
End;

procedure TDDUCustomSocket.DoRemoveClient(Client: TDDUCustomSocket);
begin
  If Assigned(fOnRemoveClient) Then
  Begin
    fOnRemoveClient(Self,Client);
  End;
end;

Procedure TDDUCustomSocket.DoSeekStream;

Begin
End;

Procedure TDDUCustomSocket.DoBlockSendDone(S : TStream; aName : String) ;

Var
  FreeIt                : Boolean;

Begin
  fSendCurrentBlockName   := '';
  fSendCurrentBlockSize   := 0;
  fSendCurrentBlockStream := Nil;

  FreeIt := True;
  If Assigned(fOnBlockSendDone) And Assigned(S) Then
  Begin
    fOnBlockSendDone(Self,S,aName,FreeIt);
  End;
  If FreeIt And Assigned(S) Then
  Begin
    If (S Is TDDUSocketMemoryStream) Then
    Begin
      //Debug('++Pre-Freeing(1) TDDUSocketMemoryStream [%0.8x] [%0.8x]  :: %s',[LongInt(S), TDDUSocketMemoryStream(S).Seq, TDDUSocketMemoryStream(S).ID]);
    End;
    SafeFreeAndNil(S);
  End;
End;

Procedure TDDUCustomSocket.DoSendStreamDone(S : TStream; IsPrivateMemoryStream : Boolean);

Var
  FreeIt                : Boolean;

Begin
  FreeIt := True;
  If Assigned(fOnSendStreamDone) And Assigned(S) And (Not IsPrivateMemoryStream) Then
  Begin
    fOnSendStreamDone(Self,S,FreeIt);
  End;
  If FreeIt Then
  Begin
    If (S Is TDDUSocketMemoryStream) Then
    Begin
      //Debug('++Pre-Freeing(2) TDDUSocketMemoryStream [%0.8x] [%0.8x]  :: %s',[LongInt(S), TDDUSocketMemoryStream(S).Seq,TDDUSocketMemoryStream(S).ID]);
    End;
    SafeFreeAndNil(S);
  End;
End;

Procedure TDDUCustomSocket.DoSignal(Signal : Cardinal);

Begin
  If Assigned(fOnSignal) Then
  Begin
    fOnSignal(Self,Signal);
  End;
End;

procedure TDDUCustomSocket.DoSocketAccept;

Var
  NewSocket             : TSocket;
  Size                  : Integer;
  SockAddrIn            : TSockAddrIn;
  DDUSocket             : TDDUCustomSocket;
  Handled               : Boolean;
  Async                 : Boolean;
  ClientClass           : TDDUCustomSocketClass;

Begin
  Case SocketMode Of
    smAuto,
    smAutoReset,
    smServerSingle,
    smServerSingleReset : Begin
                            Size := SizeOf(SockAddrIn);
                            FillChar(SockAddrIn,Size,#0);
                            NewSocket := Accept(SocketHandle,@SockAddrIn,@Size);
                            If Not (NewSocket=INVALID_SOCKET) Then
                            Begin
                              PrepareAsync(False);
                              Closesocket(SocketHandle);
                              fSocket := NewSocket;
                              LoadAddressLocal;

                              fIsServer := False;
                              PrepareAsync(True);
  //                            LoadAddressRemote; // Below is faster.
{$IFDEF WINSOCK2}
                              AddressRemote.SockAddr := SockAddrIn;
{$ELSE}
                              AddressRemote.IP := SockAddrIn.sin_addr.S_addr;
                              AddressRemote.Port := ntohs(SockAddrIn.sin_port);
{$ENDIF}
                              DoSocketConnect;
                            End
                            Else
                            Begin
                              SuddenDisconnect;
                            End;
                          End;
    smServerDispatch    : Begin
                            Size := SizeOf(SockAddrIn);
                            FillChar(SockAddrIn,Size,#0);
                            NewSocket := Accept(SocketHandle,@SockAddrIn,@Size);

                            WSAAsyncSelect(NewSocket,Handle,0,0); // We don't wanna get async messages from this socket.

                            Handled := False;
                            Async   := True;

                            If (NewSocket<>INVALID_SOCKET) Then
                            Begin
                              DDUSocket := Nil;
                              Try
                                DoAccept(NewSocket,SockAddrIn,DDUSocket,Handled,Async);
                              Except
                                CloseSocket(NewSocket);
                                NewSocket := INVALID_SOCKET;
                              End;

                              If (Not Handled) And (Not Assigned(DDUSocket)) Then
                              Begin
                                DoGetClientClass(ClientClass);
                                DDUSocket := ClientClass.Create(Owner);
                                fClients.Add(DDUSocket);

                                DDUSocket.fFreeingParent    := Self;
                                DDUSocket.fFreeOnDisconnect := True;

                                DoClientInit(DDUSocket);
                              End;
                              
                              If Assigned(DDUSocket) Then
                              Begin
                                DDUSocket.fSocket := NewSocket;
                                DDUSocket.OpenWithSocket(Async);
                              End;
                            End;
                          End;
  End;
End;

procedure TDDUCustomSocket.DoSocketConnect;

Begin
  fThrottle.AddSocket(SocketHandle,Handle);
  fThrottle.Active := True;

  fConnecting := False;
  fConnected := True;
  Try
    DoConnect;
  Except
    On E:Exception Do
    Begin
      SuddenDisconnect;
      If Not (E is EAbort) Then
      Begin
        Raise;
      End;
    End;
  End;
End;

procedure TDDUCustomSocket.DoSocketDisconnect;

Begin
  If Not Active Then
  Begin
    Exit;
  End;
  If Assigned(fDNS) And (fDNS.Action<>raNone) Then
  Begin
    fDNS.OnFoundAddress2 := Nil;
    fDNS.OnCancel2       := Nil;
    fDNS.Cancel;
  End;
//*****************************************************************************
// If we are in text mode, and there is text remaining in the buffer, kick it
// out as the last line.
//*****************************************************************************

  fDisconnecting := True;
  fConnectFailed := Connecting;

  If (SocketHandle<>INVALID_SOCKET) Then
  Begin
    Shutdown(SocketHandle,SD_SEND);
    While ((GetAvailableReadCount>0) Or (ReadLength>0)) And (Not DeferReading) And Drain And (Not fSuddenDisconnect) And (fSocksAction=saIdle) Do
    Begin
      DoRead;
    End;
  End;
  fSuddenDisconnect := False;

  fSocksAction := saIdle;
  
  If Not (SocketHandle=INVALID_SOCKET) Then
  Begin
    closesocket(SocketHandle);
  End;

  fSocket := INVALID_SOCKET;
  fAddressRemote.Clear;

  Flush;

  fConnecting := False;
  fConnected  := False;
  fActive     := False;

  DoDisconnect;
  fThrottle.RemoveSocket(SocketHandle);
  fThrottle.Active := False;
  fThrottle.Clear;

  fDisconnecting := False;

  If ConnectFailed Then
  Begin
    DoConnectFailed;
  End;

  BlockSendAbort;
  BlockReceiveAbort;
  DoFreeReceiveStream;

  If AutoDisconnectClients Then
  Begin
    SuddenDisconnectClients;
  End;

  If fFreeOnDisconnect Then // hmm, might wanna rethink this.
  Begin
    PostMessage(fFreeingParent.Handle,wm_FreeChild,0,LongInt(Self));
    Exit;
  End;

  If (not (csDestroying In ComponentState)) And (SocketMode In [smAutoReset,smServerSingleReset]) and (Not fSkipReset) Then
  Begin
    fActive      := True; 
    fPostWaiting := True; 
    PostMessage(fHandle,cm_WaitForConnect,0,10);
  End;

  fUDPSendAddress := '';
  fSkipReset := False;

  ReleaseRedirection;
End;

procedure TDDUCustomSocket.DoSocketRead;

Begin
  If (SocketHandle = INVALID_SOCKET) Or Disconnecting Then
  Begin
    Exit;
  End;

  If Throttle.CanRead(SocketHandle) Then
  Begin
    DoRead;
  End;
End;

procedure TDDUCustomSocket.DoSocketWrite;

Begin
  If (SocketHandle = INVALID_SOCKET) Then
  Begin
    Exit;
  End;

  If (fSOCKSAction<>saIdle) Then
  Begin
    NewDoWrite;
  End
  Else
  Begin
    If (Not DeferWriting) And Throttle.CanWrite(SocketHandle) Then
    Begin
      NEwDoWrite;
    End;
  End;
End;

Procedure TDDUCustomSocket.DoSOCKS4BindConnect(SockAddrIn : TSockAddrIn);

Begin
  fSocksAction := saIdle;
  AddressRemote.Clear;
{$IFDEF WINSOCK2}
  AddressRemote.SockAddr := SockAddrIn;
{$ELSE}
  AddressRemote.IP := SockAddrIn.sin_addr.S_addr;
  AddressRemote.Port := ntohs(SockAddrIn.sin_port);
{$ENDIF}
  DoSocketConnect;
End;

Procedure TDDUCustomSocket.DoSOCKS4BindReply(SockAddrIn : TSockAddrIn);

Var
  ansiExternalHost        : AnsiString;

Begin
  fSocksAction := saSOCKS4BindConnect;
  AddressLocal.Clear;
  AddressLocal.IP := SockAddrIn.sin_addr.S_addr;
  If (Proxy.ExternalHost<>'') Then
  Begin
    ansiExternalHost := Proxy.ExternalHost;
    AddressLocal.IP := Inet_Addr(PAnsiChar(ansiExternalHost ));  // Is it actually an IP?
    If (AddressLocal.IP=U_Long(INADDR_NONE)) Or (AddressLocal.IP=U_Long(INADDR_ANY)) Then
    Begin
      AddressLocal.IP := LookupName(Proxy.ExternalHost).S_addr;
    End;
  End;
  If (AddressLocal.IP=U_Long(INADDR_NONE)) Or (AddressLocal.IP=U_Long(INADDR_ANY)) Then
  Begin
    AddressLocal.Address := fSocksAddress;
  End;
  AddressLocal.Port := ntohs(SockAddrIn.sin_port);
  DoListen;
End;

Procedure TDDUCustomSocket.DoSOCKS4BindRequest;

Var
  IP                    : TINAddr;

Begin
  fSocksAction := saSOCKS4BindRequest;
  LoadAddressLocal;
  IP.s_Addr := fAddressLocal.IP;


  WriteOpenArray([#4,#2,
                 Byte(fAddressLocal.Port Shr 8),
                 Byte(fAddressLocal.Port And $FF),
                 Byte(IP.S_un_b.s_b1),
                 Byte(IP.S_un_b.s_b2),
                 Byte(IP.S_un_b.s_b3),
                 Byte(IP.S_un_b.s_b4),
                 fProxy.UserName,
                 #0]);
End;

Procedure TDDUCustomSocket.DoSOCKS4ConnectReply(SockAddrIn : TSockAddrIn);

Begin
  fSocksAction := saIdle;
  LoadAddressLocal;
  AddressRemote.Clear;
  AddressRemote.Text := fAddressDNS.Text;
  AddressRemote.Assign(fAddressDNS);
  DoSocketConnect;
End;

Procedure TDDUCustomSocket.DoSOCKS4ConnectRequest;

Var
  IP                    : TINAddr;

Begin
  fSocksAction := saSOCKS4ConnectRequest;
  IP.s_Addr := fAddressDNS.IP;
  WriteBytes( Bytes([4,1,
                 Byte(fAddressDNS.Port Shr 8),
                 Byte(fAddressDNS.Port And $FF),
                 Byte(IP.S_un_b.s_b1),
                 Byte(IP.S_un_b.s_b2),
                 Byte(IP.S_un_b.s_b3),
                 Byte(IP.S_un_b.s_b4),
                 fProxy.UserName,
                 0]));
End;

Procedure TDDUCustomSocket.DoSOCKS4Reply;

Var
  ErrorCode             : Integer;
  SockAddrIn            : TSockAddrIn;
  SocksReply            : Integer;
  Version               : Integer;
  SockReplyData         : String;

Begin
  If (InBufferLength >=8) Then
  Begin
{$IFDEF NewInBuffer}
    SockReplyData := fNewInBuffer.ReadString(8);
{$ELSE}
    SockReplyData := Copy(fInBuffer,1,8);
    Delete(fInBuffer,1,8);
{$ENDIF}
    Version    := Byte(SockReplyData[1]);
    SocksReply := Byte(SockReplyData[2]);

    If (Version<>0) Then
    Begin
      Case fSocksAction Of
        saSOCKS4ConnectRequest : fErrorText := Format(sSocks4ConnectError,[Version]);
        saSOCKS4BindRequest    : fErrorText := Format(sSocks4BindError,[Version]);
        saSOCKS4BindConnect    : fErrorText := Format(sSocks4BindConnectError,[Version]);
      End;
      ErrorCode := 0;
      DoError(eeSocksVersion,ErrorCode);
      SuddenDisconnect;
      Exit;
    End;

    FillChar(SockAddrIn,SizeOf(SockAddrIn),#0);
    SockAddrIn.sin_family := AF_INET;
    Delete(SockReplyData,1,2);
    Move(SockReplyData[1],SockAddrIn.sin_port,SizeOf(SockAddrIn.sin_port));
    Delete(SockReplyData,1,SizeOf(SockAddrIn.sin_port));
    Move(SockReplyData[1],SockAddrIn.sin_addr.S_addr,Sizeof(SockAddrIn.sin_addr.S_addr));
    Delete(SockReplyData,1,Sizeof(SockAddrIn.sin_addr.S_addr));

    Case SocksReply Of
      90 : Begin
             Case fSocksAction Of
               saSOCKS4ConnectRequest : doSOCKS4ConnectReply(SockAddrIn);
               saSOCKS4BindRequest    : doSOCKS4BindReply(SockAddrIn);
               saSOCKS4BindConnect    : doSocks4BindConnect(SockAddrIn);
             End;
           End;
      91 : fErrorText := sSocks4Error91;
      92 : FErrorText := sSocks4Error92;
      93 : fErrorText := SSocks4Error93;
    Else
      fErrorText := Format(sSocks4ErrorUnknown,[SocksReply]);
    End;

    If (fErrorText<>'') Then
    Begin
      Case fSocksAction Of
        saSOCKS4ConnectRequest : DoError(eeSocks4Connect,SocksReply);
        saSOCKS4BindRequest    : DoError(eeSocks4Bind,SocksReply);
        saSOCKS4BindConnect    : DoError(eeSocks4BindConnect,SocksReply);
      End;
      SuddenDisconnect;
    End;
  End;
End;

Procedure TDDUCustomSocket.DoSOCKS5AuthenticationReply;

Var
  ErrorCode             : Integer;
  SocksReply            : Integer;
  Version               : Integer;
  SockReplyData         : String;

Begin
//*****************************************************************************
// Wait till there is at least there enough data to process the reply, we
// can come back later if we don't get enough data now.
//*****************************************************************************
  If (InBufferLength>=2) Then
  Begin
{$IFDEF NewInBuffer}
    SockReplyData := fNewInBuffer.ReadString(2);
{$ELSE}
    SockReplyData := Copy(fInBuffer,2);
    Delete(fInBuffer,1,2);
{$ENDIF}
    Version := Byte(SockReplyData[1]);
    SocksReply := Byte(SockReplyData[2]);

    If (Version<>1) Then
    Begin
      fErrorText := Format(sSocks5AuthError,[Version]);
      ErrorCode := 0;
      DoError(eeSocksVersion,ErrorCode);
      SuddenDisconnect;
    End
    Else
    Begin
      If (SocksReply=0) Then
      Begin
        Case fSocksMode Of
          smBind    : DoSocks5BindRequest;
          smConnect : DoSOCKS5ConnectRequest;
        End;
      End
      Else
      Begin
        fErrorText := sSocks5AuthFailed;
        ErrorCode := SocksReply;
        doError(eeSocks5Authentication,ErrorCode);
        SuddenDisconnect;
      End;
    End;
  End;
End;

Procedure TDDUCustomSocket.DoSOCKS5AuthenticationRequest;

Begin
  fSocksAction := saSOCKS5Authentication;
//  WriteOpenArray([#1,Char(Length(fProxy.UserName)),fProxy.UserName,Char(Length(fProxy.Password)),fProxy.Password]);
  WriteBytes(Bytes([1,
                    Length(fProxy.UserName),
                    fProxy.UserName,
                    Length(fProxy.Password),
                    fProxy.Password]));
End;

Procedure TDDUCustomSocket.DoSOCKS5BindConnect(SockAddrIn : TSockAddrIn);

Begin
  fSOCKSAction := saIdle;
  AddressRemote.Clear;
  AddressRemote.IP := SockAddrIn.sin_addr.S_addr;
  AddressRemote.Port := ntohs(SockAddrIn.sin_port);
  DoSocketConnect;
End;

Procedure TDDUCustomSocket.DoSOCKS5BindReply(SockAddrIn : TSockAddrIn);

Var
  ansiExternalHost        : AnsiString;

Begin
  fSocksAction := saSOCKS5BindConnect;
  AddressLocal.Clear;
  AddressLocal.IP := SockAddrIn.sin_addr.S_addr;
  If (Proxy.ExternalHost<>'') Then
  Begin
    ansiExternalHost := Proxy.ExternalHost;
    AddressLocal.IP := Inet_Addr(PAnsiChar(ansiExternalHost));  // Is it actually an IP?
    If (AddressLocal.IP=U_Long(INADDR_NONE)) Or (AddressLocal.IP=U_Long(INADDR_ANY)) Then
    Begin
      AddressLocal.IP := LookupName(Proxy.ExternalHost).S_addr;
    End;
  End;
  If (AddressLocal.IP=U_Long(INADDR_NONE)) Or (AddressLocal.IP=U_Long(INADDR_ANY)) Then
  Begin
    AddressLocal.Address := fSocksAddress;
  End;
  AddressLocal.Port := ntohs(SockAddrIn.sin_port);
  DoListen;
End;

Procedure TDDUCustomSocket.DoSOCKS5BindRequest;

Var
  IP                 : TINAddr;

Begin
  fSocksAction := saSOCKS5BindRequest;
  LoadAddressLocal;
  IP.S_Addr := AddressLocal.IP;
//  WriteOpenArray([#5,#2,#0,#1,
//                 Char(IP.S_un_b.s_b1),
//                 Char(IP.S_un_b.s_b2),
//                 Char(IP.S_un_b.s_b3),
//                 Char(IP.S_un_b.s_b4),
//                 Char(AddressLocal.Port Shr 8),Char(AddressLocal.Port And $ff)]);
  WriteBytes(Bytes([5,2,0,1,
                 (IP.S_un_b.s_b1),
                 (IP.S_un_b.s_b2),
                 (IP.S_un_b.s_b3),
                 (IP.S_un_b.s_b4),
                 (AddressLocal.Port Shr 8),
                 (AddressLocal.Port And $ff)]));
End;

Procedure TDDUCustomSocket.DoSOCKS5ConnectReply(SockAddrIn : TSockAddrIn);

Begin
  fSocksAction := saIdle;
  AddressLocal.Clear;
  AddressLocal.IP := SockAddrIn.sin_addr.S_addr;
  AddressLocal.Port := ntohs(SockAddrIn.sin_port);
  AddressRemote.Clear;
  AddressRemote.Text := fAddressDNS.Text;
  AddressRemote.Assign(fAddressDNS);
  DoSocketConnect;
End;

Procedure TDDUCustomSocket.DoSOCKS5ConnectRequest;

Var
  IP                 : TINAddr;

Begin
  fSocksAction := saSOCKS5ConnectRequest;
  if (fAddressDNS.Address='') Then // Resolve Host Name
  Begin
//    WriteOpenArray([#5,#1,#0,#3,
//                   Char(Length(fAddressDNS.Host)),fAddressDNS.Host,
//                   Char(fAddressDNS.Port Shr 8),Char(fAddressDNS.Port And $ff)]);
    WriteBytes(Bytes([5,1,0,3,
                   (Length(fAddressDNS.Host)),
                   fAddressDNS.Host,
                   (fAddressDNS.Port Shr 8),
                   (fAddressDNS.Port And $ff)]));
  End
  Else
  Begin  // send an IP.
    IP.S_Addr := fAddressDNS.IP;
//    WriteOpenArray([#5,#1,#0,#1,
//                   Char(IP.S_un_b.s_b1),
//                   Char(IP.S_un_b.s_b2),
//                   Char(IP.S_un_b.s_b3),
//                   Char(IP.S_un_b.s_b4),
//                   Char(fAddressDNS.Port Shr 8),Char(fAddressDNS.Port And $ff)]);
    WriteBytes(Bytes([5,1,0,1,
                   (IP.S_un_b.s_b1),
                   (IP.S_un_b.s_b2),
                   (IP.S_un_b.s_b3),
                   (IP.S_un_b.s_b4),
                   (fAddressDNS.Port Shr 8),(fAddressDNS.Port And $ff)]));
  End;
End;

Procedure TDDUCustomSocket.DoSOCKS5MethodReply;

Var
  ErrorCode             : Integer;
  SocksMethod           : Integer;
  SockReplyData         : String;

Begin
  If (InBufferLength>=2) Then
  Begin
{$IFDEF NewInBuffer}
    SockReplyData := fNewInBuffer.ReadString(2);
{$ELSE}
    SockReplyData := Copy(fInBuffer,1,2);
    Delete(fInBuffer,1,2);
{$ENDIF}
    If (SockReplyData[1]<>#5) Then
    Begin
      fErrorText := sSocks5MethodsError+IntToStr(Byte(SockReplyData[1]));
      ErrorCode := 0;
      doError(eeSocks5Methods,ErrorCode);
      SuddenDisconnect;
      Exit;
    End;
    SocksMethod := Byte(SockReplyData[2]);
    If (SocksMethod=02) Then  // Password Authentication requested.
    Begin
      DoSOCKS5AuthenticationRequest;
    End Else If (SocksMethod=00) Then    // No authentication required.
    Begin
      Case fSocksMode Of
        smBind    : DoSocks5BindRequest;
        smConnect : DoSOCKS5ConnectRequest;
      End;
    End
    Else if (SocksMethod=$ff) Then  // No methods available.
    Begin
      fErrorText := sSocks5MethodsNoMethods;
      doError(eeSocks5Methods,SocksMethod);
      SuddenDisconnect;
    End Else // No clue, we didn't ask for, and don't support it.  Time to leave.
    Begin
      fErrorText := sSocks5MethodsUnknown;
      doError(eeSocks5Methods,SocksMethod);
      SuddenDisconnect;
    End;
  End;
End;

Procedure TDDUCustomSocket.DoSOCKS5MethodRequest;

Begin
//*****************************************************************************
// Just because we have authenication information does not mean that we should
// always use it.  If we have it, let the SOCKS server decide if we need to
// send it.
//*****************************************************************************
  fSocksAction := saSOCKS5MethodRequest;
  If fProxy.UseAuthentication Then
  Begin
    WriteOpenArray([#5,#2,#00,#02]);
  End
  Else
  Begin
    WriteOpenArray([#5,#1,#00]);
  End;
End;

Procedure TDDUCustomSocket.DoSOCKS5Reply;

Var
  aType                 : Byte;
  ErrorCode             : Integer;
  Host                  : String;
  ReplySize             : Integer;
  SockAddrIn            : TSockAddrIn;
  SocksReply            : Integer;
  Version               : Integer;

Function ReplySizeOk : Boolean;

Var
  Needed                : Integer;
  ReplyData             : String;

Begin
  ReplySize := 0;
  Result := False;
  If (InBufferLength<4) Then Exit; // Code is too small.
{$IFDEF NewInBuffer}
  ReplyData := fNewInBuffer.PeekString(5);
{$ELSE}
  ReplyData := Copy(fInBuffer,1,5);
{$ENDIF}

  Needed := 4;
  Case ReplyData[4] of
    #1 : Inc(Needed,SizeOf(TINAddr));
    #3 : Begin
           If (Length(ReplyData)<5) Then
             Exit; // Code is too small.
           Inc(Needed,1+Byte(ReplyData[5]));
         End;
    #4 : Inc(Needed,16);
  End;
  Inc(Needed,2);
  ReplySize := Needed;
  Result := InBufferLength>=Needed;
End;

Var
  ReplyData : String;

Begin
  If ReplySizeOK Then
  Begin
{$IFDEF NewInBuffer}
    ReplyData := fNewInBuffer.ReadString(ReplySize);
{$ELSE}
    ReplyData := Copy(fInBuffer,ReplySize);
    Delete(fInBuffer,1,ReplySize);
{$ENDIF}

    Version    := Byte(ReplyData[1]);
    SocksReply := Byte(ReplyData[2]);
    If (Version<>5) Then
    Begin
      fSocksAction := saIdle;
      Case fSocksAction Of
        saSOCKS5ConnectRequest : fErrorText := Format(sSocks5ConnectError,[Version]);
        saSOCKS5BindRequest    : fErrorText := Format(sSocks5BindError,[Version]);
        saSOCKS5BindConnect    : fErrorText := Format(sSocks5BindConnectError,[Version]);
      End;
      ErrorCode := 0;
      DoError(eeSocksVersion,ErrorCode);
      SuddenDisconnect;
    End Else If (SocksReply<>0) Then
    Begin
      fSocksAction := saIdle;
      Case SocksReply Of
        1 : fErrorText := sSocks5Error1;
        2 : fErrorText := sSocks5Error2;
        3 : fErrorText := sSocks5Error3;
        4 : fErrorText := sSocks5Error4;
        5 : fErrorText := sSocks5Error5;
        6 : fErrorText := sSocks5Error6;
        7 : fErrorText := sSocks5Error7;
        8 : fErrorText := sSocks5Error8;
      Else
        fErrorText :=  sSocks5ErrorUnknown+IntToStr(SocksReply);
      End;
      Case fSocksAction Of
        saSOCKS5ConnectRequest : DoError(eeSocks5Connect,SocksReply);
        saSOCKS5BindRequest    : DoError(eeSocks5Bind,SocksReply);
        saSOCKS5BindConnect    : DoError(eeSocks5BindConnect,SocksReply);
      End;
      SuddenDisconnect;
    End Else
    Begin
      FillChar(SockAddrIn,SizeOf(SockAddrIn),#0);
      SockAddrIn.sin_family := AF_INET;

      aType := Byte(ReplyData[4]);
      Delete(ReplyData,1,4);

      If (aType=1) Then  // IP Address
      Begin
        Move(ReplyData[1],SockAddrIn.sin_addr.S_addr,SizeOf(SockAddrIn.sin_addr.S_addr));
        Delete(ReplyData,1,SizeOf(SockAddrIn.sin_addr.S_addr));
      End Else If (aType=3) Then // Host name
      Begin
        SetLength(Host,Byte(ReplyData[1]));
        Move(ReplyData[2],Host[1],Byte(ReplyData[1]));
        Delete(ReplyData,1,Byte(ReplyData[1])+1);
//*****************************************************************************
// We want the IP, not a host name here.  Obviously, the socks server has
// looked it up, so it should now be sitting in a nearby DNS cache. Failing
// that, SOCKS5 users that do not resolve the IP directly will suffer from
// a blocking call.  Its recommended to ClientresolveIPs whereever possible.
//*****************************************************************************
        SockAddrIn.sin_addr := LookupName(host);
      End Else  // IP V6, not supported by me.
      begin
        Delete(ReplyData,1,16+2);
        fErrorText := sSocks5IPV6Fail;
        ErrorCode := 0;
        doError(eeSocksGeneral,ErrorCode);
        SuddenDisconnect;
        Exit;
      End;
      Move(ReplyData[1],SockAddrIn.sin_port,Sizeof(SockAddrIn.sin_port));
      Delete(ReplyData,1,Sizeof(SockAddrIn.sin_port));
      Case fSocksAction Of
        saSOCKS5ConnectRequest : doSOCKS5ConnectReply(SockAddrIn);
        saSOCKS5BindRequest    : doSOCKS5BindReply(SockAddrIn);
        saSOCKS5BindConnect    : doSOCKS5BindConnect(SockAddrIn);
      End;
    End;
  End;
End;

Procedure TDDUCustomSocket.DoSocksConnect;

Var
  SockAddrIn            : TSockAddrIn;

Begin
  If fProxy.ClientResolveIP And (fAddressDNS.Address='') And (fSocksMode=smConnect) Then
  Begin
    fSocksAction := saResolveDNS;
    Try
      If Not PrepareAddress(SockAddrIn) Then
      Begin
        Exit;
      End;
    Except
      SuddenDisconnect;
      Exit;
    End;
  End;
  If (fAddressDNS.Service<>'') Then
  Begin
    PreparePort(SockAddrIn);
  End;

  Case fProxy.SocksVersion Of
    4 : Begin
          Case fSocksMode Of
            smBind    : DoSocks4BindRequest;
            smConnect : DoSOCKS4ConnectRequest;
          End;
        End;
    5 : DoSOCKS5MethodRequest;
  End;
End;

Procedure TDDUCustomSocket.DoText(Const Text : String);

Var
  At                    : Integer;

Begin
  fText := Text;
  Try
    If BlockAutoStart And (Length(BlockAutoStartPrefix)<>0) And (StartsWith(fText,BlockAutoStartPrefix)) Then
    Begin
      fText := TextAfter(fText,BlockAutoStartPrefix);
      At := Pos(',',fText);
      If At<>0 Then
      Begin
        ReceiveBlock( StrToIntDef(Copy(fText,1,At-1),0) , Copy(fText,At+1,Length(fText)-1) );
      End
      Else
      Begin
        ReceiveBlock( 0,fText);
      End;
    End Else If Assigned(fOnText) Or Assigned(fOnTextEx) Then
    Begin
      If (DataMode=dmCookedText) Then
      Begin
        fText := printableBytes( bString(fText) );
      End;
      If Assigned(fOnTextEx) Then
      Begin
        fOnTextEx(Self,fText);
      End;
      If Assigned(fOnText) Then
      Begin
        fOnText(Self);
      End;
    End;
  Finally
    fText := '';
  End;
End;

Procedure TDDUCustomSocket.DoThrottle(Sender : TObject);

Begin
  If Assigned(fOnThrottle) Then
  Begin
    fOnThrottle(Self);
  End;
End;

Procedure TDDUCustomSocket.DoThrottleReadOff(Sender : TObject);

Begin
  If Assigned(fOnThrottleReadOff) Then
  Begin
    fOnThrottleReadOff(Self);
  End;
End;

Procedure TDDUCustomSocket.DoThrottleReadOn(Sender : TObject);

Begin
  If Assigned(fOnThrottleReadOn) Then
  Begin
    fOnThrottleReadOn(Self);
  End;
End;

Procedure TDDUCustomSocket.DoThrottleTimeout(Sender : TObject; Causes : TTimeoutCauses);

Var
  ForceDisconnect : Boolean;

Begin
  ForceDisconnect := True;
  If Assigned(fOnTimeout) Then
  Begin
    fOnTimeout(Self,Causes,ForceDisconnect);
  End;
  If ForceDisconnect Then
  Begin
    Disconnect;
  End;
End;

Procedure TDDUCustomSocket.DoThrottleWriteOff(Sender : TObject);

Begin
  If Assigned(fOnThrottleWriteOff) Then
  Begin
    fOnThrottleWriteOff(Self);
  End;
End;

Procedure TDDUCustomSocket.DoThrottleWriteOn(Sender : TObject);

Begin
  If Assigned(fOnThrottleWriteOn) Then
  Begin
    fOnThrottleWriteOn(Self);
  End;
End;

Procedure TDDUCustomSocket.NewDoWrite;

Var
  ErrorCode             : Integer;
  StreamOffset          : Int64;
  ToWrite               : UInt64;
  Wrote                 : UInt64;
  S                     : TStream;
  ExitNeeded            : Boolean;

{$IFDEF NewOutBuffer}
  Signal                : TSignal;
  aWriteBuffer          : Pointer;
  aWriteBufferSize      : Integer;
{$ELSE}
  Arg                   : Cardinal;
  OutBufferString       : String;
  StreamBuffer          : Pointer;
  StreamBufferSize      : Integer;
{$ENDIF}

  WouldBlock            : Boolean;

Begin
  WouldBlock := False;
{$REGION 'NewOutBuffer'}
{$IFDEF NewOutBuffer}
  While Not (OutBufferEmpty Or WouldBlock) DO
  Begin
    ToWrite          := 0;
    Wrote            := 0;
    StreamOffset     := 0;
    aWriteBufferSize := 0;
    aWriteBuffer     := fWriteBuffer;
    Try
      If fNewOutBuffer.Signaled Then
      Begin
{$Region 'Signals'}
        Signal := TSignal.Create;
        Try
          Signal.Assign(fNewOutBuffer.Signal);

          Case Signal.ID Of

          signalSETUPSENDADDRESSMarker :
            Begin
              fNewOutBuffer.ClearSignal;
              fUDPSendAddress := Signal.Name;
            End;

          signalSIGNALMarker :
            Begin
              fNewOutBuffer.ClearSignal;
              DoSignal(Signal.Tag);
              DoWriteRequest;
            End;

          signalDISCONNECTMarker :
            Begin
              fNewOutBuffer.ClearSignal;
              ExitNeeded := fFreeOnDisconnect;
              Disconnect;
              If ExitNeeded Then Exit;
            End;

          signalCALLBACKMarker :
            Begin
              fNewOutBuffer.ClearSignal;
              DoCallback(Signal.Name);
              DoWriteRequest;
            End;

          signalSendBLOCKMarker,
          signalSTREAMMarker,
          signalPRIVATEMEMORYSTREAMMarker :
            Begin
              S := TStream(Signal.&Object);

              If (fNewOutBuffer.Signal.Tag=0) Then
              Begin
                fNewOutBuffer.Signal.Write_Tag := 1;
                If (Signal.ID=signalSendBLOCKMarker) Then
                Begin
                  fSendCurrentBlockName   := Signal.Name;
                  fSendCurrentBlockSize   := S.Size-S.Position;
                  fSendCurrentBlockStream := S;
                  DoBlockSendStart(S,Signal.Name,S.Size-S.Position);
                End;
              End;

              If Assigned(S) Then
              Begin
                Try
                  StreamOffset := S.Position;
                  ToWrite := Internal_DoWrite_ToWrite(UInt64(S.Size-S.Position));

                  If (ToWrite<>0) And (Not Assigned(aWriteBuffer)) Then
                  Begin
                    aWriteBufferSize := ToWrite;
                    GetMem(aWriteBuffer,aWriteBufferSize);
                  End;
                  S.Read(aWriteBuffer^,ToWrite);
                Except
                  fNewOutBuffer.ClearSignal;

                  Internal_StreamDone(Signal.ID,Signal.Name,S);
                  Continue;
                End;
              End;

              If (ToWrite<>0) Then
              Begin
                Wrote := Internal_DoWrite(aWriteBuffer,ToWrite);

                If (Integer(Wrote)=SOCKET_ERROR) Then
                Begin
                  ErrorCode := WSAGetLastError;

                  If ErrorCode=WSAEWOULDBLOCK Then
                  Begin
                    WouldBlock := True;
                  End Else If (ErrorCode<>0) Then
                  Begin
                    fNewOutBuffer.ClearSignal;
                    Internal_StreamDone(Signal.ID,Signal.Name,S);
                    DoError(eeRead, ErrorCode);
                    SuddenDisconnect;
                    Exit;
                  End;
                  Wrote := 0;
                End;
              End;

              If Assigned(S) Then
              Begin
                If (ToWrite<>Wrote) Then
                Begin
                  S.Seek(StreamOffset+Integer(Wrote),soFromBeginning);
                End;
                Internal_StreamProgress(Signal.ID,Signal.Name,S);
              End;

              If (Not Assigned(S)) Or (S.Position=S.Size) Then
              Begin
                fNewOutBuffer.ClearSignal;
                Internal_StreamDone(Signal.ID,Signal.Name,S);
              End;
            End;

          End; // End Case
        Finally
          FreeAndNil(Signal);
        End;
{$ENDREGION}
      End
      Else
      Begin
{$REGION 'Data'}
        If Not Throttle.CanWrite(fSocket) Then
        Begin
          WouldBlock := True;
          Continue;
        End;

        ToWrite := Internal_DoWrite_ToWrite(fNewOutBuffer.Available);
// Get Data into write buffer
        If (ToWrite<>0) Then
        Begin
          If Not Assigned(aWriteBuffer) Then
          Begin
            aWriteBufferSize := ToWrite;
            GetMem(aWriteBuffer,aWriteBufferSize);
          End;
          ToWrite := fNewOutBuffer.PeekData(aWriteBuffer,ToWrite);
        End;
        If (ToWrite<>0) Then
        Begin
// Write Data
          Wrote := Internal_DoWrite(aWriteBuffer,ToWrite);
// Handle any errors.
          If (Integer(Wrote)=SOCKET_ERROR) Then
          Begin
            ErrorCode := WSAGetLastError;
            If (ErrorCode=WSAEWOULDBLOCK) Then
            Begin
              WouldBlock := True;
            End Else If (ErrorCode<>0) Then
            Begin
              DoError(eeRead, ErrorCode);
              SuddenDisconnect;
              Exit;
            End;
            Wrote := 0;
          End;
//Remove written data from buffer.
          fNewOutBuffer.Seek(Wrote);
        End
        Else
        Begin
// no point going round the loop again.
          WouldBlock := True;
        End;
{$ENDREGION}
      End;
    Finally
      If (Wrote<>0) Then
      Begin
        fDataWrote := fDataWrote+Wrote;
        Throttle.RegisterDataWrite(Wrote);
      End;

      If (aWriteBuffer<>fWriteBuffer) And Assigned(aWriteBuffer) Then
      Begin
        FreeMem(aWriteBuffer,aWriteBufferSize);
      End;
    End;
  End;
{$ENDIF}
{$ENDREGION}

{$REGION 'STRING BUFFER'}
{$IFNDEF NewOutBuffer}
  While Not (OutBufferEmpty Or WouldBlock) DO
  Begin
    ToWrite          := 0;
    Wrote            := 0;
    StreamBuffer     := Nil;
    StreamBufferSize := 0;
    Try
      Arg             := Cardinal(fOutBuffer.objects[0]);
      OutBufferString := fOutBuffer[0];
      If (Arg<>0)Then
      Begin
{$REGION 'Signals'}
        If (StartsWith(OutBufferString,constSETUPSENDADDRESSMarker)) Then
        Begin
          fOutBuffer.Delete(0);
          fUDPSendAddress := TextAfter(OutBufferString,constSETUPSENDADDRESSMarker);
        End Else If (OutBufferString=constSIGNALMarker) Then
        Begin
          fOutBuffer.Delete(0);
          DoSignal(Arg);
          DoWriteRequest;
        End Else If (OutBufferString=constDISCONNECTMarker) Then
        Begin
          fOutBuffer.Delete(0);
          ExitNeeded := fFreeOnDisconnect;
          Disconnect;
          If ExitNeeded Then Exit;
        End Else If (Copy(OutBufferString,1,8) =constCALLBACKMarker) Then  // Callback
        Begin
          fOutBuffer.Delete(0);
          DoCallback(OutBufferString);
          DoWriteRequest;
        End Else If (StartsWith(OutBufferString,constBLOCKMarker)) Or
                    (OutBufferString=constSTREAMMarker) Or (OutBufferString=constPRIVATEMEMORYSTREAMMarker) Then
        Begin
          If Not Throttle.CanWrite(fSocket) Then
          Begin
            WouldBlock := True;
            Continue;
          End;
{$REGION 'Load Stream Data'}
          StreamOffset := 0;
          S := TStream(Arg);
          If Assigned(S) Then
          Begin
            Try
              StreamOffset := S.Position;
              ToWrite := Internal_DoWrite_ToWrite(S.Size-S.Position);

              StreamBufferSize := ToWrite;
              GetMem(StreamBuffer,StreamBufferSize);

              S.Read(StreamBuffer^,ToWrite);
            Except
              fOutBuffer.Delete(0);
              Internal_StreamDone(OutBufferString,S);
              Continue;
            End;
          End;
{$ENDREGION}
          If (ToWrite<>0) Then
          Begin
            Wrote := Internal_DoWrite(StreamBuffer,ToWrite);
            If (Integer(Wrote)=SOCKET_ERROR) Then
            Begin
              ErrorCode := WSAGetLastError;

              If (ErrorCode=WSAEWOULDBLOCK) Then
              Begin
                WouldBlock := True;
              End ELse If (ErrorCode<>0) Then
              Begin
                fOutBuffer.Delete(0);
                Internal_StreamDone(OutBufferString,S);
                DoError(eeRead, ErrorCode);
                SuddenDisconnect;
                Exit;
              End;
              Wrote := 0;
            End;
          End;
          
          If Assigned(S) Then
          Begin
            If (ToWrite<>Wrote) Then
            Begin
              S.Seek(StreamOffset+Integer(Wrote),soFromBeginning);
            End;
            Internal_StreamProgress(OutBufferString, S);
          End;

          If (Not Assigned(S)) Or (S.Position=S.Size) Then
          Begin
            fOutBuffer.Delete(0);
            Internal_StreamDone(OutBufferString,S);
          End;

          fDataWrote := fDataWrote+Wrote;
          Throttle.RegisterDataWrite(Wrote);
        End;
{$ENDREGION}
      End
      Else
      Begin
{$REGION 'Data'}
        If Not Throttle.CanWrite(fSocket) Then
        Begin
          WouldBlock := True;
          Continue;
        End;
        ToWrite := Internal_DoWrite_ToWrite( Length(OutBufferString) );
        If (ToWrite=0) Then
        Begin
          WouldBlock := True;
        End
        Else
        Begin
          Wrote := Internal_DoWrite(Pointer(OutBufferString),ToWrite);
          If (Integer(Wrote)=SOCKET_ERROR) Then
          Begin
            ErrorCode := WSAGetLastError;
            If (ErrorCode=WSAEWOULDBLOCK) Then
            Begin
              WouldBlock := True;
            End Else If (ErrorCode<>0) Then
            Begin
              DoError(eeRead, ErrorCode);
              SuddenDisconnect;
              Exit;
            End;
            Wrote := 0;
          End;

          Delete(OutBufferString,1,Wrote);
          If (Length(OutBufferString)=0) Then
          Begin
            fOutBuffer.Delete(0);
          End
          Else
          Begin
            fOutBuffer[0] := OutBufferString;
          End;
          fDataWrote := fDataWrote+Wrote;
          Throttle.RegisterDataWrite(Wrote);
        End;
{$ENDREGION}
      End;
    Finally
      If Assigned(StreamBuffer) Then
      Begin
        FreeMem(StreamBuffer,StreamBufferSize);
      End;
    End;
  End;
{$ENDIF}
{$ENDREGION}

  If Assigned(fOnWrite) Then
  Begin
    fOnWrite(Self);  // Strictly meant for Progress indicators.
  End;

//  If WouldBlock Or (Not OutBufferEmpty) Then
  Begin
    DoWriteRequest;
  End;
End;

Procedure TDDUCustomSocket.DoWriteRequest;

Begin
  If (Connected Or (fSOCKSaction<>saIdle)) And (Not OutBufferEmpty) Then
  Begin
    If (SocketProtocol IN [spUDP,spUDPBroadcast]) Then
    Begin
      DoSocketWrite;
    End
    Else
    Begin
      PostMessage(Handle,cm_SocketMessage,SocketHandle,fd_write);
    End;
  End;
End;

Procedure TDDUCustomSocket.EOLDetection;

Var
  CRAt                  : UInt64;
  LFAt                  : UInt64;

Begin
  If (EOL.Remote=emUnknown) Then
  Begin
{$IFDEF NewInBuffer}
    fNewInBuffer.FindData(__CR ,CRAt);
    fNewInBuffer.FindData(__LF,LFAt);
{$ELSE}
    CRAt := Pos(#13,fInBuffer);
    LFAt := Pos(#10,fInBuffer);
{$ENDIF}
    If (CRAt=0) And (LFAt=0) Then  // Neither are found, no way to tell.
    Begin
    End Else If (CRAt=LFAt-1) Then  // Found a LF/CR pair.
    Begin
      EOL.Remote := emCRLF;
    End Else If (LFAt=CRAt+1) Then  // Found a LF/CR pair
    Begin
      EOL.Remote := emLFCR
    End Else If (LFAt=0) And (CRAt<>InBufferLength) Then // There is only a CR in the buffer, and it is not the last char.
    Begin
      EOL.Remote := emCROnly;
    End Else If (CRAt=0) And (LFAt<>InBufferLength) Then // There is only a LF in the buffer, and it is not the last char.
    Begin
      EOL.Remote := emLFOnly;
    End Else If (LFAt<CRAt) And ((CRAt-LfAt)>1) Then // Sending LFs, CR detection was bogus.
    Begin
      EOL.Remote := emLFOnly;
    End Else If (CRAt<LFAt) And ((LFAt-CRAt)>1) Then // Sending CRs, LS detection was bogus.
    Begin
      EOL.Remote := emCROnly;
    End;
  End;
End;

function TDDUCustomSocket.FindBytes(Bytes: TBytes; OUt At : UInt64): Boolean;
begin
{$IFDEF NewInBuffer}
  Result := fNewInBuffer.FindData(Bytes,At);
{$ELSE}
  At := 0;
//  At := Pos(#13#10,fInBuffer);
  Result := (At<>0);
{$ENDIF}
end;

Procedure TDDUCustomSocket.Flush;

Begin
  FlushInput;
  FlushOutput;
End;

Procedure TDDUCustomSocket.FlushInput;

Begin
{$IFDEF NewInBuffer}
  fNewInBuffer.Flush;
{$ELSE}
  fInBuffer := '';
{$ENDIF}
End;

Procedure TDDUCustomSocket.FlushOutput;

{$IFNDEF NewOutBuffer}
Var
  Loop                  : Integer;
  Args                  : Pointer;
  OutBufferString       : String;
{$ENDIF}

Begin
  fUDPSendAddress := '';
{$IFDEF NewOutBuffer}
  Try
    While Not fNewOutBuffer.Empty Do
    Begin
      If fNewOutBuffer.Signaled Then
      Begin
        Internal_StreamDone(fNewOutBuffer.Signal.ID,fNewOutBuffer.Signal.Name,TStream(fNewOutBuffer.Signal.&Object));
      End;
      fNewOutBuffer.TossFirstNode;
    End;
  Finally
    fNewOutBuffer.Flush;
  End;
{$ELSE}
  Try
    For Loop := 0 To fOutBuffer.Count-1 Do
    Begin
      Args            := Pointer(fOutBuffer.Objects[0]);
      OutBufferString := fOutBuffer[0];
      fOutBuffer.Delete(0);
      If Assigned(Args) Then
      Begin
        Internal_StreamDone(OutBufferString,Args);
      End;
    End;
  Finally
    fOutBuffer.Clear;
  End;
{$ENDIF}
End;

procedure TDDUCustomSocket.ForceRead;
begin
  DoRead;
end;

procedure TDDUCustomSocket.ForceWrite;
begin
  NewDoWrite;
end;

Function TDDUCustomSocket.GetCookedText : String;

Begin
  If DataMode in [dmCookedText,dmText] Then
  Begin
    Result := fText;
  End
  Else
  Begin
{$IFDEF NewInBuffer}
    Result := printableBytes( fNewInBuffer.ReadBytes (fNewInBuffer.DataAvailable) );
{$ELSE}
    Result := printableBytes( bString(fInBuffer) ) fInBuffer;
{$ENDIF}
  End;
End;

{$IFDEF NewInBuffer}
function TDDUCustomSocket.GetInBuffer: String;
begin
  Result := fNewInBuffer.PeekString(fNewInBuffer.Available);
end;
{$ENDIF}
function TDDUCustomSocket.GetInBufferBytes: TBytes;
begin
{$IFDEF NewInBuffer}
  Result := fNewInBuffer.PeekBytes(fNewInBuffer.Available);
{$ELSE}
  Result := bString(fInBuffer);
{$ENDIF}
end;

function TDDUCustomSocket.GetInBufferLength: Uint64;
begin
{$IFDEF NewInBuffer}
  Result := fNewInBuffer.DataAvailable;
{$ELSE}
  Result := Length(fInBuffer);
{$ENDIF}
end;

function TDDUCustomSocket.GetOutBufferEmpty: Boolean;
begin
{$IFDEF NewOutBuffer}
  Result := fNewOutBuffer.Empty;
{$ELSE}
  Result := (fOutBuffer.Count=0);
{$ENDIF}
End;

function TDDUCustomSocket.GetOutBufferLength: UInt64;
begin
{$IFDEF NewOutBuffer}
  Result := fNewOutBuffer.Available;
{$ELSE}
  Result := fOutBuffer.Count;
{$ENDIF}
end;

function TDDUCustomSocket.GetReadMode: TStringMode;
begin
{$IFDef NewInBuffer}
  Result := fNewInBuffer.StringReadMode;
{$ENDIF}
end;

Function TDDUCustomSocket.GetStream : TStream;

Begin
  Result := Nil;
End;

Function TDDUCustomSocket.GetUseProxy : Boolean;

Begin
  Result := Assigned(fProxy) And fProxy.Active;
End;

function TDDUCustomSocket.GetWriteMode: TStringMode;
begin
{$IFDef NewOutBuffer}
  Result := fNewOutBuffer.StringReadMode;
{$Else}
  Result := smAnsi;
{$ENDIF}
end;

Procedure TDDUCustomSocket.InternalConnect;

Begin
  If Active Then Exit;
//*****************************************************************************
// Mark the Protocol as active.
//*****************************************************************************
  fActive        := True;
  fDataRead      := 0;
  fDataWrote     := 0;
  fException     := False;
  fConnectFailed := False;
  fConnecting    := True;
  fConnected     := False;
  fDisconnecting := False;
  fStreamIncreaseSize := 0;
  fErrorText := '';
  fSuddenDisconnect := False;
//*****************************************************************************
// Prepare addresses
//*****************************************************************************
  fAddressDNS.Clear;
  fAddressDNS.Text := fAddress.Text;
  fAddressDNS.Assign(fAddress);
  If UseProxy Then
  Begin
    fAddressDNS.Clear;
    fAddressDNS.Text := fProxy.Text;
  End;
  fAddressLocal.Clear;
  fAddressRemote.Clear;
//*****************************************************************************
// Clear the SOCKS state.
//*****************************************************************************
  fSocksAction := saIdle;
  fSocksMode := smConnect;
//*****************************************************************************
// To preserve DNS information, we use a temporary address structure to resolve
// DNS.
//*****************************************************************************
//*****************************************************************************
// Prepare the throttle.
//*****************************************************************************
  fThrottle.Active := False;
  fThrottle.Clear;
//*****************************************************************************
// Choose the correct method to connect.
//*****************************************************************************
  Try
    fSkipReset := True;
    Open;
    fSkipReset := False;
  Except
    On E:Exception Do
    Begin
      SuddenDisconnect;
      // Really should have some way to indicate failed DNS connections.
      If (E.Message<>'') Then Raise;
    End;
  End;
end;

Procedure TDDUCustomSocket.InternalDisconnect;

Var
  F                     : Integer;

Begin
  If (Not (SocketHandle=INVALID_SOCKET)) And (SocketProtocol=spTCP) and fSuddenDisconnect Then
  Begin
    F := 0;  // Don't linger.
    SetSockOpt(SocketHandle,SOL_SOCKET,SO_LINGER,PAnsichar(@F),SizeOf(F));
  End;
  doSocketDisconnect;
End;

procedure TDDUCustomSocket.InternalFreeStream;
begin
 // needed for FTP stub it seems, see if we can't fix this later.
end;

Procedure TDDUCustomSocket.InternalWaitForConnect;

Begin
  If Active Then Exit;
//*****************************************************************************
// Mark the Protocol as active.
//*****************************************************************************
  fActive     := True;
  fException  := False;
  fConnecting := True;
  fConnected  := False;
  fStreamIncreaseSize := 0;
  fErrorText := '';
  fSuddenDisconnect := False;
//*****************************************************************************
// Prepare addresses
//*****************************************************************************
//  fAddressLocal = Address to create the listening port on.
  fAddressRemote.Clear;
  fAddressLocal.Clear;
  fAddressDNS.Clear;
  If Useproxy And Proxy.UseSocks Then
  Begin
    fAddressDNS.Text := Proxy.Text;
  End
  Else
  Begin
    fAddressDNS.Text := Address.Text;
    fAddressDNS.Assign(Address);
  End;
//*****************************************************************************
// Clear the SOCKS state.
//*****************************************************************************
  fSocksAction := saIdle;
  fSocksMode := smBind;
//*****************************************************************************
// Prepare the throttle.
//*****************************************************************************
  fThrottle.Active := False;
  fThrottle.Clear;

  Try
    fSkipReset := True;
    If Useproxy And Proxy.UseSocks Then
    Begin
      Open;
    End
    Else
    Begin
      Listen(5);
    End;
    fSkipReset := False;
  Except
    SuddenDisconnect;
    Raise;
  End;
End;

function TDDUCustomSocket.Internal_DoWrite(aWriteBuffer: Pointer; ToWrite: Cardinal): Cardinal;

Var
  Size                    : Integer;
  SockAddrIn              : TSockAddrIn;

begin
  If ToWrite=0 THen
  Begin
    Result := 0;
  End
  Else
  Begin
    Case SocketProtocol Of
      spTCP : Result := Send(SocketHandle,aWriteBuffer^,ToWrite,0);
      spUDPBroadcast,
      spUDP : Begin
                If fUDPSendAddress<>'' Then
                Begin
                  AddressRemote.Text         := fUDPSendAddress;
                  Size                       := SizeOf(SockAddrIn);
                  SockAddrIn.sin_family      := AF_INET;
                  SockAddrIn.sin_addr.S_addr := AddressRemote.IP;
                  SockAddrIn.sin_port           := htons(AddressRemote.Port);
                  Result                     := SendTo(SocketHandle,aWriteBuffer^,ToWrite,0,SockAddrIn,Size);
                End
                Else
                Begin
                  Result := ToWrite;
                End;
              End;
    Else
      Result := 0;
    End;
  End;
end;

function TDDUCustomSocket.Internal_DoWrite_ToWrite(TotalAvailable: UInt64): UInt64;
begin
  If (Throttle.BlockSize.Write<>0) And (Throttle.SpeedLimit.Write<>0) Then
  Begin
    Result := Throttle.BlockSize.Write;
    If (Result>Max_MTU) And (Max_MTU<>0) Then
    Begin
      Result := MAX_MTU;
    End;
  End
  Else
  Begin
    If (Max_MTU=0) Then // We can dynamically allocate any buffer size we need.
    Begin
      Result := _MAX_MTU;
    End
    Else
    Begin
      Result := Max_MTU;
    End;
  End;

  If (Result>TotalAvailable) Then
  Begin
    Result := TotalAvailable;
  End;
end;

procedure TDDUCustomSocket.Internal_StreamDone({$IFDEF NewOutBuffer}SignalID : Integer; Name : String;{$ELSE}OutBufferString : String;{$ENDIF} S : Pointer);
begin
{$IFDEF NewOutBuffer}
  If (SignalID=signalSendBLOCKMarker) Then
  Begin
    DoBlockSendDone(TStream(S),Name);
  End Else If (SignalID=signalSTREAMMarker) Or (SignalID=signalPRIVATEMEMORYSTREAMMarker) Then
  Begin
    DoSendStreamDone(TStream(S),SignalID=signalPRIVATEMEMORYSTREAMMarker);
  End;
{$ELSE}
  If (StartsWith(OutBufferString,constBLOCKMarker)) Then
  Begin
    DoBlockSendDone(TStream(S),TextAfter(OutBufferString,constBLOCKMarker));
  End Else If (OutBufferString=constSTREAMMarker) Or (OutBufferString=constPRIVATEMEMORYSTREAMMarker) Then
  Begin
    DoSendStreamDone(TStream(S),OutBufferString=constPRIVATEMEMORYSTREAMMarker);
  End;
{$ENDIF}
End;

procedure TDDUCustomSocket.Internal_StreamProgress({$IFDEF NewOutBuffer}SignalID : Integer; SignalName : String;{$ELSE}OutBufferString : String;{$ENDIF} S: Pointer);
begin
{$IfDef NewOutBuffer}
  If (SignalID=signalSendBLOCKMarker) Then
  Begin
    DoBlockSendProgress(TStream(S),SignalName);
  End Else If (SignalID=signalSTREAMMarker) Or (SignalID=signalPRIVATEMEMORYSTREAMMarker) Then
  Begin
    DoProgressStream(TStream(S).Position,TStream(S).Size);
  End;
{$ELSE}
  If (StartsWith(OutBufferString,constBLOCKMarker)) Then
  Begin
    DoBlockSendProgress(TStream(S),TextAfter(OutBufferString,constBLOCKMarker));
  End Else If (OutBufferString=constSTREAMMarker) Or (OutBufferString=constPRIVATEMEMORYSTREAMMarker) Then
  Begin
    DoProgressStream(TStream(S).Position,TStream(S).Size);
  End;
{$ENDIF}
end;

procedure TDDUCustomSocket.Listen(QueueSize: Integer);

Var
  SockAddrIn            : TSockAddrIn;

Begin
  If Not (SocketHandle=INVALID_SOCKET) Then
  Begin
    Raise ESocketError.Create(sCannotListenOnOpen);
  End;

  fSocket := CreateSocket;
  fIsServer := True;
  AddressRemote.Clear;
  PrepareSocketOptions;
  Try
    PrepareAddress(SockAddrIn);
    If (SocketProtocol=spUDPBroadCast) Then
    Begin
      SockAddrIn.sin_addr.S_addr := u_LONG(INADDR_ANY);
    End;
    CheckSocketResult(bind(SocketHandle, SockAddrIn, SizeOf(SockAddrIn)), 'bind');
// Load the local address, so we know what we are listening on.

    LoadAddressLocal;
    If (SocketProtocol=spUDPBroadCast) Then
    Begin
      AddressRemote.IP := u_Long(INADDR_BROADCAST);
      AddressRemote.Port := AddressLocal.port;
    End;
    PrepareAsync(True);
    If (QueueSize>SOMAXCONN) Then
    Begin
      QueueSize := SOMAXCONN;
    End;

    DoListen;
    If (SocketProtocol=spTCP) Then
    Begin
      CheckSocketResult(WinAPI.Winsock.listen(SocketHandle, QueueSize), 'listen');
      fConnecting := True;
      fConnected := False;
    End
    Else
    Begin
      fConnecting := False;
      fConnected := True;
      DoSocketConnect;
    End;
  Except
    SuddenDisconnect;
    Raise;
  End;
End;

Procedure TDDUCustomSocket.LoadAddressLocal;

Var
  Size                  : Integer;
  SockAddrIn            : TSockAddrIn;
  ansiHost              : AnsiString;

Begin
  Size := SizeOf(SockAddrIn);
  FillChar(SockAddrIn,Size,#0);
  If (getsockname(SocketHandle, SockAddrIn, Size)=0) Then
  Begin
    AddressLocal.IP := SockAddrIn.sin_addr.S_addr;
    AddressLocal.Port := ntohs(SockAddrIn.sin_port);
  End
  Else
  Begin
    AddressLocal.Clear;
  End;

  If AddressLocal.IP=u_Long(INADDR_ANY) Then
  Begin
    SetLength(ansiHost,255);
    FillChar(ansiHost[Low(ansiHost)],Length(ansihost),0);

    GetHostName(PAnsiChar(ansiHost),Length(ansiHost));
    ansiHost := PAnsiChar(ansiHost);
    AddressLocal.IP := LookupName(String(ansiHost)).S_addr;
  End;
End;

Procedure TDDUCustomSocket.LoadAddressRemote;

Var
  Size                  : Integer;
  SockAddrIn            : TSockAddrIn;

Begin
  Size := SizeOf(SockAddrIn);
  FillChar(SockAddrIn,Size,#0);
  If (getpeername(SocketHandle, SockAddrIn, Size)=0) Then
  Begin
    AddressRemote.IP := SockAddrIn.sin_addr.S_addr;
    AddressRemote.Port := ntohs(SockAddrIn.sin_port);
  End
  Else
  Begin
    AddressRemote.Clear;
  End;
End;

Function TDDUCustomSocket.LookupName(const Name: string): TInAddr;

Var
  HostEnt               : PDDUHostEnt;
  ansiName              : AnsiString;

Begin
  ansiName := Name.Trim;
  HostEnt := PDDUHostEnt(gethostbyname(PAnsiChar(ansiName)));
  If HostEnt<>nil Then
  Begin
    Result := HostEnt^.h_addr^^;
  End
  Else
  Begin
    Result.s_Addr := u_Long(INADDR_ANY);
  End;
End;

Function TDDUCustomSocket.LookupPort(Const port : Integer) : String;

Var
  ServEnt               : PServEnt;

Begin
  Case SocketProtocol Of
    spTCP : ServEnt := getservbyport(Port, 'tcp');
    spUDPBroadcast,
    spUDP : ServEnt := getservbyport(Port, 'udp');
  Else
    ServEnt := Nil;
  End;
  If Assigned(ServEnt) Then
  Begin
    Result := String(ServEnt.s_name);
  End
  Else
  Begin
    Result := '';
  End;
End;

function TDDUCustomSocket.LookupService(const Service: string): Integer;

Var
  ServEnt               : PServEnt;
  ansiService           : AnsiString;
  ansiTCP               : AnsiString;
  ansiUDP               : AnsiString;

Begin
  ansiService := Service;
  ansiTCP     := 'tcp';
  ansiUDP     := 'tcp';

  Case SocketProtocol Of
    spTCP : ServEnt := getservbyname(PAnsiChar(ansiService), PAnsiChar(ansiTCP));
    spUDPBroadcast,
    spUDP : ServEnt := getservbyname(PAnsiChar(ansiService), PAnsiChar(ansiUDP));
  Else
    ServEnt := Nil;
  End;
  If Assigned(ServEnt) Then
  Begin
    Result := ntohs(ServEnt.s_port);
  End
  Else
  Begin
    Result := 0;
  End;
End;

Procedure TDDUCustomSocket.Notification(AComponent: TComponent; Operation: TOperation);

Begin
  Inherited Notification(AComponent,Operation);
  If (Operation=opRemove) Then
  Begin
    If (AComponent=fDNS) Then
    Begin
      fDNS := Nil;
    End Else If (AComponent=fProxy) Then
    Begin
      fProxy := Nil;
    End Else If (aComponent=fRelatedSocket) Then
    Begin
      fRelatedSocket := Nil;
    End Else If (aComponent=fRelatedComponent) Then
    Begin
      fRelatedComponent := Nil;
    End Else If (AComponent=fRedirectSocket) Then
    Begin
      fRedirectSocket := Nil
    End Else If (AComponent=fRedirectParent) Then
    Begin
      fSocket := INVALID_SOCKET;
      fRedirectParent := Nil;
      DoSocketDisconnect;
//      Raise Exception.Create('Source Socket has been destroyed before Redirection Socket.');
    End
  End;
End;

Procedure TDDUCustomSocket.PreConnect;

Begin
End;

Procedure TDDUCustomSocket.PreDisconnect;

Begin
End;

procedure TDDUCustomSocket.PreWaitForConnect;

Begin
End;

function TDDUCustomSocket.PrepareAddress(Var SockAddrIn : TSockAddrIn) : Boolean;

Var
  ansiHost                : AnsiString;
  NoneOk                  : Boolean;

Begin
  Result := True; // Address was resolved OK.
  NoneOk := False;

  SockAddrIn.sin_family := AF_INET;
  If IsServer Then
  Begin
    If (Not BindToAddress) Then
    Begin
      SockAddrIn.sin_addr.S_addr := u_Long(INADDR_ANY);
    End
    Else
    Begin
{ TODO : 127.0.0.1 would probably do if address is blank. }
      If (fAddressDNS.Address='') Then
      Begin
        SetLength(ansiHost,255);

        If (GetHostName(PAnsiChar(ansiHost),255)=0) Then
        Begin
          ansiHost := PAnsiChar(ansiHost);
          SockAddrIn.sin_addr := LookupName(String(ansiHost));
        End
        Else
        Begin
          SockAddrIn.sin_addr.S_addr := Address.IP;
        End;
      End
      Else
      Begin
        SockAddrIn.sin_Addr.s_Addr := fAddressDNS.IP;
      End;
    End;
    fAddressDNS.IP := SockAddrIn.sin_addr.S_addr;
  End
  Else
  Begin
    If (fAddressDNS.Address='') Then
    Begin
      If (fAddressDNS.Host='') Then
      Begin
        If (SocketProtocol in [spUDP,spUDPBroadcast]) Then
        Begin
          NoneOk := True;
          SockAddrIn.sin_addr.s_addr := u_Long(INADDR_NONE);
          fAddressDNS.IP :=  SockAddrIn.sin_addr.S_addr;
        End
        Else
        Begin
          Raise ESocketError.Create(sNoAddress);
        End;
      End
      Else
      Begin
        If Assigned(fDNS) Then
        Begin
          // We can resolve the name without blocking
          Result := False;
          fDNS.OnFoundAddress2 := DNSDone;
          fDNS.OnCancel2       := DNSCancel;
          fDNS.Host            := fAddressDNS.Host;
        End
        Else
        Begin
          // We must resolve the name in a blocking method.
          SockAddrIn.sin_addr := LookupName(fAddressDNS.Host);
          fAddressDNS.IP :=  SockAddrIn.sin_addr.S_addr;
          // Sometimes its a bad name....
          If (SockAddrIn.sin_addr.S_addr=u_Long(INADDR_NONE)) Or
             (SockAddrIn.sin_addr.S_addr=u_Long(INADDR_ANY)) Then
          Begin
            Raise Exception.Create('');
          End;
        End;
      End;
    End
    Else
    Begin
      SockAddrIn.sin_Addr.s_Addr := fAddressDNS.IP;
    End;

    If Result And
       ( ((SockAddrIn.sin_addr.S_addr=u_Long(INADDR_NONE)) And (Not NoneOk)) Or
         (SockAddrIn.sin_addr.S_addr=u_Long(INADDR_ANY))) Then
    Begin
      Raise Exception.Create('');
    End;
  End;
  If Result Then
  Begin
    PreparePort(SockAddrIn);
  End;
End;

procedure TDDUCustomSocket.PrepareAsync(AsyncOn : Boolean);

Begin
  If (SocketHandle=INVALID_SOCKET) Then
  Begin
    Raise ESocketError.Create(sNoSocket);
  End;
  
  If AsyncOn Then
  Begin
    WSAAsyncSelect(SocketHandle,Handle,CM_SOCKETMESSAGE, FD_READ or FD_WRITE or FD_ACCEPT or FD_CONNECT or FD_CLOSE);
  end
  Else
  Begin
    WSAAsyncSelect(SocketHandle,Handle,CM_SOCKETMESSAGE, 0);
  End;
End;

Procedure TDDUCustomSocket.PreparePort(Var SockAddrIn : TSockAddrIn);

Begin
  SockAddrIn.sin_family := AF_INET;        
  If (fAddressDNS.Service='') Then
  Begin
    SockAddrIn.sin_port := htons(fAddressDNS.Port);
  End
  Else
  Begin
    SockAddrIn.sin_port := htons(LookupService(fAddressDNS.Service));
  End;
  fAddressDNS.Service := '';
  fAddressDNS.Port    := ntohs(SockAddrIn.sin_port);
End;

Procedure TDDUCustomSocket.PrepareSocketOptions;

Var
  T                     : Integer;
  F                     : Integer;
  V                     : Integer;
  VSize                 : Integer;
  Linger                : TLinger;

Begin
  T := 1;
  F := 0;
//*****************************************************************************
// Common(TCP&UDP) protocol options
//*****************************************************************************
  VSize := SizeOf(V);
  CheckSocketResult(GetSockOpt(SocketHandle,SOL_SOCKET,SO_DEBUG,PAnsiChar(@V),VSize),'getsockopt(SO_DEBUG)');
  If Boolean(V)<>(soDebug in SocketOptions) Then
  Begin
    CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_DEBUG,PAnsiChar(@T),SizeOf(T)),'setsockopt(SO_DEBUG T)');
  End
  Else
  Begin
    CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_DEBUG,PAnsiChar(@F),SizeOf(F)),'setsockopt(SO_DEBUG F)');
  End;
  VSize := SizeOf(V);
  CheckSocketResult(GetSockOpt(SocketHandle,SOL_SOCKET,SO_DONTROUTE,PAnsiChar(@V),VSize),'getsockopt(SO_DONTROUTE)');
  If Boolean(V)<>(soDontRoute in SocketOptions) Then
  Begin
    CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_DONTROUTE,PAnsiChar(@T),SizeOf(T)),'setsockopt(SO_DONTROUTE T)');
  End
  Else
  Begin
    CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_DONTROUTE,PAnsiChar(@F),SizeOf(F)),'setsockopt(SO_DONTROUTE F)');
  End;
  VSize := SizeOf(V);
  CheckSocketResult(GetSockOpt(SocketHandle,SOL_SOCKET,SO_REUSEADDR,PAnsiChar(@V),VSize),'getsockopt(SO_REUSEADDR)');
  If Boolean(V)<>(soReuseAddr in SocketOptions) Then
  Begin
    CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_REUSEADDR,PAnsiChar(@T),SizeOf(T)),'setsockopt(SO_REUSEADDR T)');
  End
  Else
  Begin
    CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_REUSEADDR,PAnsiChar(@F),SizeOf(F)),'setsockopt(SO_REUSEADDR F)');
  End;
//*****************************************************************************
// TCP protocol options only
//*****************************************************************************
  If (Socketprotocol=spTCP) Then
  Begin
    VSize := SizeOf(V);
    CheckSocketResult(GetSockOpt(SocketHandle,SOL_SOCKET,SO_KEEPALIVE,PAnsiChar(@V),VSize),'getsockopt(SO_KEEPALIVE)');
    If Boolean(V)<>(soKeepAlive in SocketOptions) Then
    Begin
      CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_KEEPALIVE,PAnsiChar(@T),SizeOf(T)),'setsockopt(SO_KEEPALIVE T)');
    End
    Else
    Begin
      CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_KEEPALIVE,PAnsiChar(@F),SizeOf(F)),'setsockopt(SO_KEEPALIVE F)');
    End;
    VSize := SizeOf(Linger);
    CheckSocketResult(GetSockOpt(SocketHandle,SOL_SOCKET,SO_LINGER,PAnsiChar(@Linger),VSize),'getsockopt(SO_LINGER)');
    If Boolean(Linger.l_onoff)<>(soLinger in SocketOptions) Then
    Begin
      Linger.l_onoff := 1;
      Linger.l_linger := LingerTime;
      CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_LINGER,PAnsiChar(@Linger),SizeOf(Linger)),'setsockopt(SO_LINGER T'+IntToStr(LingerTime)+' )');
    End
    Else
    Begin
      Linger.l_onoff := 0;
      Linger.l_linger := LingerTime;
      CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_LINGER,PAnsiChar(@Linger),SizeOf(Linger)),'setsockopt(SO_LINGER F)');
    End;
    VSize := SizeOf(V);
    CheckSocketResult(GetSockOpt(SocketHandle,IPPROTO_TCP,TCP_NODELAY,PAnsiChar(@V),VSize),'getsockopt(TCP_NODELAY)');
    If Boolean(V)<>(soTCPNoDelay in SocketOptions) Then
    Begin
      CheckSocketResult(SetSockOpt(SocketHandle,IPPROTO_TCP,TCP_NODELAY,PAnsiChar(@T),SizeOf(T)),'setsockopt(TCP_NODELAY T)');
    End
    Else
    Begin
      CheckSocketResult(SetSockOpt(SocketHandle,IPPROTO_TCP,TCP_NODELAY,PAnsiChar(@F),SizeOf(F)),'setsockopt(TCP_NODELAY F)');
    End;
  End;
//*****************************************************************************
// UDP protocol options only
//*****************************************************************************
  If Not (Socketprotocol=spTCP) Then
  Begin
     VSize := SizeOf(V);
    CheckSocketResult(GetSockOpt(SocketHandle,SOL_SOCKET,SO_BROADCAST,PAnsiChar(@V),VSize),'getsockopt(SO_BROADCAST)');
    If Boolean(V)<>(soBroadcast in SocketOptions) Then
    Begin
      CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_BROADCAST,PAnsiChar(@T),SizeOf(T)),'setsockopt(SO_BROADCAST T)');
    End
    Else
    Begin
      CheckSocketResult(SetSockOpt(SocketHandle,SOL_SOCKET,SO_BROADCAST,PAnsiChar(@F),SizeOf(F)),'setsockopt(SO_BROADCAST F)');
    End;
  End;
End;

procedure TDDUCustomSocket.Open;

Var
  SockAddrIn            : TSockAddrIn;

Begin
  fSocket := CreateSocket;
  fIsServer := False;
  PrepareAsync(True);
  PrepareSocketOptions;

  Try
    DoLookup;
    If PrepareAddress(SockAddrIn) Then
    Begin
      OpenFinish(SockAddrIn);
    End;
  Except
    SuddenDisconnect;
    Raise;
  End;
End;

procedure TDDUCustomSocket.OpenFinish(Var SockAddrIn : TSockAddrIn);

Begin
  If (SocketHandle=INVALID_SOCKET) Then
  Begin
    Raise ESocketError.Create(sNoSocket);
  End;
  Try
    DoConnecting;
    If (SocketProtocol=spTCP) Then
    Begin
      CheckSocketResult(WinAPI.WinSock.connect(SocketHandle, SockAddrIn, SizeOf(SockAddrIn)), 'connect');
    End
    Else
    Begin
      fAddressRemote.Clear;
      fAddressRemote.Text := fAddressDNS.Text; // Resolved info is best.
      fAddressRemote.Assign(fAddressDNS);

      FillChar(SockAddrIN,SizeOf(SockAddrIn),#0);
      SockAddrIn.sin_family := AF_INET;
      SockAddrIn.sin_addr.S_addr := u_LONG(INADDR_ANY);

//      If (SocketProtocol=spUDPBroadcast) Then
//      Begin
//        SockAddrIn.sin_port := htons(fAddressDNS.Port);
//        fAddressRemote.Port := fAddressDNS.Port;
//      End;
      
      CheckSocketResult(bind(SocketHandle, SockAddrIn, SizeOf(SockAddrIn)), 'bind');
      LoadAddressLocal;

      If (SocketProtocol=spUDPBroadcast) Then
      Begin
        fAddressRemote.IP := u_Long(INADDR_BROADCAST);
        fAddressRemote.Port := fAddressDNS.Port;
      End;
      DoSocketConnect;
    End;
  Except
    fIsServer := False;
    SuddenDisconnect;
    Raise;
  End;
End;

procedure TDDUCustomSocket.OpenWithSocket(Async : Boolean=False); 

Begin
  If (SocketHandle=INVALID_SOCKET) Then
  Begin

  End;
  fActive     := True;
  fConnecting := True;
  fConnected  := False;
  fIsServer := False;
  fStreamIncreaseSize := 0;
  fErrorText := '';
  fSuddenDisconnect := False;

  LoadAddressLocal;
  LoadAddressRemote;
  fSocksAction := saIdle;
  fSocksMode := smConnect;
  fThrottle.Active := False;
  fThrottle.Clear;

  PrepareAsync(Async);
  PrepareSocketOptions;

  DoSocketConnect;
End;

function TDDUCustomSocket.PeekBuffer(var Buf; Count : Cardinal): Integer;

Begin
  Result := 0;
  If Not Connected Then
  Begin
    Exit;
  End;

{$IFDEF NewInBuffer}
  Result := fNewInBuffer.PeekData(@Buf,Count);
{$ELSE}
  Result := Count;
  If (Result>Length(fInBuffer)) Then
  Begin
    Result := Length(fInBuffer);
  End;
  Move(Pointer(fInBuffer)^,Buf,Result);
{$ENDIF}
End;

function TDDUCustomSocket.PeekBytes: TBytes;
begin
{$IFDEF NewInBuffer}
  Result := PeekBytes(fNewInBuffer.Available);
{$ELSE}
  Result := PeekBytes(Length(fInBuffer));
{$ENDIF}
end;

function TDDUCustomSocket.PeekBytes(Count: Cardinal): TBytes;
begin
{$IFDEF NewInBuffer}
  Count := Min(Count,fNewInBuffer.Available);
  Result := fNewInBuffer.PeekBytes(Count);
{$ELSE}
  Count := Min(Count,Length(fInBuffer));
  SetLength(Result,Count);
  Move(fInBuffer[Low(fInBuffer)],Result[Low(result)],Count);
{$ENDIF}
end;

Procedure TDDUCustomSocket.PushOutput;

Begin
  NewDoWrite;
End;

function TDDUCustomSocket.ReadBuffer(var Buf; Count : Cardinal): Cardinal;

Begin
  Result := 0;
  If Not Connected Then
  Begin
    Exit;
  End;

{$IFDEF NewInBuffer}
  Result := fNewInBuffer.ReadData(@Buf,Count);
{$ELSE}
  Result := Count;
  If (Result>InBufferLength) Then
  Begin
    Result := InBufferLength;
  End;
  Move(Pointer(fInBuffer)^,Buf,Result);
  Delete(fInBuffer,1,Result);
{$ENDIF}

End;

function TDDUCustomSocket.ReadBytes(Count: Integer): TBytes;
begin
{$IFDEF NewInBuffer}
  Count := Min(Count,fNewInBuffer.Available);
  Result := fNewInBuffer.ReadBytes(Count);
{$ELSE}
  Count := Min(Count,Length(fInBuffer));
  SetLength(Result,Count);
  Move(fInBuffer[Low(fInBuffer)],Result[Low(result)],Count);
  fInBuffer := '';
{$ENDIF}
end;

function TDDUCustomSocket.ReadBytes: TBytes;
begin
{$IFDEF NewInBuffer}
  Result := ReadBytes(fNewInBuffer.Available);
{$ELSE}
  Result := ReadBytes(Length(fInBuffer));
{$ENDIF}
end;

function TDDUCustomSocket.ReadLength : Cardinal;

Begin
  Result := 0;
  If (CanReadWrite) Then
  Begin
{$IFDEF NewInBuffer}
    Result := fNewInBuffer.Available;
{$ELSE}
    Result := Cardinal(Length(fInBuffer));
{$ENDIF}
  End;
End;

function TDDUCustomSocket.ReadRawText : string;

Begin
{$IFDEF NewInBuffer}
  Result := fNewInBuffer.ReadString(fNewInBuffer.Available);
{$ELSE}
  Result := fInBuffer;
  fInBuffer := '';
{$ENDIF}
End;

function TDDUCustomSocket.ReadRawTextMax(Max : Cardinal) : String;

Begin
{$IFDEF NewInBuffer}
  Result := fNewInBuffer.ReadString(Max);
{$ELSE}
  Result := Copy(fInBuffer,1,Max);
  Delete(fInBuffer,1,Max);
{$ENDIF}
End;

Procedure TDDUCustomSocket.SetDeferReading(Const NewValue : Boolean);

Begin
  If Not(DeferReading=NewValue) Then
  Begin
    fDeferReading := NewValue;
//*****************************************************************************
// Data is read into fInBuffer even when DeferReading is true, it is just not
// dispatched.  If DeferReading is cleared, we want to dispatch anything that
// has built up in the buffer now.  We do not need to use DoSocketRead, as
// the data has already gone through the throttling routines, and we do not
// want to send it through again.
//*****************************************************************************
    If (Not DeferReading) Then
    Begin
      PostMessage(Handle,CM_DispatchIncomingData,0,0);
    End;
  End;
End;

Procedure TDDUCustomSocket.SetDeferWriting(Const NewValue : Boolean);

Begin
  If Not(DeferWriting=NewValue) Then
  Begin
    fDeferWriting := NewValue;
//*****************************************************************************
// Data is built up into fOutBuffer even when DeferWriting is true, it is
// just not sent.  If DeferWriting is cleared, we want to send anything in the
// buffer.  Using DoSocketWrite causes data to be sent through the throttling
// routines, because it has not had an oppourtinity thus far.
//*****************************************************************************
    If (Not DeferWriting) Then
    Begin
      DoSocketWrite;
    End;
  End;
End;

Procedure TDDUCustomSocket.SetDataMode(Const NewValue : TDataMode);

Begin
  If NewValue=dmBlock Then Raise Exception.Create('dmBlock can not be set explicitly.');
  If (NewValue<>DataMode) Then
  Begin
    BlockReceiveAbort;
    DoFreeReceiveStream;
    fDataMode := NewValue;
    Case DataMode Of
      dmRawStream,
      dmStream : Begin
                   DoGetReceiveStream;
                   fStreamIncreaseSize := 0;
                   DoSeekStream;
                 End;
    End;
  End;
End;

Procedure TDDUCustomSocket.SetDNS(Const NewValue : TDDUCustomDNS);

Begin
  If Assigned(NewValue) And Assigned(NewValue.LinkedTo) Then
  Begin
//*****************************************************************************
// When copying a component, it will first be in the csLoading state.
// if we raise an exception, the addresses will not be correctly looked
// up, and confuse the hell out of the IDE, so we silently discard the
// assignment instead, otherwise, raise an exception to warn the
// programmer.
//*****************************************************************************
    If (csLoading In ComponentState) Then
    Begin
      Exit;
    End
    Else
    Begin
      If NewValue.LinkedTo<>Self Then
      Begin
        Raise Exception.CreateFmt(sDnsLinked,[NewValue.Name,NewValue.LinkedTo.Name]);
      End;
    End;
  End;
//*****************************************************************************
// Release our current link, if any.
//*****************************************************************************
  If Assigned(fDNS) Then
  Begin
    fDNS.LinkedTo := Nil;
  End;
  fDNS := NewValue;
  If Assigned(fDNS) Then
  Begin
    fDNS.LinkedTo := Self;
    fDNS.FreeNotification(Self);
  End;
End;

{$IFDEF NewInBuffer}
procedure TDDUCustomSocket.SetInBuffer(const Value: String);
begin
  fNewInBuffer.Flush;
  fNewInBuffer.WriteString(Value);
end;
{$ENDIF}

procedure TDDUCustomSocket.SetInBufferBytes(const Value: TBytes);
begin
{$IFDEF NewInBuffer}
  fNewInBuffer.Flush;
  fNewInBuffer.WriteBytes(Value);
{$ELSE}
  fInBuffer := sBytes(Value);
{$ENDIF}
end;


procedure TDDUCustomSocket.SetMax_MTU(const Value: Cardinal);
begin
  If (fMax_MTU<>Value) Then
  Begin
    If Assigned(fWriteBuffer) Then
    Begin
      FreeMem(fWriteBuffer,fMax_MTU);
      fWriteBuffer := Nil;
    End;
    fMax_MTU := Value;
    If (fMax_MTU>0) Then
    Begin
      GetMem(fWriteBuffer,fMax_MTU);
    End;
  End;
end;

Procedure TDDUCustomSocket.SetProxy(Const NewValue : TDDUCustomProxy);

Begin
  fProxy := NewValue;
  If Assigned(fProxy) Then
  Begin
    fProxy.FreeNotification(Self);
  End;
End;

procedure TDDUCustomSocket.SetReadMode(const Value: TStringMode);
begin
{$IFDef NewInBuffer}
  fNewInBuffer.StringReadMode  := Value;
  fNewInBuffer.StringWriteMode := Value;
{$ENDIF}
end;

Procedure TDDUCustomSocket.SetRelatedComponent(Const NewValue : TComponent);

Begin
  fRelatedComponent := NewValue;
  If Assigned(fRelatedComponent) Then
  Begin
    fRelatedComponent.FreeNotification(Self);
  End;
End;

Procedure TDDUCustomSocket.SetRelatedSocket(Const NewValue : TDDUCustomSocket);

Begin
  fRelatedSocket := NewValue;
  If Assigned(fRelatedSocket) Then
  Begin
    fRelatedSocket.FreeNotification(Self);
  End;
End;

Procedure TDDUCustomSocket.SetSocketOptions(Const NewValue : TSocketOptions);

Begin
  fSocketOptions := NewValue;
  SyncSocketOptionsToProtocol;

  If Not (SocketHandle=INVALID_SOCKET) Then
  Begin
    PrepareSocketOptions;
  End;
End;

Procedure TDDUCustomSocket.SetSocketProtocol(Const NewValue : TSocketProtocol);

Begin
  fSocketProtocol := NewValue;
  SyncSocketOptionsToProtocol;
End;

Procedure TDDUCustomSocket.SetStream(S : TStream);

Begin
//*****************************************************************************
// Used to allow higher level objects to free their streams via the normal
// stream freeing mechanism, not to be used indiscrimanently.
//*****************************************************************************
  DoFreeReceiveStream;
  fReceiveStream := S;
End;

procedure TDDUCustomSocket.SetWriteMode(const Value: TStringMode);
begin
{$IFDef NewOutBuffer}
  fNewOutBuffer.StringReadMode  := Value;
  fNewOutBuffer.StringWriteMode := Value;
{$ENDIF}
end;

function TDDUCustomSocket.Stored_BlockAutoStartPrefix: Boolean;
begin
  Result := (BlockAutoStartPrefix<>DEFAULT_BlockAutoStartPrefix);
end;

function TDDUCustomSocket.Stored_Note: Boolean;
begin
  Result := (fNote<>'');
end;

function TDDUCustomSocket.Stored_SocketOptions: Boolean;
begin
  Result := (SocketOptions<>[]);
end;

function TDDUCustomSocket.Stored_TextMode: Boolean;
begin
  Result := (TextMode<>[]);
end;

Procedure TDDUCustomSocket.SuddenDisconnect;

Begin
  If Active Then
  Begin
    fSuddenDisconnect := True;
    Disconnect;
  End;
End;

Procedure TDDUCustomSocket.SyncSocketOptionsToProtocol;

Begin
  If (SocketProtocol=spUDPBroadcast) Then
  Begin
    Include(fSocketOptions,soBroadcast);
  End
  ELse
  Begin
    Exclude(fSocketOptions,soBroadcast);
  End;
End;

Procedure TDDUCustomSocket.UseThrottle(Throttle : TDDUThrottle);

Begin
  If Assigned(fThrottle) Then
  Begin
    If (SocketHandle<>INVALID_SOCKET) Then
    Begin
      fThrottle.RemoveSocket(SocketHandle)
    End;
    If fThrottleOwner Then
    Begin
      FreeAndNil(fThrottle);
    End;
    fThrottle := Nil;
  End;
  fThrottleOwner := False;
  fThrottle      := Throttle;
  If Not Assigned(fThrottle) Then
  Begin
    fThrottleOwner               := True;
    fThrottle                    := TDDUThrottle.Create;
    fThrottle.OnThrottle         := DoThrottle;
    fThrottle.OnThrottleReadOff  := DoThrottleReadOff;
    fThrottle.OnThrottleReadOn   := DoThrottleReadOn;
    fThrottle.OnThrottleWriteOff := DoThrottleWriteOff;
    fThrottle.OnThrottleWriteOn  := DoThrottleWriteOn;
    fThrottle.OnTimeout          := DoThrottleTimeout;
  End;
End;

Procedure TDDUCustomSocket.WaitForConnect;

Begin
  If (SocketMode in [smAuto,smAutoReset]) and Active Then
  Begin
    If Not (SocketHandle=INVALID_SOCKET) Then
    Begin
      PrepareAsync(False);
      CloseSocket(SocketHandle);
    End;
    fSocket := INVALID_SOCKET;
    fActive := False;
  End;
  If (SocketMode In [smClient]) Then
  Begin
    Raise ESocketError.Create(sClientCannotListen);
  End;
  If (SocketProtocol in [spUDP,spUDPBroadcast]) And UseProxy Then
  Begin
    Raise ESocketError.Create(sNoUDPProxy);
  End;
  If Active Then Exit;
  PreWaitForConnect;
  InternalWaitForConnect;
End;

procedure TDDUCustomSocket.WndProc(Var Msg : TMessage);

Begin
  Try
    Dispatch(Msg);
  Except
    On E:Exception Do
    Begin
      If Assigned(fOnException) Then
      Begin
        fOnException(Self,E);
      End;
    End;
//    Application.HandleException(Self);
  End;
End;

Procedure TDDUCustomSocket.WriteBuffer(var Buf; Count: Integer);

{$IFNDEF NewOutBuffer}
Var
  Work                  : String;
{$EndIf}

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;

  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;

  If (Count<>0) Then
  Begin
    WriteRemoteAddress;
{$IFDEF NewOutBuffer}
    fNewOutBuffer.WriteData(@Buf,Count);
{$ELSE}
    If (OutBufferEmpty) Or Assigned(fOutBuffer.Objects[fOutBuffer.Count-1]) Then
    Begin
      fOutBuffer.Add('');
    End;
    SetLength(Work,Count);
    Move(Buf,Work[1],Count);
    fOutBuffer[fOutBuffer.Count-1] := fOutBuffer[fOutBuffer.Count-1]+Work;
{$ENDIF}
  End;
  DoWriteRequest;
End;

procedure TDDUCustomSocket.WriteBytes(Bytes: TBytes);
begin
{$IFDEF NewOutBuffer}
  WriteRemoteAddress;
  fNewOutBuffer.WriteBytes(Bytes);
  DoWriteRequest;
{$ELSE}
  WriteBuffer(Bytes[Low(Bytes)],Length(Bytes));
{$ENDIF}
end;

Procedure TDDUCustomSocket.WriteCallback(Const Text : String); 

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
{$IFDEF NewOutBuffer}
  fNewOutBuffer.WriteSignal(signalCALLBACKMarker,Text,'',0,Nil,Nil);
{$ELSE}
  fOutBuffer.AddObject('CALLBACK '+Text,TObject(1));
{$ENDIF}
  DoWriteRequest;
End;

Procedure TDDUCustomSocket.WriteDisconnect;

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
{$IFDEF NewOutBuffer}
  fNewOutBuffer.WriteSignal(signalDisconnectMarker);
{$ELSE}
  fOutBuffer.AddObject(constDISCONNECTMarker,TObject(1));
{$ENDIF}

  DoWriteRequest;
End;

Procedure TDDUCustomSocket.WriteSignal(Signal : Cardinal);

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
{$IFDEF NewOutBuffer}
  fNewOutBuffer.WriteSignal(signalSIGNALMarker,'','',Signal);
{$ELSE}
  fOutBuffer.AddObject(constSIGNALMarker,TObject(Signal));
{$ENDIF}
  DoWriteRequest;
End;

Procedure TDDUCustomSocket.WriteFormat(const Format: string; const Args: array of const);

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
  WriteText(System.SysUtils.Format(Format,Args));
End;

Procedure TDDUCustomSocket.WriteOpenArray(Const Args : Array Of Const);

Var
  Loop                  : Integer;
  M                     : TMemoryStream;

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  M := TMemoryStream.Create;
  Try
    For Loop := Low(Args) To High(Args) Do
    Begin
      With Args[Loop] do
      Begin
        Case VType of
          vtInteger    : M.WriteBuffer(VInteger,SizeOf(VInteger));
          vtBoolean    : M.WriteBuffer(VBoolean,SizeOf(VBoolean));
          vtChar       : M.WriteBuffer(VChar,SizeOf(VChar));
          vtExtended   : M.WriteBuffer(VExtended^,SizeOf(VExtended^));
          vtString     : M.WriteBuffer(VString^[1],Length(VString^));
//          vtPointer    :
          vtPChar      : M.WriteBuffer(VPChar[1],StrLen(VPChar));
//          vtObject     :
//          vtClass      :
          vtWideChar   : M.WriteBuffer(VWideChar,SizeOf(VWideChar));
//          vtPWideChar  :
          vtAnsiString : M.WriteBuffer(String(VAnsiString)[1],Length(String(VAnsiString)));
          vtCurrency   : M.WriteBuffer(VCurrency^,SizeOf(VCurrency^));
//          vtVariant    :
{$IFDEF UNICODE}
//  Ya, finish this.
{$ENDIF}
        end;
      End;
    End;
    WriteBuffer(M.Memory^,M.Size);
  Finally
    FreeAndNil(M);
  End;
end;

procedure TDDUCustomSocket.WriteRawText(const Text : string);

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
{$IFDEF NewOutBuffer}
  WriteRemoteAddress;
  fNewOutBuffer.WriteString(Text);
  DoWriteRequest
{$ELSE}
  WriteBuffer(Pointer(Text)^,Length(Text));
{$ENDIF}

End;

Procedure TDDUCustomSocket.WriteSocket(Socket : TDDUCustomSocket);

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
{$IFDEF NewInBuffer}
  WriteRemoteAddress;
  fNewOutBuffer.StealNodes(Socket.fNewInBuffer);
{$ELSE}
  WriteBuffer(Socket.fInBuffer[1],Length(Socket.fInBuffer));
  Socket.fInBuffer := '';
{$ENDIF}
End;

Procedure TDDUCustomSocket.WriteStream(Stream : TStream);

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  If Assigned(Stream) Then
  Begin
    WriteRemoteAddress; // Not a wise choice for UDP.
{$IFDEF NewOutBuffer}
    fNewOutBuffer.WriteSignal(signalSTREAMMarker,'','',0,Stream);
{$ELSE}
    fOutBuffer.AddObject(constSTREAMMarker,Stream);
{$ENDIF}
    DoWriteRequest;
  End;
End;

Procedure TDDUCustomSocket.WriteStreamData(Stream : TStream);

Var
  M                     : TDDUSocketMemoryStream;

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  If Assigned(Stream) And (Stream.Size-Stream.Position>0) Then
  Begin
    M := TDDUSocketMemoryStream.Create(Format('Copy of [%.8x] %s',[LongInt(Stream),Stream.ClassName]));
    Try
      M.CopyFrom(Stream,(Stream.Size-Stream.Position));
    Except
      FreeAndNil(M);
      Exit;
    End;
    M.Position := 0;
    M.Seek(0,soFromBeginning);

    WriteRemoteAddress; // not a wise choice for UDP
{$IFDEF NewOutBuffer}
    fNewOutBuffer.WriteSignal(signalPRIVATEMEMORYSTREAMMarker,'','',0,M);
{$ELSE}
    fOutbuffer.AddObject(constPRIVATEMEMORYSTREAMMarker,M);
{$ENDIF}
    DoWriteRequest;
  End;
End;

procedure TDDUCustomSocket.WriteText(const Text : string);

Var
  At                    : Integer;
  What                  : String;

Begin
  If Assigned(fRedirectSocket) Then
  Begin
    Raise Exception.Create('Redirection in progress, can not write');
  End;
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  If (EOL.Local<>emUnknown) Then
  Begin
    What := AdjustLineBreaks(Text);
    If (Copy(What,Length(What)-1,2)<>#13#10) Then
    Begin
      What := What+#13#10;
    End;
  End;
  // This will let us emulate multiple protocols.
  Case EOL.Local Of
    emLFCR            : Begin
                          Repeat
                            At := Pos(What,#13#10); // LF=10, Cr=13
                            If (At<>0) THen
                            Begin
                              What[At] := #10;
                              What[At+1] := #13;
                            End;
                          Until (At=0);
                        End;
    emCROnly          : Begin
                          Repeat
                            At := Pos(What,#10); // Strips linefeeds.
                            If (At<>0) THen
                            Begin
                              Delete(What,At,1);
                            End;
                          Until (At=0);
                        End;
    emLFOnly          : Begin
                          Repeat
                            At := Pos(What,#13); // Strips carriage returns.
                            If (At<>0) THen
                            Begin
                              Delete(What,At,1);
                            End;
                          Until (At=0);
                        End;
    emCustom          : Begin
                          What := StringReplace(What,#13#10,EOL.CustomLocalEOL,[rfReplaceAll]);
                        End;
  End;

{$IFDEF NewOutBuffer}
  WriteRemoteAddress;
  fNewOutBuffer.WriteString(What);
  DoWriteRequest;
{$ELSE}
  WriteBuffer(Pointer(What)^,Length(What));
{$ENDIF}
End;

procedure TDDUCustomSocket.EndServer;
begin
  fSkipReset := True;
  SuddenDisconnect;
end;

procedure TDDUCustomSocket.DisconnectClients;

Var
  Loop                  : Integer;

begin
  For Loop := fClients.Count-1 Downto 0 Do
  Begin
    fClients[Loop].Disconnect;
  End;
end;

procedure TDDUCustomSocket.SuddenDisconnectClients;

Var
  Loop                  : Integer;

begin
  For Loop := fClients.Count-1 Downto 0 Do
  Begin
    fClients[Loop].SuddenDisconnect;
  End;
end;

{ TDDUSocket }

procedure TDDUSocket.Connect;
begin
  inherited;
end;

procedure TDDUSocket.Disconnect;
begin
  inherited;
end;

procedure TDDUSocket.WaitForConnect;
begin
  inherited;
end;

{ TDDUSocketList }

Function TDDUSocketList.Add(Item : TDDUCustomSocket) : Integer;

Begin
  Result := Inherited Add(Item);
  If Assigned(fOwner) And Assigned(Item) And (Item.fSocketList=Nil) Then
  Begin
    Item.fSocketList := Self;
    fOwner.DoAddClient(Item);
  End;
End;

Function TDDUSocketList.First : TDDUCustomSocket;

Begin
  Result := Inherited First;
End;

Function TDDUSocketList.GetItem(Index : Integer) : TDDUCustomSocket;

Begin
  Result := TDDUCustomSocket(Inherited Items[Index]);
End;

Function TDDUSocketList.IndexOf(Item : TDDUCustomSocket) : Integer;

Begin
  result := Inherited IndexOf(Item);
end;

Procedure TDDUSocketList.Insert(Index : Integer; Item : TDDUCustomSocket);

Begin
  Inherited Insert(Index,Item);
End;

Function TDDUSocketList.Last : TDDUCustomSocket;

Begin
  Result := TDDUCustomSocket(Inherited Last);
End;

Function TDDUSocketList.Remove(Item : TDDUCustomSocket) : Integer;

Begin
  Result := Inherited Remove(Item);
  If Assigned(fOwner) And Assigned(Item) And (Item.fSocketList=Self) Then
  Begin
    fOwner.DoRemoveClient(Item);
    Item.fSocketList := Nil;
  End;
end;

Procedure TDDUSocketList.SetItem(Index : Integer; Const Value : TDDUCustomSocket);

Begin
  Inherited Items[Index] := Value;
  If Assigned(fOwner) And Assigned(Value) And (Value.fSocketList=Nil) Then
  Begin
    Value.fSocketList := Self;
    fOwner.DoAddClient(Value);
  End;
End;

var
  WSAData: TWSAData;

procedure Startup;

Var
  ErrorCode             : Integer;

Begin
  ErrorCode := WSAStartup($0101, WSAData);
  If Not (ErrorCode=0) Then
  Begin
    Raise ESocketError.CreateFmt(sWindowsSocketError,[SysErrorMessage(ErrorCode), ErrorCode, 'WSAStartup']);
  End;
End;

procedure Cleanup;

Var
  ErrorCode             : Integer;

Begin
  ErrorCode := WSACleanup;
  If Not (ErrorCode=0) Then
  Begin
    Raise ESocketError.CreateFmt(sWindowsSocketError,[SysErrorMessage(ErrorCode), ErrorCode, 'WSACleanup']);
  End;
End;

function TDDUCustomSocket.GetAvailableReadCount: UInt64;

Var
  V : ULONG;
begin
  V := 0;
  If (CanReadWrite) Then
  Begin
    ioctlsocket(SocketHandle, FIONREAD, u_long(V));
  End;
  Result := V;
end;

function TDDUCustomSocket.GetClient(Index : Integer): TDDUCustomSocket;
begin
  Result := fClients[Index]
end;

function TDDUCustomSocket.GetClientCount: Integer;
begin
  Result := fClients.Count;
end;


procedure TDDUCustomSocket.WMFreeChild(var Message: TMessage);

Var
  Child                   : TDDUCustomSocket;

begin
  Child := TDDUCustomSocket(Message.LParam);
  Child.Free;
end;

procedure TDDUCustomSocket.DoGetClientClass(var ClientClass: TDDUCustomSocketClass);
begin
  ClientClass := TDDUCustomSocket;
  If Assigned(fOnGetClientClass) Then
  Begin
    fOnGetClientClass(Self,CLientCLass);
  End
end;

procedure TDDUCustomSocket.DoClientInit(Client: TDDUCustomSocket);

Var
  Handled                 : Boolean;

begin
  Handled := False;
  If Assigned(fOnClientInit) Then
  Begin
    fOnClientInit(Self,Client,Handled);
  End;

  If Not Handled Then
  Begin
    Client.CopyEvents(Self);
  End;
end;


function TDDUCustomSocket.AbandonSocket: TSocket;
begin
  PrepareAsync(False);

  fThrottle.RemoveSocket(fSocket);
  fThrottle.Active := False;
  fThrottle.Clear;



  fActive        := False;          
  fConnected     := False;          
  fConnecting    := False;          
  fDisconnecting := False;          
  fSocket        := INVALID_SOCKET; 
  Result         := fSocket;        

  fAddressRemote.Clear;
  Flush;

  BlockReceiveAbort;
  DoFreeReceiveStream;

  If fFreeOnDisconnect Then // hmm, might wanna rethink this.
  Begin
    PostMessage(fFreeingParent.Handle,wm_FreeChild,0,LongInt(Self));
    Exit;
  End;

  fUDPSendAddress := '';
  fSkipReset := False;

  ReleaseRedirection;
end;

procedure TDDUCustomSocket.AdoptSocket(aSocket: TSocket);
begin
  If Active Then
  Begin
    Raise Exception.Create('Socket already active.');
  End;

  If (aSocket<>INVALID_SOCKET) Then
  Begin
    fSocket   := aSocket;
    fIsServer := False;
    fActive   := True;
    LoadAddressLocal;
    LoadAddressRemote;

    PrepareAsync(True);
    DoSocketConnect;
  End;
end;

procedure TDDUCustomSocket.BlockReceiveAbort;

Var                     
  aReceiveBlockStream     : TStream;  
  aReceiveBlockName       : String;   
  aReceiveBlockSize       : Cardinal; 

begin
  aReceiveBlockStream    := fReceiveCurrentBlockStream;
  aReceiveBlockName      := fReceiveCurrentBlockName;
  aReceiveBlockSize      := fReceiveCurrentBlockSize;

  fReceiveCurrentBlockStream := Nil;
  fReceiveCurrentBlockName   := '';
  fReceiveCurrentBlockSize   := 0;

  If (DataMode=dmBlock) Then
  Begin
    fDataMode := dmText;
  End;

  If Assigned(aReceiveBlockStream) Then
  Begin
    Try
      aReceiveBlockStream.Position := 0;
      DoBlockReceiveAbort(aReceiveBlockStream,aReceiveBlockName,aReceiveBlockSize);
    Finally
      If aReceiveBlockStream Is TDDUSocketMemoryStream Then
      Begin
        //Debug('++Pre-Freeing(5) TDDUSocketMemoryStream [%0.8x] [%0.8x]  :: %s',[LongInt(aStream), TDDUSocketMemoryStream(aStream).Seq,TDDUSocketMemoryStream(aStream).ID]);
      End;
      SafeFreeAndNil(aReceiveBlockStream);
    End;
  End;
end;

procedure TDDUCustomSocket.DoBeforeRead;
begin
  If Assigned(fOnBeforeRead) Then
  Begin
    fOnBeforeRead(Self);
  End;
end;

Procedure TDDUCustomSocket.DoBlockReceiveAbort(aStream : TStream; aName : String; aSize : Cardinal);
begin
  If Assigned(fOnBlockReceiveAbort) Then
  Begin
    fOnBlockReceiveAbort(Self,aStream,aName,aSize);
  End;
end;

procedure TDDUCustomSocket.DoBlockReceiveDone(aStream : TStream; aName : String; aSize : Cardinal);
begin
  If Assigned(fOnBlockReceiveDone) Then
  Begin
    fOnBlockReceiveDone(Self,aStream,aName,aSize);
  End;
end;

procedure TDDUCustomSocket.DoBlockReceiveStart(aStream : TStream; aName : String; aSize : Cardinal);
begin
  If Assigned(fOnBlockReceiveStart) Then
  Begin
    fOnBlockReceiveStart(Self,aStream,aName,aSize);
  End;
end;

procedure TDDUCustomSocket.BlockReceiveDone;

Var
  aReceiveBlockStream                 : TStream;
  aReceiveBlockName                   : String;
  aReceiveBlockSize                   : Cardinal;

begin
  aReceiveBlockStream    := fReceiveCurrentBlockStream;
  aReceiveBlockName      := fReceiveCurrentBlockName;
  aReceiveBlockSize      := fReceiveCurrentBlockSize;

  fReceiveCurrentBlockStream := Nil; 
  fReceiveCurrentBlockName   := '';  
  fReceiveCurrentBlockSize   := 0;   
  If DataMode=dmBlock Then
  Begin
    fDataMode  := dmText;
  End;

  If Assigned(aReceiveBlockStream) Then
  Begin
    Try
      aReceiveBlockStream.Position := 0;
      DoBlockReceiveDone(aReceiveBlockStream,aReceiveBlockName,aReceiveBlockSize);
    Finally
      If aReceiveBlockStream Is TDDUSocketMemoryStream Then
      Begin
        //Debug('++Pre-Freeing(5) TDDUSocketMemoryStream [%0.8x] [%0.8x]  :: %s',[LongInt(aStream), TDDUSocketMemoryStream(aStream).Seq,TDDUSocketMemoryStream(aStream).ID]);
      End;
      SafeFreeAndNil(aReceiveBlockStream);
    End;
  End;
end;

procedure TDDUCustomSocket.BlockReceiveStart;
begin
  DoBlockReceiveStart(fReceiveCurrentBlockStream,fReceiveCurrentBlockName,fReceiveCurrentBlockSize);
end;

procedure TDDUCustomSocket.BlockSendAbort;
begin
  fSendCurrentBlockStream := Nil;
  fSendCurrentBlockName   := '';
  fSendCurrentBlockSize   := 0;
end;

procedure TDDUCustomSocket.ReceiveBlock(BlockSize: Cardinal; BlockName: String);

begin
  BlockReceiveAbort;
  fReceiveCurrentBlockName            := BlockName;
  fReceiveCurrentBlockSize            := BlockSize;
  fReceiveCurrentBlockStream          := TDDUSocketMemoryStream.Create('ReceiveBlock:'+BlockName);
  fReceiveCurrentBlockStream.Size     := BlockSize;
  fReceiveCurrentBlockStream.Position := 0;
  fDataMode                           := dmBlock;
  BlockReceiveStart;
  If BlockSize=0 Then
  Begin
    BlockReceiveDone;
  End;
end;

procedure TDDUCustomSocket.SendBlock(BlockName: String; Stream: TStream);
begin
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  If Not Assigned(Stream) Then
  Begin
    Raise Exception.Create('You can not send an empty stream!');
  End;
  //Debug('++SendBlock(%s) [%.8x] [%s]',[Stream.Classname,LongInt(Stream),BlockName]);

  WriteText(BlockAutoStartPrefix+IntToStr(Stream.Size-Stream.Position)+','+BlockName);
  WriteStream(Stream);
End;

procedure TDDUCustomSocket.SendBlock(BlockName: String; Block: TStrings);

Var
  M                       : TMemoryStream;

begin
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;

  //Debug('++SendBlock(%s) [%s]',[Block.ClassName,BlockName]);

  M := TMemoryStream.Create;
  Try
    Block.SaveToStream(M);
    M.Position := 0;
    WriteText(BlockAutoStartPrefix+IntToStr(M.Size-M.Position)+','+BlockName);
    WriteStreamData(M);
  Finally
    FreeAndNil(M);
  End;
end;

procedure TDDUCustomSocket.SendBlock(BlockName, Data: String);
begin
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  //Debug('++SendBlock(String) [%s]',[BlockName]);
  WriteText(BlockAutoStartPrefix+IntToStr(Length(Data))+','+BlockName);
end;

procedure TDDUCustomSocket.DoBlockReceiveProgress(S : TStream; aName : String);
begin
  If Assigned(fOnBlockReceiveProgress) Then
  Begin
    fOnBlockReceiveProgress(Self,aName, S.Position, S.Size);
  End;
end;

procedure TDDUCustomSocket.DoBlockSendProgress(S : TStream; aName : String) ;
begin
  If Assigned(fOnBlockSendProgress) Then
  Begin
    fOnBlockSendProgress(Self,aName,S.Position,S.Size);
  End;
end;

procedure TDDUCustomSocket.DoBlockSendStart(aStream: TStream; aName: String; aSize: Cardinal);
begin
  If Assigned(fOnBlockSendStart) Then
  Begin
    fOnBlockSendStart(Self,aStream,aName,aSize);
  End;
end;

procedure TDDUCustomSocket.WriteBlock(BlockName: String; Stream: TStream);

begin
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  If Not Assigned(Stream) Then
  Begin
    Raise Exception.Create('You can not send an empty stream!');
  End;
  //Debug('++SendBlock(%s)  [%.8x] [%s]',[Stream.ClassName,LongInt(Stream),BlockName]);

  WriteText(BlockAutoStartPrefix+IntToStr(Stream.Size-Stream.Position)+','+BlockName);
{$IFDEF NewOutBuffer}
  fNewOutBuffer.WriteSignal(signalSendBLOCKMarker,BlockName,'',0,Stream);
{$ELSE}
  fOutBuffer.AddObject(constBLOCKMarker+BlockName,Stream);
{$ENDIF}
  DoWriteRequest;
end;

procedure TDDUCustomSocket.WriteBlock(BlockName: String; Block: TStrings);

Var
  S                       : String;

begin
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  //Debug('++SendBlock(%s) [%s]',[Block.ClassName,BlockName]);
  S := Block.Text;
  WriteText(BlockAutoStartPrefix+IntToStr(Length(S))+','+BlockName);
  WriteRawText(S);
end;

procedure TDDUCustomSocket.WriteBlock(BlockName, Data: String);
begin
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  //Debug('++SendBlock(String) [%s]',[BlockName]);
  WriteText(BlockAutoStartPrefix+IntToStr(Length(Data))+','+BlockName);
  WriteRawText(Data);
end;

procedure TDDUCustomSocket.WriteRemoteAddress;

Begin
  If (Not CanReadWrite) Then
  Begin
    Exit;
  End;
  If (SocketProtocol in [spUDP,spUDPBroadcast]) Then
  Begin
{$IFDEF NewOutBuffer}
    fNewOutBuffer.WriteSignal(signalSETUPSENDADDRESSMarker,AddressRemote.Text,'',0,nil,nil);
{$ELSE}
    fOutBuffer.AddObject(constSETUPSENDADDRESSMarker+AddressRemote.Text,TObject(1) );
{$ENDIF}
    DoWriteRequest;
  End;
end;

procedure TDDUCustomSocket.RedirectTo(Socket: TDDUCustomSocket);

begin
  If Assigned(Socket) And Socket.Active Then
  Begin
    Raise Exception.Create('Redirection target is already active.');
  End;

  If Assigned(fRedirectSocket) Then
  Begin
    fRedirectSocket.ReleaseRedirection;
  End;

  If Assigned(Socket) And Active Then
  Begin
    fRedirectSocket        := Socket;
    Socket.fRedirectParent := Self;

    Socket.fSocket         := fSocket;
    Socket.fSocketMode     := smClient;
    Socket.fActive         := fActive;
    Socket.fConnected      := fConnected;

    Socket.DoConnect;
    Socket.TakeBuffers(Self);

    If (InBufferLength<>0) Then
    Begin
      PostMessage(Socket.Handle,CM_DispatchIncomingData,0,0);
    End;
    Socket.DoReadRequest;
    Socket.DoWriteRequest;
  End;
end;

procedure TDDUCustomSocket.ReleaseRedirection;

Var
  WasActive               : Boolean;
  aParent                 : TDDUCustomSocket;

begin
  If Assigned(fRedirectParent) Then
  Begin
    WasActive := Active;
    aParent   := fRedirectParent;

    fRedirectParent.TakeBuffers(Self);

    fRedirectParent.fRedirectSocket := Nil;
    fSocket := INVALID_SOCKET;
    fActive := False;
    fConnected := False;
    fAddressLocal.Clear;
    fAddressRemote.Clear;
    fRedirectParent := Nil;

    If Not WasActive Then
    Begin
      aParent.SuddenDisconnect;
    End
    Else
    Begin
      If (aParent.InBufferLength<>0) Then
      Begin
        PostMessage(aParent.Handle,CM_DispatchIncomingData,0,0);
      End;
      aParent.DoReadRequest;
      aParent.DoWriteRequest;
    End;
  End;
end;

procedure TDDUCustomSocket.TakeBuffers(Source: TDDUCustomSocket);

{$IFNDEF NewOutBuffer}
Var
  Loop                    : Integer;
{$ENDIF}

begin
  fReceiveCurrentBlockName   := Source.fReceiveCurrentBlockName;
  fReceiveCurrentBlockSize   := Source.fReceiveCurrentBlockSize;
  fReceiveCurrentBlockStream := Source.fReceiveCurrentBlockStream;
  fSendCurrentBlockName      := Source.fSendCurrentBlockName;
  fSendCurrentBlockSize      := Source.fSendCurrentBlockSize;
  fSendCurrentBlockStream    := Source.fSendCurrentBlockStream;

  fReceiveStream             := Source.fReceiveStream;

  fUDPSendAddress := Source.fUDPSendAddress;
{$IFDEF NewInBuffer}
  fNewInBuffer.StealNodes(Source.fNewInBuffer);
{$ELSE}
  fInBuffer       := Source.fInBuffer;
  Source.fInBuffer           := '';
{$ENDIF}


{$IFDEF NewOutBuffer}
  fNewOutBuffer.StealNodes(Source.fNewOutBuffer);
{$ELSE}
  For Loop := 0 To Source.fOutBuffer.Count-1 Do
  Begin
    fOutBuffer.AddObject(Source.fOutBuffer[Loop],Source.fOutBuffer.Objects[Loop]);
  End;
  Source.fOutBuffer.Clear;
{$ENDIF}

  Source.fReceiveStream             := Nil; /// uuuh. should be nil I think

  Source.fReceiveCurrentBlockName   := '';
  Source.fReceiveCurrentBlockSize   := 0;
  Source.fReceiveCurrentBlockStream := Nil;
  Source.fSendCurrentBlockName      := '';      
  Source.fSendCurrentBlockSize      := 0;
  Source.fSendCurrentBlockStream    := Nil;
end;

{ TDDUSocketMemoryStream }

constructor TDDUSocketMemoryStream.Create(aID: String);
begin
  Inherited Create;
  fID  := aID;
  fSeq := InterlockedIncrement(MSSeq);
  //Debug('++Creating TDDUSocketMemoryStream [%0.8x] [%0.8x]  :: %s',[LongInt(Self), fSeq,fID]);
end;

destructor TDDUSocketMemoryStream.Destroy;
begin
  //Debug('++Freeing TDDUSocketMemoryStream [%0.8x] [%0.8x]  :: %s',[LongInt(Self), fSeq,fID]);
  inherited;
end;

Initialization
  Startup;
Finalization
  Cleanup;
End.

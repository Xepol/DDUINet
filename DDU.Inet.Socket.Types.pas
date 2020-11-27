unit DDU.Inet.Socket.Types;

//*********************************************************************************************************************
//
// DDUINET (DDU.Inet.Socket.Types)
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
// Supported features :
//
//            - Provides flexible address asignments for controls.
//            - Provides throttling (speed meters and speed limiting)
//            - Provides Timeout capabilities
//
// Version : 2.0
//
// History
//*****************
//
// Version 1.0 - 1999
//
// Version 2.0 - July 2002
//
//            - Added IsValid to TDDUSocketAddress.
//            - Moved TDataMode,TSocketMode,TSocketProcotol,TSocketOption,TSocketOptions,
//              TSocksMode,TTextMode,TTextModeSet to DDUSocketTypes
//            - Move SocketErrorMessage, CheckSocketResult to DDUSocketTypes
//            - Added additional exceptions to support SocketStreams.
//
// Future plans
//             - WinSock2, IP6 support
//
//
// Future plans
//             - WinSock2, IP6 support
//*********************************************************************************************************************

interface

{$I DVer.inc}

{.$DEFINE WINSOCK2}
{.$DEFINE DSI}

uses
  WinAPI.Windows, WinAPI.Messages,
{$IFDEF WINSOCK2}
  DDU.Inet.WinAPI.WinSock2,
{$ELSE}
  WinAPI.WinSock,
{$ENDIF}
  System.SysUtils,
  System.Classes,
//  DDUWebConst
  DDU.Inet.Socket.Consts
  {$IF defined(DSI)},DSiWin32{$ENDIF};

{$I DTypes.inc}

Type
  ESocketError            = Class(Exception);
  EInvalidAddress         = Class(Exception);  // Used by Socket Streams
  ESocketSeekError        = Class(ESocketError);
  ESocketSizeError        = Class(ESocketError);
  ESocketThreadTerminated = Class(ESocketError);

Type
  TDataMode = (dmRaw,dmCookedRaw,dmCookedText,dmText,dmStream,dmRawStream,dmBlock);
  TSocketMode = (smAuto,smAutoReset,smClient,smServerSingle,smServerSingleReset,smServerDispatch);
  TSocketProtocol =(spTCP,spUDP,spUDPBroadcast);

  TSocketOption = (soBroadcast,soDebug,soDontRoute,soKeepAlive, soLinger,soReuseAddr,soTCPNoDelay);
  TSocketOptions = Set Of TSocketOption;

  TSocksMode = (smConnect,smBind);

  TTextMode = (tmEcho,tmBackspace,tmRawText,tmFlowControl);
  TTextModeSet = Set Of TTextMode;

Const
  CM_SOCKETMESSAGE        = WM_USER + $1001;
  CM_DispatchIncomingData = WM_USER + $1002;
  CM_WAITFORCONNECT       = WM_USER + $1003;
  wm_FreeChild            = WM_USER + 1;

Type
  TCMSocketMessage      = Record
                            Msg         : Cardinal;
                            Socket      : TSocket;
                            SelectEvent : Word;
                            SelectError : Word;
                            Result      : Longint;
                          End;

Type
  TEOLMarker = (emUnknown,emCRLF,emLFCR,emCROnly,emLFOnly,emCustom);

Type
  PPInAddr = ^PINAddr;
  PIPList = ^TIPList;
  TIPList = Array[0..8192] Of PInAddr;
  PDDUHostEnt = ^TDDUHostEnt;
  TDDUHostEnt = packed record
                  h_name: PAnsiChar;
                  h_aliases: ^PAnsiChar;
                  h_addrtype: Smallint;
                  h_length: Smallint;
                  case Byte of
                    0: (h_addr: PPInAddr);
                    1: (h_addr_list: PIPList)
                  end;

Type
  TDDUCount = Class(TPersistent)
  Private
    fRead  : Cardinal;   // Bits per second
    fWrite : Cardinal;   // Bits per second
  Public
    Procedure Assign(Source : TPersistent); Override;
  Published
    Property Read  : Cardinal Read fRead  Write fRead  Default 0;
    Property Write : Cardinal Read fWrite Write fWrite Default 0;
  End;

Type
  TDDUEOL = Class(TPersistent)
  Private
    fCustomLocalEOL  : String;
    fCustomRemoteEOL : String;
    fLocal           : TEOLMarker;
    fRemote          : TEOLMarker;
  Public
    Constructor Create; Virtual;
  Published
    Property CustomLocalEOL  : String     Read fCustomLocalEOL  write fCustomLocalEOL;
    Property CustomRemoteEOL : String     Read fCustomRemoteEOL write fCustomRemoteEOL;
    Property Local           : TEOLMarker Read fLocal           Write fLocal            Default emCRLF;
    property Remote          : TEOLMarker Read fRemote          Write fRemote           Default emUnknown;
  End;

Type
  TDDUSpeed = Class(TDDUCount)
  Private
    fUseFlowRate : Boolean;
    Function GetReadBps : Cardinal;
    Function GetReadKBps : Cardinal;
    Function GetWriteBps : Cardinal;
    Function GetWriteKBps : Cardinal;
  Public
    Procedure Assign(Source : TPersistent); Override;
  Published
    Property ReadBps     : Cardinal Read GetReadBps;                        // Bytes per second
    Property ReadKBps    : Cardinal Read GetReadKBps;                       // Bytes per second
    Property WriteBps    : Cardinal Read GetWriteBps;                       // Kilobytes per second
    Property WriteKBps   : Cardinal Read GetWriteKBps;                      // Kilobytes per second
    Property UseFlowRate : Boolean  Read fUseFlowRate  Write fUseFlowRate Default False;
  End;

Type
  TTimeoutCause = (toBoth,toRead,toWrite);
  TTimeoutCauses = Set Of TTimeoutCause;

  TTimeoutEvent = Procedure(Sender : TObject; Causes : TTimeoutCauses) Of object;

Type
  TDDUTimeout = Class(TPersistent)
  Private
    fBoth      : Cardinal;  // ms since last read or write
    fRead      : Cardinal;  // ms since last read
    fWrite     : Cardinal;  // ms since last write
    fLastWrite : Cardinal;
    fLastRead  : Cardinal;
    fLastBoth  : Cardinal;
  Public
    Procedure Assign(Source : TPersistent); Override;
  Published
    Property Both  : Cardinal Read fBoth  Write fBoth  Default 0;
    Property Read  : Cardinal Read fRead  Write fRead  Default 0;
    Property Write : Cardinal Read fWrite Write fWrite Default 0;
  End;

Type
  TDDUSocketAddress = Class(TPersistent)
  Private
    fAddress     : String;     // IP address.
    fDefaultPort : Integer;   
    fHost        : String;     // Host Name
    fPort        : Integer;    // PORT value
    fProtocol    : String;     // Service as text.
    fService     : String;    
    fSockAddr    : TSockAddr; 

    Function  GetDefaultText : String;
    Function  GetIP : U_long;
    Function  GetText : String;
    Function  GetFTPText : String;
    Procedure SetAddress(Const NewValue : String);
    Procedure SetFTPText(Const NewValue : String);
    Procedure SetHost(Const NewValue : String);
    Procedure SetIP(Const NewValue : U_long);
    Procedure SetPort(Const NewValue : Integer);
    Procedure SetService(Const NewValue : String);
    procedure SetSockAddr(const Value: TSockAddr);
  Protected
  Public
    Constructor Create; Virtual;
    Procedure Assign(Source : TPersistent); Override;
    Procedure Clear;
    function  LookupName(const name: string) : TInAddr;
    Function  LookupService(const Service: string): Integer;

    Function IsValid : Boolean;

    Property DefaultPort : Integer Read fDefaultPort    Write fDefaultPort Default 0;
    Property DefaultText : String  Read GetDefaultText;
    Property IP          : U_long  Read GetIP           Write SetIP;
    Property Text        : String  Read GetText         Write SetHost;
    Property FTPText     : String  Read GetFTPText      Write SetFTPText;
    Property Protocol    : String  Read fProtocol       Write fProtocol;

    Property SockAddr    : TSockAddr Read fSockAddr     Write SetSockAddr;
  Published
    Property Address     : String   Read fAddress     Write SetAddress;
    Property Host        : String   Read fHost        Write SetHost;
    Property Port        : Integer  Read fPort        Write SetPort Default 0;
    Property Service     : String   Read fService     Write SetService;
  End;

Type
  TDDUSocketUser = Class(TPersistent)
  Private
    fPassword : String;
    fUserName : String;
  Public
    Procedure Assign(Source : TPersistent); Override;
  Published
    Property Password : String   Read fPassword Write fPassword;
    Property UserName : String   Read fUserName Write fUserName;
  End;

Type
  TDDUThrottle = Class(TPersistent)
  Private
//*****************************************************************************
// Internal counters to measure the speed.
//*****************************************************************************
    fDataRead           : Cardinal; // For comparison
    fDataReadLast       : Cardinal; // For comparison
    fDataWrite          : Cardinal; // For comparison
    fDataWriteList      : Cardinal; // For comparison
    fTimeStart          : Cardinal; // For average speed.
    fTimeLastUpdate     : Cardinal; // Last time speed was tested.
//*****************************************************************************
// Maximum block sizes per operation.
//*****************************************************************************
    fBlockSize          : TDDUCount;
//*****************************************************************************
// Socket lists.
//*****************************************************************************
    fSockets            : TList;
    fWindows            : TList;
//*****************************************************************************
// Speed Controls.
//*****************************************************************************
    fSpeedAvg           : TDDUSpeed;
    fSpeedFlow          : TDDUSpeed;
    fSpeedLimit         : TDDUSpeed;
//*****************************************************************************
//  Timeouts
//*****************************************************************************
    fTimeout            : TDDUTimeout;
//*****************************************************************************
// Timer for updates
//*****************************************************************************
    fActive             : Boolean;
    fEnabled            : Boolean;
    fInterval           : Integer;
    fTimerWnd           : HWnd;
//*****************************************************************************
// Events
//*****************************************************************************
    fOnThrottle         : TNotifyEvent;
    fOnThrottleReadOff  : TNotifyEvent;
    fOnThrottleReadOn   : TNotifyEvent;
    fOnThrottleWriteOff : TNotifyEvent;
    fOnThrottleWriteOn  : TNotifyEvent;
    fOnTimeout          : TTimeoutEvent;
    fMasterThrottle     : TDDUThrottle;
    Procedure SetActive(Const NewValue : Boolean);
    Procedure SetEnabled(Const NewValue : Boolean);
    Procedure SetInterval(Const NewValue : Integer);
  Protected
    Procedure CalculateAVGSpeeds;
    Procedure CalculateFlowSpeeds;
    Procedure CheckTimeouts;
    Procedure DoTimeout(Causes : TTimeoutCauses); Virtual;
    Procedure UpdateTimer;
    Procedure WndProc(Var Msg : TMessage);
  Public
    Constructor Create; Virtual;
    Destructor Destroy; Override;
  Public
    Procedure Assign(Source : TPersistent); Override;
    Procedure AddSocket(aSocket : TSocket; Wnd : hWnd);
    Function  CanRead(aSocket : TSocket) : Boolean;
    Function  CanWrite(aSocket : TSocket) : Boolean;
    Procedure Clear;
    Procedure CalculateSpeeds;
    Procedure RegisterDataRead(Size : Cardinal);
    Procedure RegisterDataWrite(Size : Cardinal);
    Procedure RemoveSocket(aSocket : TSocket);
    Procedure ThrottleReadOff; Virtual;
    Procedure ThrottleReadOn; Virtual;
    Procedure ThrottleWriteOff; Virtual;
    Procedure ThrottleWriteOn; Virtual;
  Public
    Property Active         : Boolean      Read fActive         Write SetActive;
    Property DataRead       : Cardinal     Read fDataRead;
    Property DataWrite      : Cardinal     Read fDataWrite;
    Property SpeedAvg       : TDDUSpeed    Read fSpeedAvg;
    Property SpeedFlow      : TDDUSpeed    Read fSpeedFlow;
    Property MasterThrottle : TDDUThrottle Read fMasterThrottle Write fMasterThrottle;
  Public
    Property OnThrottle         : TNotifyEvent  Read fOnThrottle         Write fOnThrottle;
    Property OnThrottleReadOff  : TNotifyEvent  Read fOnThrottleReadOff  Write fOnThrottleReadOff;
    Property OnThrottleReadOn   : TNotifyEvent  Read fOnThrottleReadOn   Write fOnThrottleReadOn;
    Property OnThrottleWriteOff : TNotifyEvent  Read fOnThrottleWriteOff Write fOnThrottleWriteOff;
    Property OnThrottleWriteOn  : TNotifyEvent  Read fOnThrottleWriteOn  Write fOnThrottleWriteOn;
    Property OnTimeout          : TTimeoutEvent Read fOnTimeout          Write fOnTimeout;
  Published
    Property BlockSize      : TDDUCount   Read fBlockSize  Write fBlockSize;
    Property Enabled        : Boolean     Read fEnabled    Write SetEnabled  Default True;
    Property Interval       : Integer     Read fInterval   Write SetInterval Default 100;
    Property SpeedLimit     : TDDUSpeed   Read fSpeedLimit Write fSpeedLimit;
    Property TimeOut        : TDDUTimeout Read fTimeout    Write fTimeout;
  End;

Function SocketErrorMessage(ErrNo : Integer) : String;
Function CheckSocketResult(ResultCode: Integer; const Op: string) : Integer;

Implementation

Const
  TimerID               = $1234;
  WriteID               = $123;
  ReadID                = $321;

Function SocketErrorMessage(ErrNo : Integer) : String;

Begin
  Result := IntToStr(ErrNo);
  Case ErrNo of
     0                  : Result := Result +sWSANoError;
     WSAEINTR           : Result := Result +sWSAEINTR;
     WSAEBADF           : Result := Result +sWSAEBADF;
     WSAEFAULT          : Result := Result +sWSAEFAULT;
     WSAEINVAL          : Result := Result +sWSAEINVAL;
     WSAEMFILE          : Result := Result +sWSAEMFILE;
     WSAEWOULDBLOCK     : Result := Result +sWSAEWOULDBLOCK;
     WSAEINPROGRESS     : Result := Result +sWSAEINPROGRESS;
     WSAEALREADY        : Result := Result +sWSAEALREADY;
     WSAENOTSOCK        : Result := Result +sWSAENOTSOCK;
     WSAEDESTADDRREQ    : Result := Result +sWSAEDESTADDRREQ;
     WSAEMSGSIZE        : Result := Result +sWSAEMSGSIZE;
     WSAEPROTOTYPE      : Result := Result +sWSAEPROTOTYPE;
     WSAENOPROTOOPT     : Result := Result +sWSAENOPROTOOPT;
     WSAEPROTONOSUPPORT : Result := Result +sWSAEPROTONOSUPPORT;
     WSAESOCKTNOSUPPORT : Result := Result +sWSAESOCKTNOSUPPORT;
     WSAEOPNOTSUPP      : Result := Result +sWSAEOPNOTSUPP;
     WSAEPFNOSUPPORT    : Result := Result +sWSAEPFNOSUPPORT;
     WSAEAFNOSUPPORT    : Result := Result +sWSAEAFNOSUPPORT;
     WSAEADDRINUSE      : Result := Result +sWSAEADDRINUSE;
     WSAEADDRNOTAVAIL   : Result := Result +sWSAEADDRNOTAVAIL;
     WSAENETDOWN        : Result := Result +sWSAENETDOWN;
     WSAENETUNREACH     : Result := Result +sWSAENETUNREACH;
     WSAENETRESET       : Result := Result +sWSAENETRESET;
     WSAECONNABORTED    : Result := Result +sWSAECONNABORTED;
     WSAECONNRESET      : Result := Result +sWSAECONNRESET;
     WSAENOBUFS         : Result := Result +sWSAENOBUFS;
     WSAEISCONN         : Result := Result +sWSAEISCONN;
     WSAENOTCONN        : Result := Result +sWSAENOTCONN;
     WSAESHUTDOWN       : Result := Result +sWSAESHUTDOWN;
     WSAETOOMANYREFS    : Result := Result +sWSAETOOMANYREFS;
     WSAETIMEDOUT       : Result := Result +sWSAETIMEDOUT;
     WSAECONNREFUSED    : Result := Result +sWSAECONNREFUSED;
     WSAELOOP           : Result := Result +sWSAELOOP;
     WSAENAMETOOLONG    : Result := Result +sWSAENAMETOOLONG;
     WSAEHOSTDOWN       : Result := Result +sWSAEHOSTDOWN;
     WSAEHOSTUNREACH    : Result := Result +sWSAEHOSTUNREACH;
     WSAENOTEMPTY       : Result := Result +sWSAENOTEMPTY;
     WSAEPROCLIM        : Result := Result +sWSAEPROCLIM;
     WSAEUSERS          : Result := Result +sWSAEUSERS;
     WSAEDQUOT          : Result := Result +sWSAEDQUOT;
     WSAESTALE          : Result := Result +sWSAESTALE;
     WSAEREMOTE         : Result := Result +sWSAEREMOTE;
     WSASYSNOTREADY     : Result := Result +sWSASYSNOTREADY;
     WSAVERNOTSUPPORTED : Result := Result +sWSAVERNOTSUPPORTED;
     WSANOTINITIALISED  : Result := Result +sWSANOTINITIALISED;
     WSAHOST_NOT_FOUND  : Result := Result +sWSAHOST_NOT_FOUND;
     WSATRY_AGAIN       : Result := Result +sWSATRY_AGAIN;
     WSANO_RECOVERY     : Result := Result +sWSANO_RECOVERY;
     WSANO_DATA         : Result := Result +sWSANO_DATA;
  Else
    Result := Result +sWSAUndefined;
  End;
End;

Function CheckSocketResult(ResultCode: Integer; const Op: string) : Integer;

Begin
  If (ResultCode<>0) Then
  Begin
    Result := WSAGetLastError;
    If (Result <> WSAEWOULDBLOCK) Then
    Begin
      Raise ESocketError.CreateFmt(sWindowsSocketError,[SysErrorMessage(Result), Result, Op,SocketErrorMessage(Result)]);
    End;
  End
  Else
  Begin
    Result := 0;
  End;
End;

Constructor TDDUEOL.Create;

Begin
  Inherited Create;
  fLocal := emCRLF;
  fRemote := emUnknown;
End;

//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************

procedure TDDUSpeed.Assign(Source: TPersistent);
begin
  If Source Is TDDUSpeed Then
  Begin
    fUseFlowRate := TDDUSpeed(Source).fUseFlowRate;
  End
  Else
  Begin
    inherited;
  End;
end;

Function TDDUSpeed.GetReadBps : Cardinal;

Begin
  REsult := fRead Div 8;
End;

Function TDDUSpeed.GetReadKBps : Cardinal;

Begin
  REsult := fRead Div 8000;
End;

Function TDDUSpeed.GetWriteBps : Cardinal;

Begin
  Result := fWrite Div 8;
End;

Function TDDUSpeed.GetWriteKBps : Cardinal;

Begin
  Result := fWrite Div 8000;
End;

//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************

Procedure TDDUSocketAddress.Assign(Source : TPersistent); 

Begin
  If Source Is TDDUSocketAddress Then
  Begin
    fAddress  := TDDUSocketAddress(Source) .fAddress;  
    fHost     := TDDUSocketAddress(Source) .fHost;     
    fPort     := TDDUSocketAddress(Source) .fPort;     
    fService  := TDDUSocketAddress(Source) .fService;  
    fProtocol := TDDUSocketAddress(Source) .fProtocol; 
  End
  Else
  Begin
    Inherited Assign(Source);
  End;
End;

Procedure TDDUSocketAddress.Clear;

Begin
  fAddress := '';
  fHost    := '';
  fPort    := 0;
  fService := '';
  fProtocol := 'tcp';
End;

constructor TDDUSocketAddress.Create;
begin
  Inherited Create;
  Clear;
end;

Function TDDUSocketAddress.GetDefaultText : String;

Begin
  If (Host='') Then
  Begin
    Result := Address;
  End
  Else
  Begin
    Result := Host;
  End;
  If (Result<>'') Then
  Begin
    If (Service='') Then
    begin
      If ((DefaultPort=0) Or (Port<>DefaultPort)) Then
      Begin
        Result := Result+':'+IntToStr(Port);
      End;
    End
    Else
    Begin
      Result := Result+':'+Service;
    End;
  End;
End;

Function TDDUSocketAddress.GetIP : U_long;

Var
  ansiAddress             : AnsiString;

Begin
  ansiAddress := Trim(fAddress);
  Result := Inet_Addr(PAnsiChar(ansiAddress));
End;

Function TDDUSocketAddress.GetText : String;

Begin
  If (Host='') Then
  Begin
    Result := Address;
  End
  Else
  Begin
    Result := Host;
  End;
  If (Result<>'') Then
  Begin
    If (Service='') Then
    begin
      Result := Result+':'+IntToStr(Port);
    End
    Else
    Begin
      Result := Result+':'+Service;
    End;
  End;
End;

Function TDDUSocketAddress.GetFTPText : String;

Var
  Loop                  : Integer;

Begin
  If (Address='') Then
  Begin
    Result := inet_ntoA(LookupName(fHost));
  End
  Else
  Begin
    Result := Address;
  End;
  Result := Result+'.'+IntToStr(Port Div 256)+'.'+IntToStr(Port And $ff);
  For Loop := 1 To Length(Result) Do
    If Result[Loop]='.' Then Result[Loop] := ',';
End;

function TDDUSocketAddress.IsValid: Boolean;
begin
  Result := ((Host<>'') Or (IP<>INADDR_ANY) ) And ( (Service<>'') Or (Port<>0) );
end;

Function TDDUSocketAddress.LookupName(const Name: string): TInAddr;

Var
  HostEnt               : PDDUHostEnt;
  ansiName              : AnsiString;

Begin
  ansiName := Trim(Name);
  HostEnt := PDDUHostEnt(gethostbyname(PAnsiChar(ansiName)));
  If HostEnt <> nil Then
  Begin
    Result := HostEnt^.h_addr^^;
  End
  Else
  Begin
    Result.s_Addr := u_Long(INADDR_ANY);
  End;
End;

function TDDUSocketAddress.LookupService(const Service: string): Integer;

Var
  ServEnt               : PServEnt;
  ansiService           : AnsiString;
  ansiProtocol          : AnsiString;

Begin
  ansiService  := trim(Service);
  ansiProtocol := trim(fProtocol);
  ServEnt := getservbyname(PAnsiChar(ansiService), PAnsiChar(ansiProtocol));

  If Assigned(ServEnt) Then
  Begin
    Result := ntohs(ServEnt.s_port);
  End
  Else
  Begin
    Result := 0;
  End;
End;

Procedure TDDUSocketAddress.SetAddress(Const NewValue : String);

Var
  TestIP                : TINAddr;
  ansiNewValue          : AnsiString;

Begin
//*****************************************************************************
// Ensure that the IP is correct.
//*****************************************************************************
  fHost := '';
  fAddress := '';
  ansiNewValue := Trim(NewValue);
  TestIP.s_ADDR := Inet_Addr(PAnsiChar(ansiNewValue));  // Is it actually an IP?
  If (TestIP.S_Addr=U_Long(INADDR_NONE)) Or (TestIP.S_Addr=U_Long(INADDR_ANY)) Then
  Begin
    Host := NewValue;
  End
  Else
  Begin
    fAddress := NewValue;
  End;
End;

Procedure TDDUSocketAddress.SetFTPText(Const NewValue : String);

Var
  Work                  : String;

Function GetToken : Integer;

Var
  At : Integer;

Begin
  at := Pos(',',Work);
  If (At=0) Then
  Begin
    Result := StrToIntDef(Work,0);
    Work := '';
  End
  Else
  Begin
    Result := StrToIntDef(Copy(Work,1,At-1),0);
    Delete(Work,1,At);
  End;
  Result := Result And $ff;
End;

Begin
  Work := NewValue;
  Address := IntToStr(GetToken)+'.'+IntToStr(GetToken)+'.'+IntToStr(GetToken)+'.'+IntToStr(GetToken);
  Port := GetToken*256+GetToken;
End;

Procedure TDDUSocketAddress.SetHost(Const NewValue : String);

Var
  At                    : Integer;
  TestIP                : TINAddr;
  Work                  : String;
  ansiWork              : AnsiString;

Begin
  Work := Trim(NewValue);
  At := Pos(':',NewValue);
  If (At<>0) Then
  Begin
    Work := NewValue;
    Delete(Work,1,At);
    Service := Trim(Work);
    Work := Trim(Copy(NewValue,1,At-1));
  End;
//*****************************************************************************
// Check if the host name is actually an IP, if so, assign it to the ADDRESS
// field instead.
//*****************************************************************************
  ansiWork := Work;
  TestIP.s_ADDR := Inet_Addr(PAnsiChar(ansiWork));  // Is it actually an IP?
  If (TestIP.S_Addr<>U_Long(INADDR_NONE)) And (TestIP.S_Addr<>U_Long(INADDR_ANY)) Then
  Begin
    fHost := '';
    Address := Work;
  End
  Else
  Begin
    fHost := Work;
    fAddress := '';
  End;
End;

Procedure TDDUSocketAddress.SetIP(Const NewValue : U_long);

{$IFDEF WINSOCK2}
Var
  L                       : Cardinal;
{$EndIf}

Begin
  fHost := '';
{$IFDEF WINSOCK2}
  L := 1024;
  SetLength(fAddress,L);
  If WSAAddressToString(fSockAddr,SizeOf(fSockAddr),Nil,PChar(fAddress),L)=0 Then
  Begin
  ENd
  ELse
  Begin
    SetLength(fAddress,L);//StrLen(fAddress));
  End;
{$ELSE}
  fAddress := Inet_NtoA(TINAddr(NewValue));
{$ENDIF}
End;

Procedure TDDUSocketAddress.SetPort(Const NewValue : Integer);

Begin
//*****************************************************************************
// PORT is meaningless, so just clear it.
//*****************************************************************************
  fPort    := newValue;
  fService := '';

  TSockAddrIn(fSockAddr).sin_port := htons(fPort);
End;

Procedure TDDUSocketAddress.SetService(Const NewValue : String);

Var
  V,E                   : Integer;

Begin
//*****************************************************************************
// Make sure that the service IS a service, and not a port number.
//*****************************************************************************
  Val(NewValue,V,E);
  If E=0 Then
  Begin
    fPort := V;
    fService := '';
  End
  Else
  Begin
    fPort := 0;
    fService := NewValue;
  End;
End;

procedure TDDUSocketAddress.SetSockAddr(const Value: TSockAddr);
begin
  fSockAddr := Value;
{$IFDEF WINSOCK2}
  IP := INADDR_ANY;
  Port := ntohs(TSockAddrIn(Value).sin_port);
{$ELSE}
  IP  := Value.sin_addr.S_addr;
  Port := ntohs(Value.sin_port);
{$ENDIF}


end;

//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************

Constructor TDDUThrottle.Create;

Begin
  Inherited Create;
  fInterval   := 100;                
  fEnabled    := True;               
  fBlockSize  := TDDUCount.Create;
  fSpeedAvg   := TDDUSpeed.Create;   
  fSpeedFlow  := TDDUSpeed.Create;   
  fSpeedLimit := TDDUSpeed.Create;   
  fTimeout    := TDDUTimeout.Create;
  fSockets    := TList.Create;       
  fWindows    := TList.Create;       
End;

Destructor TDDUThrottle.Destroy;

Begin
  Active := False;
  FreeAndNil(fWindows);
  FreeAndNil(fSockets);
  FreeAndNil(fTimeout);
  FreeAndNil(fSpeedLimit);
  FreeAndNil(fSpeedFlow);
  FreeAndNil(fSpeedAvg);
  FreeAndNil(fBlockSize);
  Inherited Destroy;
End;

Procedure TDDUThrottle.AddSocket(aSocket : TSocket; Wnd : hWnd);

Begin
  If (aSocket<>INVALID_SOCKET) Then
  Begin
    If (fSockets.IndexOf(Pointer(aSocket))=-1) Then
    Begin
      fSockets.Add(Pointer(aSocket));
      fWindows.Add(Pointer(Wnd));
    End;
  End;
End;

Procedure TDDUThrottle.CalculateAVGSpeeds;

Var
  Now                   : Cardinal;
  Duration              : Cardinal;

Begin
  Now := GetTickCount;
  Duration := Now-fTimeStart;
  If Duration=0 Then Duration := 1;
  fSpeedAvg.Read  := Round(fDataRead*8000.0/Duration);
  fSpeedAvg.Write := Round(fDataWrite*8000.0/Duration);
End;

Procedure TDDUThrottle.CalculateFlowSpeeds;

Var
  Now                   : Cardinal;
  Duration              : Cardinal;

Begin
  Now             := GetTickCount;
  Duration        := Now-fTimeLastUpdate;
  fTimeLastUpdate := Now;
  If Duration=0 Then Duration := 1;
  fSpeedFlow.Read  := MulDiv(fDataRead-fDataReadLast,8000,Duration);
  fSpeedFlow.Write := MulDiv(fDataWrite-fDataWriteList,8000,Duration);
  fDataReadLast    := fDataRead;
  fDataWriteList   := fDataWrite;
End;

Procedure TDDUThrottle.CalculateSpeeds;

Begin
  CalculateFlowSpeeds;
  CalculateAvgSpeeds;
  If Assigned(fOnThrottle) Then
  Begin
    fOnThrottle(Self);
  End;
  CheckTimeouts;
End;

Function TDDUThrottle.CanRead(aSocket : TSocket) : Boolean;

Begin
  CalculateAvgSpeeds;
  Result := True;
  If (fSockets.IndexOf(Pointer(aSocket))<>-1) and (Active And Enabled) And
     (SpeedLimit.Read<>0) And
     ((SpeedLimit.UseFlowRate And (SpeedFlow.Read>=SpeedLimit.Read)) Or
     (SpeedAvg.Read>=SpeedLimit.Read)) Then
  Begin
    Result := False;
    ThrottleReadOff;
  End;
End;

Function TDDUThrottle.CanWrite(aSocket : TSocket) : Boolean;

Begin
  CalculateAvgSpeeds;
  Result := True;
  If (fSockets.IndexOf(Pointer(aSocket))<>-1) and (Active And Enabled) And
     (SpeedLimit.Write<>0) And
     ((SpeedLimit.UseFlowRate And (SpeedFlow.Write>=SpeedLimit.Write)) Or
     (SpeedAvg.Write>=SpeedLimit.Write)) Then
  Begin
    Result := False;
    ThrottleWriteOff;
  End;
End;

procedure TDDUThrottle.CheckTimeouts;

Var
  Causes                : TTimeoutCauses;
  Now                   : Cardinal;

begin
  Now := GetTickCount;
  Causes := [];
  If (fTimeout.Both<>0) And ((Now-(fTimeout.fLastBoth))>=fTimeout.Both) Then
  Begin
    Include(Causes,toBoth);
  End;
  If (fTimeout.Read<>0) And ((Now-(fTimeout.fLastRead))>=fTimeout.Read) Then
  Begin
    Include(Causes,toRead);
  End;
  If (fTimeout.Write<>0) And ((Now-(fTimeout.fLastWrite))>=fTimeout.Write) Then
  Begin
    Include(Causes,toWrite);
  End;
  If (Causes<>[]) Then
  Begin
    DoTimeout(Causes);
  End;
end;

Procedure TDDUThrottle.Clear;

Begin
  fDataRead        := 0;
  fDataReadLast    := 0;
  fDataWrite       := 0;
  fDataWriteList   := 0;
  fSpeedAvg.Read   := 0;
  fSpeedAvg.Write  := 0;
  fSpeedFlow.Read  := 0;
  fSpeedFlow.Write := 0;
  
  fTimeLastUpdate   := GetTickCount;
  fTimeStart        := fTimeLastUpdate;

  fTimeout.fLastBoth  := GetTickCount;
  fTimeout.fLastRead  := fTimeout.fLastBoth;
  fTimeout.fLastWrite := fTimeout.fLastBoth;
End;

procedure TDDUThrottle.DoTimeout(Causes : TTimeoutCauses);

begin
  fTimeout.fLastBoth  := GetTickCount;
  fTimeout.fLastRead  := fTImeout.fLastBoth;
  fTimeout.fLastWrite := fTImeout.fLastBoth;
  If Assigned(fOnTimeout) Then
  Begin
    fOnTimeout(Self,Causes);
  End;
end;

Procedure TDDUThrottle.RegisterDataRead(Size : Cardinal);

Begin
  fDataRead           := fDataRead+Size;
  fTimeout.fLastBoth  := GetTickCount;
  fTimeout.fLastRead  := fTImeout.fLastBoth;

  If Assigned(MasterThrottle) Then
  Begin
    MasterThrottle.RegisterDataRead(Size);
  End;
End;

Procedure TDDUThrottle.RegisterDataWrite(Size : Cardinal);

Begin
  fDataWrite          := fDataWrite+Size;    
  fTimeout.fLastBoth  := GetTickCount;       
  fTimeout.fLastWrite := fTImeout.fLastBoth; 
  If Assigned(MasterThrottle) Then
  Begin
    MasterThrottle.RegisterDataWrite(Size);
  End;
End;

Procedure TDDUThrottle.RemoveSocket(aSocket : TSocket);

Var
  At                    : Integer;

Begin
  If (aSocket<>INVALID_SOCKET) Then
  Begin
    At := fSockets.IndexOf(Pointer(aSocket));
    If (At<>-1) Then
    Begin
      fSockets.Delete(At);
      fWindows.Delete(At);
    End;
  End;
End;

Procedure TDDUThrottle.SetActive(Const NewValue : Boolean);

Begin
  If (NewValue<>fActive) Then
  Begin
    fActive := NewValue;
    UpdateTimer;
  End;
End;

Procedure TDDUThrottle.SetEnabled(Const NewValue : Boolean);

Begin
  If (NewValue<>fEnabled) Then
  Begin
    fEnabled := NewValue;
    UpdateTimer;
  End;
End;

Procedure TDDUThrottle.SetInterval(Const NewValue : Integer);

Begin
  If (NewValue<0) Then
  Begin
    Raise Exception.Create('Timer intervals must be 0 or higher.');
  End;
  If (fInterval<>NewValue) Then
  Begin
    fInterval := NewValue;
    UpdateTimer;
  End;
End;

Procedure TDDUThrottle.ThrottleReadOff;

Begin
  KillTimer(fTimerWnd,ReadID);
  SetTimer(fTimerWnd,ReadID,10,Nil);
  If Assigned(fOnThrottleReadOff) Then
  Begin
    fOnThrottleReadOff(Self);
  End;
End;

Procedure TDDUThrottle.ThrottleReadOn;

Var
  Loop                  : Integer;
  Socket                : TSocket;
  Wnd                   : HWnd;

Begin
  For Loop := 0 To fSockets.Count-1 Do
  Begin
    Socket := TSocket(fSockets[Loop]);
    Wnd := HWnd(fWindows[Loop]);
    PostMessage(Wnd,cm_SocketMessage,Socket,fd_Read);
  End;

  If Assigned(fOnThrottleReadOn) Then
  Begin
    fOnThrottleReadOn(Self);
  End;
End;

Procedure TDDUThrottle.ThrottleWriteOff;

Begin
  KillTimer(fTimerWnd,WriteID);
  SetTimer(fTimerWnd,WriteID,10,Nil);
  If Assigned(fOnThrottleWriteOff) Then
  Begin
    fOnThrottleWriteOff(Self);
  End;
End;

Procedure TDDUThrottle.ThrottleWriteOn;

Var
  Loop                  : Integer;
  Socket                : TSocket;
  Wnd                   : HWnd;

Begin
  For Loop := 0 To fSockets.Count-1 Do
  Begin
    Socket := TSocket(fSockets[Loop]);
    Wnd := HWnd(fWindows[Loop]);
    PostMessage(Wnd,cm_SocketMessage,Socket,fd_write);
  End;

  If Assigned(fOnThrottleWriteOn) Then
  Begin
    fOnThrottleWriteOn(Self);
  End;
End;

Procedure TDDUThrottle.UpdateTimer;

Var
  NeedTimer             : Boolean;

Begin
  NeedTimer := (fInterval>0) And Active And Enabled;

  If NeedTimer And (fTimerWnd=0) Then
  Begin
{$IF defined(DSI)}
    fTimerWnd := DSiAllocateHWnd(WndProc);
{$ELSE}
    fTimerWnd := AllocateHWnd(WndProc);
{$ENDIF}

  End;
  
  If (fTimerWnd<>0) Then
  Begin
    KillTimer(fTimerWnd,TimerID);
  End;
  
  If (Not NeedTimer) And (fTimerWnd<>0) Then
  Begin
{$IF defined(DSI)}
    DSiDeallocateHWnd(fTimerWnd);
{$ELSE}
    DeallocateHWnd(fTimerWnd);
{$ENDIF}
    fTimerWnd := 0;
  End;

  If NeedTimer Then
  Begin
    SetTimer(fTimerWnd,TimerID,fInterval,Nil);
  End;
End;

Procedure TDDUThrottle.WndProc(Var Msg : TMessage);

Begin
  If (Msg.Msg=WM_TImer) Then
  Begin
    Case Msg.WPARAM Of
      TimerID  : Begin
                   CalculateSpeeds;
                 End;
      ReadID   : Begin
                   KillTimer(fTimerWnd,ReadID);
                   ThrottleReadOn;
                 End;
      WriteID  : Begin
                   KillTimer(fTimerWnd,WriteID);
                   ThrottleWriteOn;
                 End;
    End;
    Msg.Result := 0;
  End
  Else
  Begin
    Msg.Result := DefWindowProc(fTimerWnd,Msg.Msg,Msg.WParam,Msg.LParam);
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


procedure TDDUThrottle.Assign(Source: TPersistent);
begin
  If (Source Is TDDUThrottle) Then
  Begin
    fDataRead  := TDDUThrottle(Source).fDataRead;
    fDataWrite :=  TDDUThrottle(Source).fDataWrite;
    fSpeedAvg.Assign(TDDUThrottle(Source).fSpeedAvg);
    fSpeedAvg.Assign(TDDUThrottle(Source).fSpeedFlow);
    fSpeedLimit.Assign(TDDUThrottle(Source).fSpeedLimit);
    fTimeout.Assign(TDDUThrottle(Source).fTimeout);
  End
  Else
  Begin
    inherited;
  End;
end;

{ TDDUTimeout }

procedure TDDUTimeout.Assign(Source: TPersistent);
begin
  If Source Is TDDUTimeout Then
  Begin
    fBoth      := TDDUTimeout(Source).fBoth;
    fRead      := TDDUTimeout(Source).fRead;
    fWrite     := TDDUTimeout(Source).fWrite;
    fLastWrite := TDDUTimeout(Source).fLastWrite;
    fLastRead  := TDDUTimeout(Source).fLastRead;
    fLastBoth  := TDDUTimeout(Source).fLastBoth;
  End
  Else
  Begin
    inherited;
  End;
end;

{ TDDUCount }

procedure TDDUCount.Assign(Source: TPersistent);
begin
  If Source Is TDDUCOunt Then
  Begin
    fRead := TDDUCount(Source).fRead;
    fWrite := TDDUCount(Source).fWrite;
  End
  Else
  Begin
    inherited;
  End;
end;

{ TDDUSocketUser }

procedure TDDUSocketUser.Assign(Source: TPersistent);
begin
  If SOurce Is TDDUSocketUser Then
  Begin
    fPassword := TDDUSocketUser(Source).fPassword;
    fUserName := TDDUSocketUser(Source).fUserName;
  End
  Else
  Begin
    inherited;
  End;

end;

Initialization
  Startup;
Finalization
  Cleanup;
end.

unit DDU.Inet.DNS;

//*****************************************************************************
//
// DDUINET (DDU.Inet.DNS)
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
// Future plans
//             - WinSock2, IP6 support
//*****************************************************************************

interface

{$I DVer.inc}

{$UNDEF DSI}

uses
  WinAPI.Windows,
  WinAPI.Messages,
  WinAPI.WinSock,
  System.SysUtils,
  System.Classes
//  VCL.Forms
  {$IF defined(DSI)}, DSiWin32 {$ENDIF};

{$I DTypes.inc}

Const
  um_GotAddress         = wm_User+$1001; // Host name has been resolved to an address.
  um_GotHost            = wm_User+$1002; // Host Address has been resolved to a name.

Type
  TResolveAction = (raNone,raGetAddress,raGetHostName);

Type
  TExceptionEvent = Procedure(Sender : TObject; E: Exception) Of Object;

  TDDUCustomDNS = class(TComponent)
  private
    { Private declarations }
//*****************************************************************************
//
//*****************************************************************************
    fASyncHandle                : Integer;
    fBuffer                     : Pointer;
    fOK                         : Boolean;
    fResolveAction              : TResolveAction;
    fSocketWindow               : HWND;
    fUseTimer                   : Boolean;
    fNeedTimer                  : Boolean;
//*****************************************************************************
//
//*****************************************************************************
    fAddress                    : TINAddr;
    fHost                       : String;
    fTimeOut                    : Integer;
    fTimeoutEnabled             : Boolean;
//*****************************************************************************
//
//*****************************************************************************
    fOnFoundAddress             : TNotifyEvent;
    fOnFoundAddress2            : TNotifyEvent; // Used for internal linkages.
    fOnCancel                   : TNotifyEvent;
    fOnCancel2                  : TNotifyEvent; // Used for internal linkages.
    fOnFoundHost                : TNotifyEvent;
    fOnFoundHost2               : TNotifyEvent; // Used for Internal linkages.
    fOnTimeout                  : TNotifyEvent;
//*****************************************************************************
// When other controls use this, we want only one to be able to use it at a
// time.
//*****************************************************************************
    fLinkedTo                   : TComponent;
//*****************************************************************************
//
//*****************************************************************************
    fUseIPCache         : Boolean;
//*****************************************************************************
//
//*****************************************************************************
    Function  GetAddress : String;
    Procedure SetAddress(Const NewValue : String);
    Procedure SetHost(Const NewValue : String);
    Procedure SetLinkedTo(Const NewValue : TComponent);
    Procedure SetTimeout(Const NewValue : Integer);
    Procedure SetTimeoutEnabled(Const NewValue : Boolean);
    Procedure UpdateTimer;
  Private
    fBlocking: Boolean;
    fOnException: TExceptionEvent;
    Procedure WndProc(Var Msg : TMessage);
    procedure SetBlocking(const Value: Boolean);
  protected
    { Protected declarations }
    Procedure DoFoundAddress; Virtual;
    Procedure DoFoundHost; Virtual;
    Procedure DoTimeout; Virtual;
    Procedure Notification(AComponent: TComponent; Operation: TOperation); Override;
    Procedure ResolveAddress; Virtual;
    Procedure ResolveHost; Virtual;
  public
    { Public declarations }
    Constructor Create(AOwner : TComponent); Override;
    Destructor Destroy; Override;
    procedure Cancel; Virtual;
    Procedure CopyIPCache(S : TStrings);
    Procedure FlushIPCache; Virtual;
  Public
    Property Action              : TResolveAction Read fResolveAction;
    Property Address             : String         Read GetAddress           Write SetAddress Stored False;
    Property Blocking            : Boolean        Read fBlocking            Write SetBlocking Default False;
    Property Host                : String         Read fHost                Write SetHost Stored False;
    Property LinkedTo            : TComponent     Read fLinkedTo            Write SetLinkedTo;
    Property OK                  : Boolean        Read fOK;
    Property TimeOut             : Integer        Read fTimeout             Write SetTimeout Default 0;
    Property TimeOutEnabled      : Boolean        Read fTimeoutEnabled      Write SetTimeoutEnabled Default False;
    Property UseIPCache          : Boolean         Read fUseIPCache  Write fUseIPCache Default False;
    Property OnCancel            : TNotifyEvent   Read fOnCancel            Write fOnCancel;
    Property OnCancel2           : TNotifyEvent   Read fOnCancel2           Write fOnCancel2;
    Property OnFoundAddress      : TNotifyEvent   Read fOnFoundAddress      Write fOnFoundAddress;
    Property OnFoundAddress2     : TNotifyEvent   Read fOnFoundAddress2     Write fOnFoundAddress2;
    Property OnFoundHost         : TNotifyEvent   Read fOnFoundHost         Write fOnFoundHost;
    Property OnFoundHost2        : TNotifyEvent   Read fOnFoundHost2        Write fOnFoundHost2;
    Property OnTimeout           : TNotifyEvent   Read fOnTimeout           Write fOnTimeout;
    Property OnException         : TExceptionEvent Read fOnException        Write fOnException;
  end;

Type
  TDDUDNS = Class(TDDUCustomDNS)
  Published
    Property Address;
    Property Blocking;
    Property Host;
    Property Timeout;
    Property TimeoutEnabled;
    Property UseIPCache;
    Property OnCancel;
    Property OnFoundAddress;
    Property OnFoundHost;
    Property OnTimeout;
  End;

implementation

Const
  TimerID               = $1234;

var
  WSAData: TWSAData;
  IPCache               : TStringList;  // Saves IP address, keyed on Host name.
  HostCache             : TStringList;  // Saves Host names, keyed on IP address.

procedure Startup;

begin
  WSAStartup($0101, WSAData);
end;

procedure Cleanup;
begin
  WSACleanup;
end;

Constructor TDDUCustomDNS.Create(AOwner : TComponent);

Begin
  Inherited Create(AOwner);
  Startup;

  GetMem(fBuffer,MAXGETHOSTSTRUCT);
  fResolveAction := raNone;
{$IF defined(DSI)}
  fSocketWindow := DSiAllocateHWnd(WndProc);
{$ELSE}
  fSocketWindow := AllocateHWnd(WndProc);
{$ENDIF}
  fAddress.S_addr := u_Long(INADDR_NONE);
End;

procedure TDDUCustomDNS.Cancel;

Begin
  Fillchar(fBuffer^,MAXGETHOSTSTRUCT,#0);
  fOK := False;
  fNeedTimer := False;
  UpdateTimer;

  If (Action<>raNone) Then
  Begin
    WSACancelAsyncRequest(fASyncHandle);
    fResolveAction := raNone;
    If Assigned(fOnCancel) And (Not (csDestroying In ComponentState)) Then
    Begin
      fOnCancel(Self);
    End;
    If Assigned(fOnCancel2) And (Not (csDestroying In ComponentState)) Then
    Begin
      fOnCancel2(Self);
    End;
  End;
End;

Procedure TDDUCustomDNS.CopyIPCache(S : TStrings);

Begin
  S.Clear;
  IPCache.Sort;
  HostCache.Sort;
  S.AddStrings(IPCache);
  S.AddStrings(HostCache);
End;

Procedure TDDUCustomDNS.FlushIPCache;

Begin
  IPCache.Clear;
  HostCache.Clear;
End;

Destructor TDDUCustomDNS.Destroy;

Begin
  Cancel;
{$IF defined(DSI)}
  DSiDeallocateHWnd(fSocketWindow);
{$ELSE}
  DeallocateHWnd(fSocketWindow);
{$ENDIF}
  FreeMem(fBuffer,MAXGETHOSTSTRUCT);
  Cleanup;
  Inherited Destroy;
End;

Procedure TDDUCustomDNS.DoFoundAddress;

Begin
  If Ok And UseIPCache Then
  Begin
    IPCache.Values[Host] := Address;
    HostCache.Values[Address] := Host;
    IPCache.Sort;
    HostCache.Sort;
  End;
  fResolveAction := raNone;
  If Assigned(fOnFoundAddress2) Then
  Begin
    Try
      fOnFoundAddress2(Self);
    Except
    End;
  End;
  If Assigned(fOnFoundAddress) Then
  Begin
    Try
      fOnFoundAddress(Self);
    Except
    End;
  End;
End;

Procedure TDDUCustomDNS.DoFoundHost;

Begin
  If Ok And UseIPCache Then
  Begin
    IPCache.Values[Host] := Address;
    HostCache.Values[Address] := Host;
    IPCache.Sort;
    HostCache.Sort;
  End;
  fResolveAction := raNone;
  If Assigned(fOnFoundHost2) Then
  Begin
    Try
      fOnFoundHost2(Self);
    Except
    End;
  End;
  If Assigned(fOnFoundHost) Then
  Begin
    Try
      fOnFoundHost(Self);
    Except
    End;
  End;
End;

Procedure TDDUCustomDNS.DoTimeout;

Begin
  If Assigned(fOnTimeout) Then
  Begin
    fOnTimeout(Self);
  End;
End;

Function TDDUCustomDNS.GetAddress : String;

Begin
  If (u_Long(fAddress.S_addr)=u_Long(INADDR_NONE)) Then
  Begin
    Result := '';
  End
  Else
  Begin
    Result := String(Inet_NtoA(fAddress));
  End;
End;

Procedure TDDUCustomDNS.Notification(AComponent: TComponent; Operation: TOperation);

Begin
  Inherited Notification(AComponent,Operation);
  If (Operation=opRemove) And (AComponent=fLinkedTo) Then
  Begin
    fLinkedTo := Nil;
  End;
End;

Procedure TDDUCustomDNS.ResolveAddress;

Var                     
  HostEnt                 : PHostEnt; 

Begin
  Cancel;
  fResolveAction := raGetHostName;
  fHost := '';
  If UseIPCache And (HostCache.Values[Address]<>'') Then// In the cache
  Begin
    fHost := HostCache.Values[Address];
    fOK := True;
    DoFoundHost;
  End Else If (u_Long(fAddress.S_addr)=u_Long(INADDR_NONE)) Then // Not a valid IP.
  Begin
    fOk := False;
    DoFoundHost;
  End Else If Blocking Then
  Begin
    HostEnt := gethostbyaddr(@fAddress,4,PF_INET);
    If Assigned(HostEnt) Then
    Begin
      fOK := True;
      fHost := String(HostEnt^.h_name);
    End;
    DoFoundHost;
  End Else // Look it up.
  Begin
    fNeedTimer := True;
    UpdateTimer;
    fASyncHandle := WSAAsyncGetHostByAddr(fSocketWindow,um_GotHost,@fAddress,4,PF_INET,fBuffer,MAXGETHOSTSTRUCT);
  End;
End;

Procedure TDDUCustomDNS.ResolveHost;

Var
  HostEnt                 : PHostEnt;
  at                      : Pointer;
  ansiHost                : AnsiString;

Begin
  Cancel;
  fResolveAction := raGetHostName;
  if (fHost<>'') Then
  Begin
    ansiHost := fHost.Trim;
    fAddress.S_addr := INet_Addr(PAnsiChar(ansiHost));
  End;

  If UseIPCache And (IPCache.Values[Host]<>'') Then  // In the cache.
  Begin
    ansiHost        := IPCache.Values[Host];
    fAddress.S_addr := INet_Addr(PAnsiChar(ansiHost) );
    fOk := True;
    DoFoundAddress;
  End Else if (fHost='') Then  // Blank
  Begin
    fAddress.S_addr := u_Long(INADDR_NONE);
    fOk := False;
    DoFoundAddress;
  End Else If (u_Long(fAddress.S_addr)<>u_Long(INADDR_NONE)) Then // And IP
  Begin
    fOk := True;
    DoFoundAddress;
  End Else If Blocking Then
  Begin
    ansiHost := Host.Trim;
    HostEnt := gethostbyname(PAnsiChar(ansiHost));
    If Assigned(HostEnt) Then
    Begin
      fOk := True;
      At := HostEnt^.h_Addr^;
      fAddress.S_addr := LongInt(At^);
    End;
    DoFoundAddress;
  End Else  // Look it up.
  Begin
    fNeedTimer := True;
    UpdateTimer;
    ansiHost := Host.Trim;
    fASyncHandle := WSAAsyncGetHostByName(fSocketWindow,um_GotAddress,PAnsiChar(ansiHost),fBuffer,MAXGETHOSTSTRUCT);
  End;
End;

Procedure TDDUCustomDNS.SetAddress(Const NewValue : String);

Var
  IP                    : TINAddr;
  ansiNewValue          : AnsiString;

Begin
  If (NewValue='') Then
  Begin
    fAddress.S_addr := u_Long(INADDR_NONE);
    fHost := '';
  End
  Else
  Begin
    ansiNewValue := Trim(NewValue);
    IP.S_Addr := Inet_Addr(PAnsiChar(ansiNewValue));
    If (String(Inet_NtoA(IP))=Trim(NewValue)) Then
    Begin
      fAddress:= IP;
      ResolveAddress;
    End;
  End;
End;

procedure TDDUCustomDNS.SetBlocking(const Value: Boolean);
begin
  fBlocking := Value;
end;

Procedure TDDUCustomDNS.SetHost(Const NewValue : String);

Begin
  fHost := NewValue;
  ResolveHost;
End;

Procedure TDDUCustomDNS.SetLinkedTo(Const NewValue : TComponent);

Begin
  If Assigned(fLinkedTo) And (NewValue<>Nil) Then
  Begin
    Raise Exception.Create('DNS Control '+Name+' Already linked to '+fLinkedTo.Name);
  End;
  fLinkedTo := NewValue;
  If Assigned(fLinkedTo) Then
  Begin
    fLinkedTo.FreeNotification(Self);
  End;
End;

Procedure TDDUCustomDNS.SetTimeout(Const NewValue : Integer);

Begin
  If (NewValue<0) Then
  Begin
    Raise Exception.Create('Timeout must be a positive value.');
  End;
  fTimeout := NewValue;
  UpdateTimer;
End;

Procedure TDDUCustomDNS.SetTimeoutEnabled(Const NewValue : Boolean);

Begin
  fTimeoutEnabled := NewValue;
  UpdateTimer;
End;

Procedure TDDUCustomDNS.UpdateTimer;

Begin
  If fUseTimer Then
  Begin
    KillTimer(fSocketWindow,TimerID);
  End;
  fUseTimer := fNeedTimer And (Not (csDesigning in ComponentState)) And TimeoutEnabled And
               (fTimeout>0);
  If fUseTimer Then
  Begin
    SetTimer(fSocketWindow,TimerID,fTimeOut,Nil);
  End;
End;

Procedure TDDUCustomDNS.WndProc(Var Msg : TMessage);

Var
  At                    : Pointer;

Begin
  Try
    Case Msg.Msg Of
      um_GotAddress  : Begin  // The host name has been resolved.  Load it and go.
                         fNeedTimer := False;
                         UpdateTimer;
                         If (WSAGetAsyncError(Msg.lParam)=0) Then
                         Begin
                           fOk := True;
                           At := PHostEnt(fBuffer)^.h_Addr^;
                           fAddress.S_addr := LongInt(At^);
                         End;
                         DoFoundAddress;
                       End;
      um_GotHost     : Begin  // The host address has been resolved, load it and go.
                         fNeedTimer := False;
                         UpdateTimer;
                         If (WSAGetAsyncError(Msg.lParam)=0) Then
                         Begin
                           fOK := True;
                           fHost := String(PHostEnt(fBuffer)^.h_name);
                         End;
                         DoFoundHost;
                       End;
      wm_Timer       : Begin
                         If (msg.WParam=TimerId) Then
                         Begin
                           DoTimeout;
                         End;
                       End;
    Else
      Msg.Result := DefWindowProc(fSocketWindow,Msg.Msg,Msg.WParam,Msg.LParam);
    End;
  Except
    On E:Exception Do
    Begin
      If Assigned(fOnException) then
      Begin
        fOnException(Self,E);
      End;
//      Application.HandleException(E);
    End;
  End;
End;


Initialization
  IPCache := TStringList.Create;
  HostCache := TStringList.Create;
Finalization
  FreeAndNil(IPCache);
  FreeAndNil(HostCache);
end.

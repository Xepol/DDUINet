unit DDU.Inet.Proxy;

//*****************************************************************************
//
// DDUINET (DDU.Inet.Proxy)
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
//
// Future plans
//             - WinSock2, IP6 support
//*****************************************************************************

interface

{$I DVer.inc}

uses
  WinAPI.Windows,
  WinAPI.Messages,
  System.Win.Registry,
  System.SysUtils,
  System.Classes;
  
{$I DTypes.inc}

Type
  TDDUCustomProxy = class(TComponent)
  private
    { Private declarations }
    fActive            : Boolean;
    fClientResolveIP   : Boolean;
    fExternalHost      : String;
    fHost              : String;
    fPort              : Integer;
    fPassword          : String;
    fSocksVersion      : Byte;
    fUseAuthentication : Boolean;
    fUseSocks          : Boolean;
    fUserName          : String;
    Function GetClientResolveIP : Boolean;
    Function GetText : String;
    Procedure SetHost(Const NewValue : String);
    Procedure SetSocksVersion(Const NewValue : Byte);
    Procedure SetUseSocks(Const NewValue : Boolean);
  protected
    { Protected declarations }
  public
    { Public declarations }
    Constructor Create(AnOwner : TComponent); Override;
  public
    { Public declarations }
    Property Active            : Boolean Read fActive            Write fActive            Default True;
    Property ClientResolveIP   : Boolean Read GetClientResolveIP Write fClientResolveIP   Default True;
    Property ExternalHost      : String  Read fExternalHost      Write fExternalHost;
    Property Host              : String  Read fHost              Write SetHost;
    Property Port              : Integer Read fPort              Write fPort;
    Property Password          : String  Read fPassword          Write fPassword;
    Property SocksVersion      : Byte    Read fSocksVersion      Write SetSocksVersion    Default 5;
    Property Text              : String  Read GetText            Write SetHost;
    Property UseAuthentication : Boolean Read fUseAuthentication Write fUseAuthentication Default False;
    Property UserName          : String  Read fUserName          Write fUserName;
    Property UseSocks          : Boolean Read fUseSocks          Write SetUseSocks        Stored False;
  end;

type
  TDDUCustomIEProxy  = class(TDDUCustomProxy)
  private
    { Private declarations }
    fProtocol : String;
    fValid    : Boolean;
    Procedure SetActive(Const NewValue : Boolean);
    Procedure SetHost(Const NewValue : String);
    Procedure SetPort(Const NewValue : Integer);
    Procedure SetProtocol(Const NewValue : String);
    Procedure SetValid(Const NewValue : Boolean);
    function GetActive: Boolean;
    function GetHost: String;
    function GetPort: Integer;
  protected
    { Protected declarations }
  public
    { Public declarations }
    Constructor Create(AnOwner : TComponent); Override;
    Property Active   : Boolean Read GetActive   Write SetActive   Stored False;
    Property Host     : String  Read GetHost     Write SetHost     Stored False;
    Property Port     : Integer Read GetPort     Write SetPort     Stored False;
    Property Protocol : String  Read fProtocol   Write SetProtocol Stored False;
    Property Valid    : Boolean read fValid      Write SetValid    Stored False;
  end;

Type
  TDDUProxy = class(TDDUCustomProxy)
  published
    { Published declarations }
    Property Active;
    Property Host;
    Property Port;
    Property Password;
    Property UseAuthentication;
    Property UserName;
  end;

type
  TDDUIEHTTPProxy = class(TDDUCustomIEProxy )
  public
    { Public declarations }
    Constructor Create(AnOwner : TComponent); Override;
  published
    { Published declarations }
    Property Active;
    Property Host;
    Property Port;
    Property Password;
    Property SocksVersion;
    Property Valid;
    Property UseAuthentication;
    Property UserName;
    Property UseSocks;
  end;

Type
  TDDUSocksProxy = class(TDDUCustomProxy)
  Public
    Constructor Create(AnOwner : TComponent); Override;
  published
    { Published declarations }
    Property Active;
    Property ClientResolveIP;
    Property ExternalHost;   
    Property Host;
    Property SocksVersion;
    Property Port;
    Property Password;
    Property UseAuthentication;
    Property UserName;
  end;

implementation

Procedure BreakApart(Source : String; Delim : String; Dest : TStringList);

Var
  At : Integer;

Begin
  Dest.Clear;
  At := Pos(Delim,Source);
  While(At<>0) Do
  Begin
    Delete(Source,At,Length(Delim));
    Insert(#13#10,Source,At);
    At := Pos(Delim,Source);
  End;
  Dest.Text := AdjustLineBreaks(Source);
End;

Constructor TDDUCustomProxy.Create(AnOwner : TComponent);

Begin
  Inherited Create(AnOwner);
  fClientResolveIP := True;
  fActive := True;
  fSocksVersion := 5;
End;

Function TDDUCustomProxy.GetClientResolveIP : Boolean;

Begin
  Result := fClientResolveIP;
  If fUseSocks And (fSocksVersion=4) Then Result := True;
End;

Function TDDUCustomProxy.GetText : String;

Begin
  If (Host='') Then
  Begin
    Result := '';
  End
  Else
  Begin
    Result := Host+':'+IntToStr(Port);
  End;
End;
Procedure TDDUCustomProxy.SetHost(Const NewValue : String);

Var
  At                    : Integer;
  Work                  : String;

Begin
  Work := NewValue;
  At := Pos(':',Work);
  If (At<>0) Then
  Begin
    Work := NewValue;
    Delete(Work,1,At);
    Port := StrToIntDef(Trim(Work),Port);
    Work := Trim(Copy(NewValue,1,At-1));
  End;
  fHost := Work;
End;

Procedure TDDUCustomProxy.SetSocksVersion(Const NewValue : Byte);

Begin
  If Not (NewValue In [4,5]) Then
  Begin
    Raise Exception.Create('Unknown Socks Version '+IntTostr(NewValue));
  End;
  fSocksVersion := NewValue;
End;

Procedure TDDUCustomProxy.SetUseSocks(Const NewValue : Boolean);

Begin
End;

Constructor TDDUCustomIEProxy.Create(AnOwner : TComponent);

Var
  RegFile               : TRegINIfile;
  Reg                   : TRegistry;
  Proxy                 : String;
  SocksProxy            : String;
  ProxyEnabled          : Integer;
  S                     : TStringList;

Begin
  Inherited Create(AnOwner);
//*****************************************************************************
// Loads IE proxy settings from the registry if they are there.
//*****************************************************************************

  RegFile := TRegINIFile.Create('\Software\Microsoft\Windows\CurrentVersion');
  Try
    Proxy := RegFile.ReadString('Internet Settings','ProxyServer','');
  Finally
    FreeAndNil(RegFile);
  End;
  ProxyEnabled := 0;
  Reg := TRegistry.Create;
  Reg.RootKey := HKEY_CURRENT_USER;
  Try
    If Reg.OpenKey('\Software\Microsoft\Windows\CurrentVersion\Internet Settings',False) Then
    Begin
      Try
        ProxyEnabled := Reg.ReadInteger('ProxyEnable');
        fValid := True;
      Except
        fValid := False;
      End;
      Reg.CloseKey;
    End;
  Finally
    FreeAndNil(Reg);
  End;

  fActive := (ProxyEnabled<>0);

  If (Pos(';',Proxy)<>0) Or (Pos('=',Proxy)<>0) Then
  Begin
    S := TStringList.Create;
    Try
      BreakApart(Proxy,';',S);
      Proxy      := S.Values[fProtocol];
      SocksProxy := S.Values['socks'];
    Finally
      S.Clear;
    End;
    fValid := (Trim(Proxy)<>'') And (Trim(SocksProxy)<>'');
  End;

  Proxy := Trim(Proxy);
  SocksProxy := Trim(SocksProxy);

  If (SocksProxy<>'') Then
  Begin
    Inherited Host := SocksProxy;
    fUseSocks := True;
  End
  Else If (Proxy<>'') Then
  Begin
    Inherited Host := Proxy;
    fUseSocks := (Port=1080);
  End;
  fValid := fValid And (fHost<>'');
End;

function TDDUCustomIEProxy.GetActive: Boolean;
begin
  Result := Inherited Active;
end;

function TDDUCustomIEProxy.GetHost: String;
begin
  REsult := Inherited Host;
end;

function TDDUCustomIEProxy.GetPort: Integer;
begin
  Result := Inherited Port;
end;

Procedure TDDUCustomIEProxy.SetActive(Const NewValue : Boolean);

Begin
End;

Procedure TDDUCustomIEProxy.SetHost(Const NewValue : String);

Begin
End;

Procedure TDDUCustomIEProxy.SetPort(Const NewValue : Integer);

Begin
End;

Procedure TDDUCustomIEProxy.SetProtocol(Const NewValue : String);

Begin
End;

Procedure TDDUCustomIEProxy.SetValid(Const NewValue : Boolean);

Begin
End;

Constructor TDDUIEHTTPProxy.Create(AnOwner : TComponent);

Begin
  Inherited Create(AnOwner);
  fProtocol := 'http';
End;

Constructor TDDUSocksProxy.Create(AnOwner : TComponent);

Begin
  Inherited Create(AnOwner);
  Port := 1080;
  fUseSocks := True;
End;


end.

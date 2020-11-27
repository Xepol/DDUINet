unit DDU.Inet.IPList;

//*********************************************************************************************************************
//
// DDUINET (DDU.Inet.IPList)
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
// Purpose : Get a list of local IP addresses.
//
// History : <none>
//
//*********************************************************************************************************************

interface

Uses
  WinAPI.WinSock,
  System.SysUtils,
  System.Classes,
  DDU.Inet.Socket.Types;

Type
  TDDUIPList=Class(TComponent)
  Private
    fAddresses : TStringList;
    function GetAddresses: TStrings;
    procedure SetAddresses(const Value: TStrings);
  Protected
    Procedure Refresh;
  Public
    Constructor Create(Owner : TComponent); Override;
    Destructor Destroy; Override;
  Published
    Property Addresses : TStrings Read GetAddresses Write SetAddresses;
  End;

implementation

{ TDDUIPList }

constructor TDDUIPList.Create(Owner: TComponent);
begin
  Inherited Create(Owner);
  fAddresses := TStringList.Create;
end;

destructor TDDUIPList.Destroy;
begin
  FreeAndNil(fAddresses);
  inherited;
end;

function TDDUIPList.GetAddresses: TStrings;
begin
  Refresh;
  Result := fAddresses;
end;

procedure TDDUIPList.Refresh;

Var
  HostEnt                 : PDDUHostEnt;
  Loop                    : Integer;
  Addr                    : PInAddr;
  ansiHost                : AnsiString;

Begin
  SetLength(ansiHost,255);
  FillChar(ansiHost[1],Length(ansiHost),#0);
  GetHostName(PAnsiChar(ansiHost),Length(ansiHost));
  ansiHost := PAnsiChar(ansiHost);

  fAddresses.Clear;
  HostEnt := PDDUHostEnt(gethostbyname(PAnsiChar(ansiHost)));
  If HostEnt<>nil Then
  Begin
    Loop := 0;
    Repeat
      Addr := HostEnt^.h_addr_list^[Loop];
      If Assigned(Addr) Then
      Begin
        fAddresses.Add( Inet_NtoA(Addr^) );
      End
      Else
      Begin
        Break;
      End;
      Inc(Loop);
    Until False;
  End;
  IF fAddresses.IndexOf('127.0.0.1')=-1 Then
  Begin
    fAddresses.Add('127.0.0.1');
  End;
End;

procedure TDDUIPList.SetAddresses(const Value: TStrings);
begin

end;

end.

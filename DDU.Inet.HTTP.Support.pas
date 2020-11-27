unit DDU.Inet.HTTP.Support;

//*********************************************************************************************************************
//
// DDUINET (DDU.Inet.HTTP.Support)
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
// Purpose : Reduced functionality from the HTTPAPP unit.
//
// History : <none>
//
// ExtractHeaderFields (C) CodeGear
//
// Code striped from the HTTPAPP unit.  We do not need to want the full burden of code stored therein.
//
//
// Future plans
//             - WinSock2, IP6 support
//*********************************************************************************************************************

interface

{$I DVer.inc}

uses
  WinAPI.Windows,
  System.SysUtils,
  System.Classes,
  System.AnsiStrings;

{$I DTypes.inc}

Const
  MAX_STRINGS   = 12;
  MAX_INTEGERS  = 1;
  MAX_DATETIMES = 3;

type
  TCharSet = set of Char;
  TMethodType = (mtAny, mtGet, mtPut, mtPost, mtHead);

function  DateStrToDateTimeGMT(DateStr: string): TDateTime;
Function  DateTimeGMTToDateStr(Const DateTimeGMT : TDateTime) : String;
function  DosPathToUnixPath(const Path: string): string;
procedure ExtractHeaderFields(Separators, WhiteSpace: TCharSet; Content: PChar; Strings: TStrings; Decode: Boolean);
procedure ExtractHTTPFields(Separators, WhiteSpace: TCharSet; Content: PChar; Strings: TStrings);
function  GMTToLocal(GMT : TDateTime) : TDateTime;
function  HTTPDecode(const AStr: String): string;
function  HTTPEncode(const AStr: String): string;
function  LocalToGMT(Local : TDateTime) : TDateTime;
Function  ParseHTTPReplyHeader(Source : String; Out HTTPLevel : Currency; Out ResultCode : Integer; Out Message : String) : Boolean;
Function  ParseHTTPRequestHeader(Source : String; Out Command,URL : String; Out HTTPLevel : Currency) : Boolean;

Function  PosR(Substr: string; S: string): Integer;
function  StatusString(StatusCode: Integer): string;
function  UnixPathToDosPath(const Path: string): string;

implementation

const
// These strings are NOT to be resourced
  Months: array[1..12] of string = (
    'Jan', 'Feb', 'Mar', 'Apr',
    'May', 'Jun', 'Jul', 'Aug',
    'Sep', 'Oct', 'Nov', 'Dec');
  Days : Array [1..7] of String = ('Sun','Mon','Tue','Wed','Thu','Fri','Sat');



function TranslateChar(const Str: string; FromChar, ToChar: Char): string;
var
  I: Integer;
begin
  Result := Str;
  for I := 1 to Length(Result) do
    if Result[I] = FromChar then
      Result[I] := ToChar;
end;

Function GetDateFrag(Var S : String; Breaker : String) : String;

Var
  At : Integer;

Begin
  At := Pos(Breaker,S);
  If (At=0) Then
  Begin
    Result := trim(S);
    S := '';
  End
  Else
  Begin
    Result := Trim(Copy(S,1,At-1));
    S := Trim(Copy(S,At+Length(Breaker),Length(S)- (At+Length(Breaker)-1) ));
  End;
End;

Function DateStrToDateTimeGMT(DateStr : String) : TDateTime;

Var
  Day                     : Integer;
  Month                   : String;
  Year                    : Integer;
  Hour                    : Integer;
  Min                     : Integer;
  Sec                     : Integer;
  S                       : TStringList;
  OK                      : Boolean;

Begin
  Result := 0;
  DateStr := Trim(DateStr);

  S := TStringList.Create;
  Try
    S.Add(GetDateFrag(DateStr,#32)); // 0=Day Word
    S.Add(GetDateFrag(DateStr,#32)); // 1=Day
    S.Add(GetDateFrag(DateStr,#32)); // 2=Month
    S.Add(GetDateFrag(DateStr,#32)); // 3=Year
    S.Add(GetDateFrag(DateStr,':')); // 4=hour
    S.Add(GetDateFrag(DateStr,':')); // 5=minutes
    S.Add(GetDateFrag(DateStr,#32)); // 6=seconds

    Ok := TryStrToInt(S[1],Day)  And
          TryStrToInt(S[3],Year) And
          TryStrToInt(S[4],Hour) And
          TryStrToInt(S[5],Min)  And
          TryStrToInt(S[6],Sec);
    Month := S[2];
  Finally
    FreeAndNil(S);
  End;

  If OK Then //sscanf(DateStr,'%*s %d %s %d %d:%d:%d',[@Day,@Month,@Year,@Hour,@Min,@Sec])=6 Then
  Begin
    S := TStringList.Create;
    Try
      S.CommaText := 'Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec';
      Try
        Result := EncodeDate(Year,S.IndexOf(Month)+1,Day)+EncodeTime(Hour,Min,Sec,0);
      Except
      End;
    Finally
      FreeAndNil(S);
    End;
  End;
End;

Function  DateTimeGMTToDateStr(Const DateTimeGMT : TDateTime) : String;

Var
  Year                    : Word;
  Month                   : Word;
  Day                     : Word;
  DOW                     : Word;
  Hour                    : Word;
  Min                     : Word;
  Sec                     : Word;
  MSec                    : Word;

Begin
  DecodeDateFully(DateTimeGMT,Year,Month,Day,DOW);
  DecodeTime(DateTimeGMT,Hour,Min,Sec,MSec);
  Result := Format('%s, %d %s %d %d:%.2d:%.2d',[Days[DOW],Day,Months[Month],Year,Hour,Min,Sec]);
End;

function DosPathToUnixPath(const Path: string): string;
begin
  Result := TranslateChar(Path, '\', '/');
end;

procedure ExtractHeaderFields(Separators, WhiteSpace: TCharSet; Content: PChar; Strings: TStrings; Decode: Boolean);

var
  EOS                     : Boolean;
  Head                    : PChar;
  InQuote                 : Boolean;
  QuoteChar               : Char;
  Tail                    : PChar;

begin
  if (Content = nil) or (Content^=#0) then Exit;
  Tail := Content;
  InQuote := False;
  QuoteChar := #0;
  Repeat
    while Tail^ in WhiteSpace + [#13, #10] do Inc(Tail);
    Head := Tail;
    while True do
    begin
      while (InQuote and not (Tail^ in ['''', '"'])) or
        not (Tail^ in Separators + [#0, #13, #10, '''', '"']) do Inc(Tail);
      if Tail^ in ['''', '"'] then
      begin
        if (QuoteChar <> #0) and (QuoteChar = Tail^) then
          QuoteChar := #0
        else
        begin
          QuoteChar := Tail^;
          Inc(Head);
        end;
        InQuote := QuoteChar <> #0;
        if InQuote then
          Inc(Tail)
        else Break;
      end else Break;
    end;
    EOS := Tail^ = #0;
    Tail^ := #0;
    if Head^ <> #0 then
      if Decode then
        Strings.Add(HTTPDecode(Head))
      else Strings.Add(Head);
    Inc(Tail);
  until EOS;
end;

procedure ExtractHTTPFields(Separators, WhiteSpace: TCharSet; Content: PChar; Strings: TStrings);
begin
  ExtractHeaderFields(Separators, WhiteSpace, Content, Strings, True);
end;

function GMTToLocal(GMT : TDateTime) : TDateTime;

Var
  FileDate              : Integer;
  GMTTime               : TFileTime;
  LocalTime             : TFileTime;

Begin
  FileDate := DateTimeToFileDate(GMT);
  DosDateTimeToFileTime(LongRec(FileDate).Hi, LongRec(FileDate).Lo, GMTTime);
  FileTimeToLocalFileTime(GMTTime,LocalTime);
  FileTimeToDosDateTime(LocalTime,LongRec(FileDate).Hi, LongRec(FileDate).Lo);
  Result := FileDateToDateTime(FileDate);
End;

function HTTPDecode(const AStr: String): String;

var
  Loop                    : Integer;
  Len                     : Integer;

begin
  SetLength(Result, Length(AStr));
  Len := 0;
  Loop := 1;
  While (Loop<=Length(AStr)) Do
  Begin
    If AStr[Loop]='+' Then
    Begin
      Result[Len+1] := #32;
      Inc(Len);
      Inc(Loop);
    End Else If AStr[Loop]='%' Then
    Begin
      If AStr[Loop+1]='%' Then
      Begin
        Result[Len+1] := '%';
        Inc(Len);
        Inc(Loop,2);
      End
      Else
      Begin
        Result[Len+1] := Chr( StrToInt('$'+Copy(aStr,Loop+1,2)) );
        Inc(Len);
        Inc(Loop,3);
      End;
    End Else
    Begin
      Result[Len+1] := AStr[Loop];
      Inc(Len);
      Inc(Loop);
    End;
  End;
  SetLength(Result, Len);
end;

function HTTPEncode(const AStr: String): String;

Const
  NoConversion = ['A'..'Z','a'..'z','*','@','.','_','-','0'..'9'];

var                     
  Len                     : Integer;
  Loop                    : Integer;

begin
  SetLength(Result, Length(AStr) * 3);

  Len := 0;
  Loop := 1;
  While (Loop<=Length(AStr)) Do
  Begin
    If AStr[Loop]=#32 Then
    Begin
      Result[Len+1] := '+';
      Inc(Len);
    End Else if AStr[Loop] in NoConversion then
    Begin
      Result[Len+1] := AStr[Loop];
      Inc(Len);
    End Else
    Begin
      System.AnsiStrings.FormatBuf(Result[Len+1], 3, '%%%.2x', 6, [Ord(AStr[Loop])]);
      Inc(Len,3);
    End;
    Inc(Loop);
  end;
  SetLength(Result, Len);
end;

function LocalToGMT(Local : TDateTime) : TDateTime;

Var
  FileDate              : Integer;
  GMTTime               : TFileTime;
  LocalTime             : TFileTime;

Begin
  FileDate := DateTimeToFileDate(Local);
  DosDateTimeToFileTime(LongRec(FileDate).Hi, LongRec(FileDate).Lo, LocalTime);
  LocalFileTimeToFileTime(LocalTime,GMTTime);
  FileTimeToDosDateTime(GMTTime,LongRec(FileDate).Hi, LongRec(FileDate).Lo);
  Result := FileDateToDateTime(FileDate);
End;

Function  ParseHTTPReplyHeader(Source : String; Out HTTPLevel : Currency; Out ResultCode : Integer; Out &Message : String) : Boolean;

Var
  At                      : Integer;
  aHTTP                   : String;
  aHTTPlevel              : Currency;
  aResultCode             : Integer;
  aMessage                : String;

Begin
  aHTTPLevel  := 0;
  aResultCode := 0;
  aMessage    := '';
  Result := False;
  Try
    At := Source.IndexOf(#32);
    If At<0 Then Exit;

    aHTTP      := Source.SubString(0,At).ToUpper;
    If Not aHTTP.StartsWith('HTTP/') Then Exit;
    aHTTPLevel := StrToCurrDef( aHTTP.Substring(5),0.0);
    If aHTTPLevel=0 Then Exit;

    Source := SOurce.SubString(At+1);

    At := Source.IndexOf(#32);
    If At<0 Then Exit;

    aResultCode := StrToIntDef(Source.Substring(0,At),0);
    aMessage    := Source.Substring(At+1).Trim;

    Result := aResultCode>0;
  Finally
    If Result Then
    Begin
      HTTPLevel  := aHTTPLevel;
      ResultCode := aResultCode;
      &Message   := aMessage;
    End
    Else
    Begin
      HTTPLevel  := 0;
      ResultCode := 0;
      &Message   := '';
    End;
  End;
End;

function ParseHTTPRequestHeader(Source: String; out Command, URL: String; Out HTTPLevel: Currency): Boolean;

Var
  At                      : Integer;
  aCommand                : String;
  aURL                    : String;
  aHTTPLEvel              : Currency;
  aHTTP                   : String;

begin
  aHTTPLevel := 0;
  Result     := False;
  Try
    At := Source.IndexOf(#32);
    If At<0  Then Exit;
    aCommand := Source.Substring(0,At).ToUpper;
    Source  := Source.Substring(At+1).Trim;

    At := Source.LastIndexOf(#32);
    If At=-1 Then Exit;

    aHTTP := Source.Substring(At+1);
    aURL  := Source.Substring(0,At).Trim;
    If aURL.IndexOf(#32)<>-1 Then Exit;

    If Not aHTTP.StartsWith('HTTP/') Then Exit;

    aHTTPLevel := StrToCurrDef( aHTTP.Substring(5),0.0);

    If aHTTPLevel=0 Then Exit;

    Result := True;//InStringList(aCommand,['GET','HEAD','POST','PUT','DELETE','TRACE','CONNECT'],False);
  Finally
    If Result Then
    Begin
      Command   := aCommand;
      URL       := aURL;
      HTTPLevel := aHTTPLevel;
    End
    Else
    Begin
      Command   := '';
      URL       := '';
      HTTPLevel := 0;
    End;
  End;
end;

Function PosR(Substr: string; S: string): Integer;

Begin
  Result := Length(S)-Length(SubStr);
  While (Result>0) Do
  Begin
    If (Copy(S,Result,Length(SubStr))=SubStr) Then Exit;
    Dec(Result);
  End;
  Result := 0;
End;

function StatusString(StatusCode: Integer): string;
begin
  case StatusCode of
    100: Result := 'Continue';
    101: Result := 'Switching Protocols';
    200: Result := 'OK';
    201: Result := 'Created';
    202: Result := 'Accepted';
    203: Result := 'Non-Authoritative Information';
    204: Result := 'No Content';
    205: Result := 'Reset Content';
    206: Result := 'Partial Content';
    300: Result := 'Multiple Choices';
    301: Result := 'Moved Permanently';
    302: Result := 'Moved Temporarily';
    303: Result := 'See Other';
    304: Result := 'Not Modified';
    305: Result := 'Use Proxy';
    400: Result := 'Bad Request';
    401: Result := 'Unauthorized';
    402: Result := 'Payment Required';
    403: Result := 'Forbidden';
    404: Result := 'Not Found';
    405: Result := 'Method Not Allowed';
    406: Result := 'None Acceptable';
    407: Result := 'Proxy Authentication Required';
    408: Result := 'Request Timeout';
    409: Result := 'Conflict';
    410: Result := 'Gone';
    411: Result := 'Length Required';
    412: Result := 'Unless True';
    500: Result := 'Internal Server Error';
    501: Result := 'Not Implemented';
    502: Result := 'Bad Gateway';
    503: Result := 'Service Unavailable';
    504: Result := 'Gateway Timeout';
  else
    Result := '';
  end
end;

function UnixPathToDosPath(const Path: string): string;
begin
  Result := TranslateChar(Path, '/', '\');
end;

end.

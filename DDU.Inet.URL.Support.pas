unit DDU.Inet.URL.Support;

//*********************************************************************************************************************
//
// DDUINET (DDU.Inet.URL.Support)
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
// Version : 2.1
//
//
// Future plans
//             - WinSock2, IP6 support
//*********************************************************************************************************************

interface

{$I DVer.inc}

uses
  System.SysUtils,
  System.Classes;
  
{$I DTypes.inc}

Procedure CrackURL(Const Url : String; Var Protocol : String; Var User : String; Var Pwd : String; Var Site : String; Var FileName : String);
Function BackslashUrl(Const URL : String) : String;
Function SlashURL(Const URL : String) : String;
Function IsV4IP(Const What : String) : Boolean;
Function IsURL(Const URL : String) : Boolean;
Function IsEmail(Const Email : String) : Boolean;
Function MakeAbsoluteURL(Const URL : String) : String;
Function CombineURLS(Root : String; SubPath : String) : String;
Function ExtractURLProtocol(Const URL : String) : String;
Function ExtractURLPassword(Const URL : String) : String;
Function ExtractURLUser(Const URL : String) : String;
Function ExtractURLHost(Const URL : String) : String;
Function ExtractURLSite(Const URL : String) : String;
Function ExtractURLPort(Const URL : String) : Integer;
Function ExtractURLSiteFile(Const URL : String) : String;
Function ExtractURLPath(Const URL : String) : String;
Function ExtractURLFileName(Const URL : String) : String;
Function GuessURLFileName(Const URL : String) : String;


implementation

Type
  TCharSet              = Set Of Char;

// Function  InStringList(Const What : String; Const Strings : Array Of String) : Boolean;
// Function  Normalize(Const AString : String) : String;
// Function  UnixPathToDosPath(Const Path : String) : String;
// Function  DosPathToUnixPath(Const Path : String) : String;
// Procedure BreakApart (Source : String; Delim : TCharSet; Dest : TStringList);


// Used during cracking.
//ThreadVar
Var
  Protocol              : String;
  User                  : String;
  Pwd                   : String;
  Site                  : String;
  SiteFile              : String;

Function InStringList(Const What : String; Const Strings : Array Of String) : Boolean;

Var
  Loop                  : Integer;

Begin
  Result :=True;
  For Loop := Low(Strings) To High(Strings) Do
  Begin
    If (AnsiCompareText(What,Strings[Loop])=0) Then
    Begin
      Exit;
    End;
  End;
  Result := False;
End;

//
// Purpose : Trim, Single Space, and convert to upper case, also removes double punctation.
//
Function Normalize(Const AString : String) : String;

Const
  TPunctuation          : Set Of Char = [#32..#47,#58..#64,#91..#96,#123..#127];

Var
  Loop                  : Integer;
  Ch                    : Char;

Begin
  Result := AnsiUpperCase(Trim(AString));
  // Elimate double punctuation
  For Loop := Length(Result) Downto 2 Do
  Begin
    Ch := Result[Loop];
    If (Ch In TPunctuation) And (Result[Loop-1]=Ch) Then
    Begin
      Delete(Result,Loop,1);
    End;
  End;
  // Elimate spaces before punctuation.
  For Loop := Length(Result)-1 Downto 1 Do
  Begin
    Ch := Result[Loop];
    If (Ch=#32) And (Result[Loop+1] In TPunctuation) Then
    Begin
      Delete(Result,Loop,1);
    End;
  End;
  // Elimate spaces after punctuation.
  For Loop := Length(Result)-1 Downto 1 Do
  Begin
    Ch := Result[Loop];
    If (Ch In TPunctuation) And (Ch<>#32) And (Result[Loop+1]=#32) Then
    Begin
      Delete(Result,Loop+1,1);
    End;
  End;
End;

Function UnixPathToDosPath(Const Path : String) : String;

Var
  Loop                  : Integer;

Begin
  Result := Path;
  For Loop := 1 To Length(Result) Do
  Begin
    If Result[Loop]='/' Then Result[Loop] := '\';
  End;
End;

Function DosPathToUnixPath(Const Path : String) : String;

Var
  Loop                  : Integer;

Begin
  Result := Path;
  For Loop := 1 To Length(Result) Do
  Begin
    If Result[Loop]='\' Then Result[Loop] := '/';
  End;
End;

Procedure BreakApart (Source : String;
                      Delim : TCharSet;
                      Dest : TStringList);

Var
  DelimCount            : Integer;        // Instead of deleteing Delims 1 at a time,
                                          // count them, and then delete them. Delphi 2.0
                                          // can have some damn big strings...
  CharCount             : Integer;        // Count of valid characters

Begin
  Dest.Clear;
  If Delim=[] Then
  Begin
    Include(Delim,#32);
  End;
  While Length(Source)>0 Do
  Begin
    { Elimate leading deliminators }
    DelimCount := 0;
    While Source[DelimCount+1] In Delim Do
    Begin
      Inc(DelimCount);
    End;
    Delete(Source,1,DelimCount);
    If Length(Source)=0 Then        // Trailing deliminators do not constitue
    Begin                           // additional information.
      Break;
    End;
    CharCount := 0;
    Repeat
      Inc(CharCount);
    Until (CharCount>=Length(Source)) Or (Source[CharCount+1] In Delim);
    Dest.Add(Copy(Source,1,CharCount));
    Delete(Source,1,CharCount);
  End;
End;

Procedure CrackURL(Const URL : String;
                   Var Protocol : String;
                   Var User : String;
                   Var Pwd : String;
                   Var Site : String;
                   Var FileName : String);

Var
  At                    : Integer;
  Loop                  : Integer;

Begin
  Protocol := URL;
  User := '';
  Pwd := '';

  For Loop := 1 To Length(Protocol) Do
  Begin
    If (Protocol[Loop]='\') Then Protocol[Loop]:='/';
  End;

  Site := Protocol;
  FileName := '/';
  At := Pos(':',Protocol);
  If (At<>0) Then
  Begin
    Protocol := AnsiLowerCase(Copy(Protocol,1,At-1));
    Site := Copy(Site,At+1,Length(Site));
    If (Copy(Site,1,2)='//') Then
    Begin
      Delete(Site,1,2);
    End
    Else
    Begin
      Site := '';
    End;
  End
  Else
  Begin
    Protocol := AnsiLowerCase(Url);
    Site := '';
    Exit;
  End;
  
  At := Pos('/',Site);
  If (At=0) Then
  Begin
    FileName := '/';
  End
  Else
  Begin
    FileName := URL;
    At := Pos('://',FileName);
    If (At<>0) Then Delete(FileName,1,At+2);
    At := Pos('/',FileName);
    Site := Copy(FileName,1,At-1);
    If (At<>0) Then
    Begin
      Delete(FileName,1,At-1);
    End
    Else
    Begin
      FileName := '/';
    End;
  End;
  
  At := Pos('@',Site);
  If (At<>0) Then
  Begin
    User := Copy(Site,1,At-1);
    Delete(Site,1,At);
    At := Pos(':',User);
    If (At<>0) Then
    Begin
      Pwd := Copy(User,At+1,Length(User));
      User := Copy(User,1,At-1);
    End;
  End;
End;

Function IsV4IP(Const What : String) : Boolean;

Var
  Work                  : String;

Function GetFrag : Boolean;

Var
  At                    : Integer;
  Val                   : Integer;

Begin
  At := Pos('.',Work);
  If (At=0) Then
  Begin
    Val := StrToIntDef(Work,-1);
    At := Length(Work);
  End
  Else
  Begin
    Val := StrToIntDef(Copy(Work,1,At-1),-1);
  End;
  Result := (Val>=0) And (Val<=255) And (Work<>'');
  Delete(Work,1,At);
End;

Begin
  Work := Trim(What);
  Result := (GetFrag and GetFrag And GetFrag And GetFrag And (Work=''));
End;

Function BackslashUrl (Const URL : String) : String;

Var
  Loop                  : Integer;

Begin                
  Result := Normalize(URL);
  For Loop := 1 To Length(Result) Do
  Begin
    If Result[Loop]='/' Then Result[Loop] := '\';
  End;
End;

Function SlashURL(Const URL : String) : String;

Var
  Loop                  : Integer;

Begin
  Result := Normalize(URL);
  For Loop := 1 To Length(Result) Do
  Begin
    If Result[Loop]='\' Then Result[Loop] := '/';
  End;
End;

Function MakeAbsoluteURL(Const URL : String) : String;

Var
  Protocol              : String;
  Password              : String;
  User                  : String;
  Site                  : String;
  FileName              : String;

  At                    : Integer;
  Backto                : Integer;

  UseBackSlash          : Boolean;


Begin
  CrackURL(URL,Protocol,Password,User,Site,FileName);
  // Filename could contain .. or . entries.
  UseBackSlash := (Pos('\',FileName)<>0);

  For At := 1 To Length(FileName) Do
  Begin
    If fileName[At]='/' Then
    Begin
      FileName[at] := '\';
    End;
  End;

  At := Pos('\.\',FileName);
  While (At<>0) Do
  Begin
    Delete(FileName,At,2);
    At := Pos('\.\',FileName);
  End;

  At := Pos('\..\',FileName);
  While (At<>0) Do
  Begin
    BackTo := At;
    Repeat
      Dec(backTo);
    Until (BackTo<1) Or (Filename[BackTo]='\');
    If BackTo=0 Then BackTo := 1;
    Delete(FileName,BackTo+1,(At-BackTo+3));
    At := Pos('\..\',FileName);
  End;
  If not UseBackSlash Then
  Begin
    For At := 1 To Length(FileName) Do
    Begin
      If fileName[At]='\' Then
      Begin
        FileName[at] := '/';
      End;
    End;
  End;
  If (Password='') And (User='') Then
  Begin
    Result := Format('%s://%s%s',[Protocol,Site,FileName]);
  End
  Else
  Begin
    Result := Format('%s://%s:%s@%s%s',[Protocol,user,Password,Site,FileName]);
  End;
End;

Function CombineURLS(Root : String; SubPath : String) : String;

Var
  Protocol              : String;
  User                  : String;
  Password              : String;
  Site                  : String;
  Path                  : String;
  At                    : Integer;

Begin
  Result := DosPathToUnixPath(Trim(Root));
  SubPath := DosPathToUnixPath(Trim(SubPath));

  If (SubPath='') Then Exit;
  If (Result='') Then
  Begin
    Result := SubPath;
    Exit;
  End;

  // Strip any CGI and ISAPI arguments.
  At := Pos('?',Result);
  If (At<>0) Then
  Begin
    Result := Copy(Result,1,At-1);
  End;

  // Ensure that there is at least a slash after the site name.
  CrackURL(Result,Protocol,Password,User,Site,Path);

  If (Path='/') And (Copy(Result,Length(Result),1)<>'/') Then
  Begin
    Root := Root+'/';
    Result := Result+'/';
  End;

  If (Copy(SubPath,1,1)<>'?') Then
  Begin
  // Strip out any file names.
    While (Result<>'') And (Copy(Result,Length(Result),1)<>'/') Do SetLength(Result,Length(Result)-1);
  End;

  If (Copy(SubPath,1,1)='.') Then   // Relative to the current DIR>
  Begin
    Result := MakeAbsoluteURL(Result+SubPath);
  End
  Else If (Copy(SubPath,1,1)='/') Then  // Absolute from the root.
  Begin
    CrackURL(Result,Protocol,Password,User,Site,Path);
    If (Password='') And (User='') Then
    Begin
      Result := Format('%s://%s%s',[Protocol,Site,SubPath]);
    End
    Else
    Begin
      Result := Format('%s://%s:%s@%s%s',[Protocol,user,Password,Site,SubPath]);
    End;
  End
  Else
  Begin  // Could be an all new site, or another .html file name.
    CrackURL(SubPath,Protocol,Password,User,Site,Path);
    If ((Protocol<>'') And (Site<>'')) Then // all new site.
    Begin
      Result := SubPath;
    End
    Else
    Begin  // Another HTML file, or into the current file.
      If (Copy(SubPath,1,1)='#') Then  // In the current document.
      Begin
        Result := Root+SubPath;
      End
      Else
      Begin
        Result := Result+SubPath;
      End;
    End;
  End;
End;

Function ExtractURLProtocol(Const URL : String) : String;

Begin
  CrackURL(URL,Protocol,User,Pwd,Site,SiteFile);
  Result := Protocol;
End;

Function ExtractURLUser(Const URL : String) : String;

Begin
  CrackURL(URL,Protocol,User,Pwd,Site,SiteFile);
  Result := User;
End;

Function ExtractURLPassword(Const URL : String) : String;

Begin
  CrackURL(URL,Protocol,User,Pwd,Site,SiteFile);
  Result := Pwd;
End;

Function ExtractURLHost(Const URL : String) : String;

Begin
  CrackURL(URL,Protocol,User,Pwd,Site,SiteFile);
  Result := Site;
End;

Function ExtractURLSite(Const URL : String) : String;

Var
  At                    : Integer;

Begin
  CrackURL(URL,Protocol,User,Pwd,Site,SiteFile);
  At := Pos(':',Site);
  If (At<>0) Then
  Begin
    SetLength(Site,At-1);
  End;
  Result := Site;
End;

Function ExtractURLPort(Const URL : String) : Integer;

Var
  At                              : Integer;

Begin
  CrackURL(URL,Protocol,User,Pwd,Site,SiteFile);

  At := Pos(':',Site);
  If (At<>0) Then
  Begin
    Result := StrToIntDef(Copy(Site,At+1,Length(Site)),0);
  End
  Else
  Begin
    Result := 0;
  End;
End;

Function ExtractURLSiteFile(Const URL : String) : String;

Begin
  CrackURL(URL,Protocol,User,Pwd,Site,SiteFile);
  If (Protocol='') And (Site='') Then
  Begin
    Result := URl;
  End
  Else
  Begin
    Result := SiteFile;
  End;
End;

Function ExtractURLPath(Const URL : String) : String;

Var
  At                      : Integer;

Begin
  Result := ExtractURLSiteFile(URL);

  At := Length(Result);
  While (At>0) And (Not (Result[At] In ['\','/'])) Do
  Begin
    Dec(At);
  End;
  SetLength(Result,At);
//  While (Length(Result)>0) And Not (Result[Length(result)] In ['\','/']) Do
//    SetLength(Result,Length(Result)-1);
End;

Function ExtractURLFileName(Const URL : String) : String;

Begin
  Result := ExtractURLSiteFile(URL);
  Delete(Result,1,Length(ExtractURLPath(Url)));
End;

Function IsEmail(Const Email : String) : Boolean;

Var
  At     : Integer;
  Name   : String;
  Domain : String;

Begin
  Result := False;
  At := Pos('@',Email);
  If At=0 Then Exit;
  Name := Trim(Copy(Email,1,At-1));
  Domain := Trim(Copy(Email,At+1,Length(Email)));
  If (Name='') Or (Domain='') Or (Pos('@',Domain)<>0) Then Exit;
  // Add in more stringent checking based on contents of each field.
  Result := True;
End;

Function IsURL (Const URL : String) : Boolean;

Var
  At                    : Integer;
  Work                  : String;

Begin
  Work := URL;
  At := Pos('?',Work);
  If (At<>0) Then
  Begin
    SetLength(Work,At-1);
  End;
  CrackURL(Work,Protocol,User,Pwd,Site,SiteFile);
  Result := InStringList(AnsiUpperCase(protocol),['FTP','HTTP']) And (Trim(Site)<>'') And (Trim(SiteFile)<>'');
End;

Function GuessURLFileName(Const URL : String) : String;

Const
  NotValidInFileName        : Set Of Char = [#0..#31,'\','/',':','?','"','<','>','|'];

Var
  URLS                  : TStringList;
  Loop                  : Integer;
  Original              : String;
  P,Usr,Pwd,S,f         : String;
  Work                  : String;
  At                    : Integer;

Begin
  Original := URL;
  Result := '';
  If (URL='') Then
  Begin
    Exit;
  End;
  Urls := TStringList.Create;
  Try
    BreakApart(URL,['?'],URLS);
    
    For Loop := URLS.COunt-1 DownTo 0 Do
    Begin
      At := Pos('FTP',AnsiUpperCase(URLs[Loop]));
      If (At=0) Then At := Pos('HTTP',AnsiUpperCase(URLs[Loop]));
      If (At>1) Then
      Begin
        Work := URLS[Loop];
        Delete(Work,1,At-1);
        URLS[Loop] := Work;
      End;

      If IsURL(URLS[Loop]) Then
      Begin
        Result := GuessURLFileName(URLS[Loop]);
        Break;
      End;
    End;
    If (Result='') Then
    Begin
      Original := URLS[0];
    End;
  Finally
    FreeAndNil(Urls);
  End;
  If (Result='') Then
  Begin
    If IsURL(Original) Then
    Begin
      CrackURL(Original,P,Usr,Pwd,S,F);
      Work := Copy(F,Length(F),1);
      If InStringList(Work,['/','\']) Then
      Begin
        If (Length(Work)=1) Then
        Begin
          Work := 'default.'+P;
        End
        Else
        Begin
          Delete(Original,Length(Original),1);
          Original := Original+'.'+P;
          Result := GuessURLFileName(Original);  // This will ALWAYS produce a URL.
        End;
      End;
    End;
    If (Result='') Then
    Begin
      Result := Original;
      For Loop := 1 TO Length(Result) Do
      Begin
        If Result[Loop] In NotValidInFileName Then Result[Loop] := '_';
      End;
    End;
  End;
End;



end.

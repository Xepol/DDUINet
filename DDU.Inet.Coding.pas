unit DDU.Inet.Coding;

//*****************************************************************************
//
// DDUINET (DDU.Inet.Coding)
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

interface

{$I DVer.inc}

Uses
  System.SysUtils,
  System.Classes,
  DDU.Buffer,
  DDU.Buffer.Support;

{$I DTypes.inc}

Function Base64EncodeLine(Source : TBytes; MinLength : Integer) : TBytes;

Function Base64DecodeLine(Source : TBytes) : TBytes;
Function Base64DecodeBuffer(Source : TBytes) : TBytes;

Function UUEncodeLine(Source : String; MinLength : Integer) : String;
Function UUDecodeLine(Source : String) : String;

implementation


// To keep code as a fast as possible, instead of passing structures on
// the stack, I am making them global.  This lets me write in a few additional
// shortcuts further on.  They are used by internal routines.  If the contents
// of these global variables were to change between calls loading them and
// interpreting them the results would be corruption.  For this reason,
// the internal routines should NEVER be exposed.  To ensure that this code
// remains threadsafe, these variables are ThreadVar, instead of global VARs.
//
// Certain assumptions and requirements are made about the state of
// these variables at various stages.  Where important, these assumptions
// will be noted in the code.
//
// To reduce the total amount of String management performed by Delphi,
// I am using Shortstrings with know locations, and known lengths where-ever
// possible.
//
ThreadVar
  EncodeResult          : Array[0..4] Of Byte;
  DecodeResult          : Array[0..3] Of Byte;

  Group                 : Array[0..3] Of Byte;
  GroupSize             : Integer;

Const
  NeedInitBase64DecodeArray : Boolean = True;

Var
  Base64DecodeArray     : Array[0..255] Of Byte;
  UUMapString           : TBytes;
  Base64MapString       : TBytes;
  Base64EndToken        : Byte;

Procedure InitBase64DecodeArray;

Var
  Loop : Integer;

Begin
  If NeedInitBase64DecodeArray Then // No real harm done here with multi threading.
  Begin
    NeedInitBase64DecodeArray := False;
    FillChar(Base64DecodeArray,SizeOf(Base64DecodeArray),#0);
    For Loop := 1 To Length(Base64MapString) Do
    Begin
      Base64DecodeArray[Byte(Base64MapString[Loop])] := Loop-1;
    End;
  End;
End;

//
// Uses ThreadVar Group and GroupSize, set by a LoadGroup call prior to this.
//
// Always assumes that GROUPSIZE is at least 1, no larger than 3.
//
// Result is returned through the ThreadVar EncodeResult,
// reducing the total amount of String management required by Delphi.
//
// EncodeResult[0] Is set to the correct length for the String.
//
Procedure UUEncodeGroup;

Begin
  EncodeResult[0] := GroupSize+1;
  EncodeResult[1] := UUMapString[((Group[0] And $fc) Shr 2)+1];
  EncodeResult[2] := UUMapString[(((Group[0] And $3) Shl 4) Or ((Group[1] And $f0) Shr 4))+1];
  If (GroupSize<>1) Then
    EncodeResult[3] := UUMapString[(((Group[1] And $f) Shl 2) Or ((Group[2] And $c0) Shr 6))+1];
  If (GroupSize=3) Then
    EncodeResult[4] := UUMapString[(Group[2] And $3f)+1];
End;

//
// Uses ThreadVar Group and GroupSize, set by a LoadGroup call prior to this.
//
// Always assumes that GROUPSIZE is at least 1, no larger than 3.
//
// Result is returned through the ThreadVar EncodeResult,
// reducing the total amount of String management required by Delphi.
//
// Encoding routines should set EncodeResult[0] to #4 before
// starting if the need exists to use EncodeResult as a String.
//
Procedure EncodeBase64Group;

Begin
  EncodeResult[1] := Base64MapString[((Group[0] And $fc) Shr 2)+1];
  EncodeResult[2] := Base64MapString[(((Group[0] And $3) Shl 4) Or ((Group[1] And $f0) Shr 4))+1];
  If (GroupSize<>1) Then
  Begin
    EncodeResult[3] := Base64MapString[(((Group[1] And $f) Shl 2) Or ((Group[2] And $c0) Shr 6))+1];
  End
  Else
  Begin
    EncodeResult[3] := Base64EndToken;
  End;
  If (GroupSize=3) Then
  Begin
    EncodeResult[4] := Base64MapString[(Group[2] And $3f)+1];
  End
  Else
  Begin
    EncodeResult[4] := Base64EndToken;
  End;
End;

//
// Uses ThreadVar Group and GroupSize, set by a LoadGroup call prior to this.
//
// Always assumes that GROUPSIZE is at least 1, no larger than 3.
//
// Assumes that EncodeResult is already the correct total length, and
// filled with = signs.
//
// This code is different than EncodeBase64Group because it knows that
// the result is a String, and is specially written for that purpose,
// reducing the total amount of String management required by Delphi.
//
Procedure EncodeBase64GroupToString(Var EncodeResult : TBytes;
                                    Var EncodeTo : Integer);

Begin
  EncodeResult[EncodeTo]   := Base64MapString[((Group[0] And $fc) Shr 2)+1];
  EncodeResult[EncodeTo+1] := Base64MapString[(((Group[0] And $3) Shl 4) Or ((Group[1] And $f0) Shr 4))+1];
  If (GroupSize<>1) Then
  Begin
    EncodeResult[EncodeTo+2] := Base64MapString[(((Group[1] And $f) Shl 2) Or ((Group[2] And $c0) Shr 6))+1];
  End;
  If (GroupSize=3) Then
  Begin
    EncodeResult[EncodeTo+3] := Base64MapString[(Group[2] And $3f)+1];
  End;
  EncodeTo := (EncodeTo+GroupSize+1);
End;

//
// Uses ThreadVar Group and GroupSize, set by a LoadGroup call prior to this.
//
// Always assumes that GROUPSIZE is at least 1, no larger than 3.
//
// Result is returned through the ThreadVar DecodeResult,
// reducing the total amount of String management required by Delphi.
//
// Encoding routines should set EncodeResult[0] to #4 before
// starting if the need exists to use EncodeResult as a String.
//
Procedure DecodeBase64Group;

Begin
  If (Group[3]=Byte(Base64EndToken)) Then Dec(GroupSize);
  If (Group[2]=Byte(Base64EndToken)) Then Dec(GroupSize);

  Group[0] := Base64DecodeArray[Group[0]];
  Group[1] := Base64DecodeArray[Group[1]];
  Group[2] := Base64DecodeArray[Group[2]];
  Group[3] := Base64DecodeArray[Group[3]];

  DecodeResult[1] := (((Group[0]) Shl 2) Or (Group[1] Shr 4));
  DecodeResult[2] := (((Group[1] And $f) Shl 4) Or (Group[2] Shr 2));
  DecodeResult[3] := (((Group[2] And $3) Shl 6) or Group[3]);
  DecodeResult[0] := (GroupSize-1);
End;


//
// Fills ThreadVar Group and GroupSize variables for an Encoding routine.
//
// SOURCE String and EncodeFrom are used to reduce the total amount of
// String management required by Delphi.
//
// Group is pre-set to 0s for encoding.
//
Function LoadEncodeGroup(Const Source : TBytes; Var EncodeFrom : Integer) : Integer;

Begin
  GroupSize := (Length(Source)-EncodeFrom)+1;
  Group[0] := 0;
  Group[1] := 0;
  Group[2] := 0;
  If (GroupSize<=0) Then
  Begin
    Result := 0;
    Exit;
  End;
  If (GroupSize>3) Then GroupSize := 3;
  Result := GroupSize;  // So it can be used as a function in a While statement.
  Group[0] := Source[EncodeFrom];

// Ok, I know its picky, but identity(=,<>) tests are faster than < and > operations.
  If (GroupSize<>1)  Then Group[1] := Source[EncodeFrom+1];
  If (GroupSize = 3) Then Group[2] := Source[EncodeFrom+2];
  Inc(EncodeFrom,GroupSize);
End;

//
// Fills ThreadVar Group and GroupSize variables for an Encoding routine.
//
// SOURCE String and EncodeFrom are used to reduce the total amount of
// String management required by Delphi.
//
// Group is pre-set to 0s for Decoding.
//
Function LoadDecodeGroup(Const Source : TBytes;
                         Var DecodeFrom : Integer) : Integer;

Begin
  GroupSize := (Length(Source)-DecodeFrom)+1;
  Group[0] := 0;
  Group[1] := 0;
  Group[2] := 0;
  Group[3] := 0;
  If (GroupSize<=0) Then
  Begin
    Result := 0;
    Exit;
  End;

  If (GroupSize>4) Then GroupSize := 4;
  Result := GroupSize;  // So it can be used as a function in a While statement.

  Group[0] := Byte(Source[DecodeFrom]);
// Ok, I know its picky, but identity(=,<>) tests are faster than < > operations.
  If (GroupSize<>1) Then Group[1] := Byte(Source[DecodeFrom+1]); // 2
  If (GroupSize>2) Then Group[2] := Byte(Source[DecodeFrom+2]);  // 3 or 4
  If (GroupSize=4) Then Group[3] := Byte(Source[DecodeFrom+3]);  // 4
  Inc(DecodeFrom,GroupSize);
End;

Function Base64EncodeLine(Source : TBytes; MinLength : Integer) : TBytes;

Var
  EncodeFrom            : Integer;
  EncodeTo              : Integer;
  Size                  : Integer;
  RawSource             : TBytes;

Begin

// String size is pre-allocated, to reduce the amount of String management
// performed by Delphi.  Base64 lines MUST by a multiple of 4, so even if a
// minimum size is supplied, it is rounded to the nearest highest multiple of 4.
  RawSource := Source;

  EncodeTo := Length(RawSource);
  If (EncodeTo<MinLength) Then
  Begin
    EncodeTo := MinLength;
  End;
  Size := (EncodeTo Div 3)*4;
  If ((EncodeTo Mod 3)<>0) Then
  Begin
    Inc(Size,4);
  End;
  SetLength(Result,Size);

// Result is pre-filled with = characters.
  FillChar(Result[0],Size,Base64EndToken);

// Encoding is started, no String management takes place from this point forward,
// all results are read/written directly from/to memory buffers pre-allocated
// to the strings used.

  EncodeFrom := 0;
  EncodeTo   := 0;
  While (LoadEncodeGroup(RawSource,EncodeFrom)<>0) Do
  Begin
    EncodeBase64GroupToString(Result,EncodeTo);
  End;
End;

Function Base64DecodeLine(Source : TBytes) : TBytes;

Var
  DecodeFrom            : Integer;
  Buffer                : TDDUBuffer;

Begin
  InitBase64DecodeArray;

  Buffer := TDDUBuffer.Create;
  Try

    DecodeFrom := 0;


    While (LoadDecodeGroup(Source,DecodeFrom)<>0) Do
    Begin
      DecodeBase64Group;

      Buffer.WriteData(@DecodeResult[1],DecodeResult[0]);
    End;
  Finally
    Result := Buffer.ReadBytes(Buffer.DataAvailable);
    Buffer.Free;
  End;

End;

Function Base64DecodeBuffer(Source : TBytes) : TBytes;

//Var
//  S                     : TStringList;
//  Loop                  : Integer;
//
//  InBuffer              : TDDUBufer;
//  OutBuffer             : TDDUBuffer;

Begin
//  Buffer := TDDUBuffer.Create;
//  Try
//    S := TStringList.Create;
//    Try
//      S.Text := Source;
//
//      For Loop := 0 To S.Count-1 Do
//      Begin
//        Result := Result+Base64DecodeLine(S[Loop]);
//      End;
//    Finally
//      FreeAndNil(S);
//    End;
//
//  FInally
//    Buffer.Free;
//  End;
End;

Function UUEncodeLine(Source : String; MinLength : Integer) : String;

Begin
End;

Function UUDecodeLine(Source : String) : String;

Begin
End;


Initialization
  UUMapString      := bString('`!"#$%&''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_',smAnsi);
  Base64MapString  := bString('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',smAnsi);
  Base64EndToken   :=  Ord('=');
end.

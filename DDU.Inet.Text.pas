unit DDU.Inet.Text;

//*********************************************************************************************************************
//
// DDUINET (DDU.Inet.Text)
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
//            - Text based raw protocol.
//            - Automatic LF/CR/CRLF EOL sensing for data from host.
//            - Buffers incoming and outgoing data.
//            - Multiple simultaneous session capable.
//            - Ability to send received data to a stream automatically.
//
//            - A non-blocking client.
//            - Fully event driven.
//            - ALL Events returned to programmer for further interpretation.
//            - High level of control over sockets.  You can specify the amount of information
//              to data read&write from/to a socket per read/write.
//            - Events are simulated as required.
//            - Drains socket before obeying a disconnect to prevent data being lost.
//
// Known Issues :
//
//            - Locks during normal DNS LOOPUP, use a linked TDDUCUSTOMDNS component for resolving.
//
//
// Future plans
//             - WinSock2, IP6 support
//*********************************************************************************************************************

interface

{$I DVer.inc}

uses
  WinAPI.Windows,
  WinAPI.Messages,
  WinAPI.WinSock,
  System.SysUtils,
  System.Classes,
  DDU.Inet.Socket,
  DDU.Inet.Socket.Types;
  
{$I DTypes.inc}

Type
  TDDUText = class(TDDUSocket)
  Public
    Constructor Create(AnOwner : TComponent); Override;
  Published
    property Address;
    Property BlockAutoStart;
    Property BlockAutoStartPrefix;
    Property AutoDisconnectClients;
    Property DataMode Default dmText;
    property Drain;
    Property DNS;
    Property EOL;
    Property Proxy;
    Property SocketMode;
    Property SocketOptions;
    Property SocketProtocol;
    Property TextMode;
    property Throttle;
//*****************************************************************************
// Events
//*****************************************************************************
    property OnAccept;
    Property OnAcceptEx;             
    Property OnAddClient;            
    Property OnAfterRead;            
    Property OnBeforeRead;           
    Property OnBlockReceiveAbort;    
    Property OnBlockReceiveDone;     
    Property OnBlockReceiveProgress; 
    Property OnBlockReceiveStart;    
    Property OnBlockSendDone;        
    Property OnBlockSendProgress;    
    Property OnBlockSendStart;       
    Property OnClientInit;           
    Property OnConnect;              
    Property OnConnectFailed;        
    Property OnConnecting;           
    Property OnDisconnect;           
    Property OnError;                
    Property OnFreeStream;           
    Property OnGetClientClass;       
    Property OnGetStream;            
    Property OnListen;               
    Property OnLookup;               
    Property OnProgress;             
    Property OnProgressStream;       
    Property OnRead;                 
    Property OnRemoveClient;         
    Property OnSendStreamDone;       
    Property OnSignal;               
    Property OnText;                 
    Property OnTextEx;               
    Property OnThrottle;             
    Property OnThrottleReadOff;      
    Property OnThrottleReadOn;       
    Property OnThrottleWriteOff;     
    Property OnThrottleWriteOn;      
    Property OnTimeout;              
  End;

implementation

Constructor TDDUText.Create(AnOwner : TComponent);

Begin
  Inherited Create(AnOwner);
  DataMode := dmText;
End;

end.

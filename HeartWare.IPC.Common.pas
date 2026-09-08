{ ========================================================================== }
{                                                                            }
{  HeartWare.IPC.Common                                                      }
{                                                                            }
{  HeartWare.IPC is FreeWare. See README.MD for licensing and usage terms.   }
{                                                                            }
{  Shared low-level support for the HeartWare.IPC client/server transport.   }
{                                                                            }
{  This unit owns pipe-name construction, packet framing, CRC32 validation,  }
{  UTF-8 convenience helpers, shared exception classes, and the abstract     }
{  TIPCTransport ancestor used by both ends of a connection.                 }
{                                                                            }
{  Wire protocol                                                             }
{  - DWORD Length, LONG ErrorCode, Data[Length-4], DWORD CRC32.              }
{  - Length and CRC32 both cover ErrorCode plus Data.                        }
{  - Requests conventionally use ErrorCode=0.                                }
{  - MaxPacketSize defaults to 256 MiB and includes ErrorCode.               }
{                                                                            }
{  Public types                                                              }
{  - EIPCError: general IPC transport/protocol failure.                      }
{  - EIPCCodedError: adds ErrorCode and binary Data.                         }
{  - EIPCReplyError: server-side deliberate error response.                  }
{  - EIPCRemoteError: client-side representation of remote failure.          }
{  - TIPCTransport: common complete-packet read/write implementation.        }
{                                                                            }
{  Public helpers                                                            }
{  - IPCLogonSID returns the current Windows logon SID.                      }
{  - IPCPipeName builds the SID-qualified local named-pipe path.             }
{  - IPCUTF8Encode and IPCUTF8Decode convert String and TBytes.              }
{  - IPCCRC32 calculates the CRC used by the packet format.                  }
{                                                                            }
{  Implementation notes                                                      }
{  - The standalone build contains its own CRC32 implementation.             }
{  - If HW is defined and HeartWare.CRC provides CRC32, it may be used.      }
{  - A disconnect is clean only between packets; truncated frames fail.      }
{  - TIPCTransport performs no internal locking for concurrent callers.      }
{                                                                            }
{ ========================================================================== }
UNIT HeartWare.IPC.Common;

INTERFACE

USES
  WinAPI.Windows,
  System.SysUtils;

CONST
  SDDL_REVISION_1 = 1;

FUNCTION ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor : LPCWSTR; StringSDRevision: DWORD; OUT SecurityDescriptor: PSECURITY_DESCRIPTOR; SecurityDescriptorSize: PULONG) : BOOL; stdcall; external 'advapi32.dll';
FUNCTION ConvertStringSecurityDescriptorToSecurityDescriptor(StringSecurityDescriptor : LPCWSTR; StringSDRevision: DWORD; OUT SecurityDescriptor: PSECURITY_DESCRIPTOR; SecurityDescriptorSize: PULONG) : BOOL; inline;

CONST
  {
    Negative values are reserved by HeartWare.IPC itself.

    Positive values are available to applications using the IPC layer.
  }

  IPC_ERROR_EXCEPTION = -1;
  IPC_ERROR_PROTOCOL  = -2;

  {
    Maximum value of <Length> accepted by default.

    This includes the 4-byte ErrorCode, but not the Length DWORD
    itself or the CRC32.
  }

  IPC_DEFAULT_MAX_PACKET_SIZE = 256*1024*1024;


TYPE
  PBytes                = ^TBytes;
  EIPCError             = CLASS(Exception);
  EIPCCodedError        = CLASS(EIPCError)
                          PRIVATE
                            FErrorCode : Integer;
                            FData      : TBytes;
                          PUBLIC
                            CONSTRUCTOR Create(ErrorCode : Integer ; CONST Msg : String); REINTRODUCE; OVERLOAD;
                            CONSTRUCTOR Create(ErrorCode : Integer ; CONST Data : TBytes); REINTRODUCE; OVERLOAD;
						  PUBLIC
                            PROPERTY    ErrorCode : Integer Read FErrorCode;
                            PROPERTY    Data : TBytes Read FData;
                          END;
  {
    May be raised by TIPCSession.Parse.

    The server converts it directly into an IPC error response.
  }
  EIPCReplyError        = CLASS(EIPCCodedError);
  {
    Raised by TIPCClient.Execute when the server returned a non-zero
    ErrorCode.
  }
  EIPCRemoteError       = CLASS(EIPCCodedError);
  {
    Common binary transport ancestor for both server and client.

    Wire format:

      DWORD Length
      LONG  ErrorCode
      BYTE  Data[Length-4]
      DWORD CRC32

    Length and CRC32 both include ErrorCode.

    Read/Write operate on complete IPC packets, not individual
    ReadFile/WriteFile operations.
  }
  TIPCTransport         = CLASS ABSTRACT
                          PRIVATE
                            FMaxPacketSize      : Cardinal;
                          PRIVATE
                            FUNCTION            ReadExact(Buffer : POINTER ; Count : Cardinal ; AllowCleanDisconnect : BOOLEAN) : BOOLEAN;
                            FUNCTION            WriteExact(Buffer : POINTER ; Count : Cardinal) : BOOLEAN;
                            PROCEDURE           SetMaxPacketSize(Value : Cardinal);
                          PROTECTED
                            FPipe               : THandle;
                            FUNCTION            Read(OUT ErrorCode : Integer ; OUT Data : TBytes) : BOOLEAN;
                            FUNCTION            Write(ErrorCode : Integer ; CONST Data : TBytes) : BOOLEAN;
                            PROCEDURE           ClosePipe;
                          PUBLIC
                            CONSTRUCTOR         Create;
                            DESTRUCTOR          Destroy; OVERRIDE;
                          PUBLIC
                            PROPERTY            MaxPacketSize : Cardinal Read FMaxPacketSize Write SetMaxPacketSize;
                          END;

FUNCTION IPCLogonSID : String;
FUNCTION IPCPipeName(CONST BaseName : String) : String;
FUNCTION IPCUTF8Encode(CONST S : String) : TBytes;
FUNCTION IPCUTF8Decode(CONST Data : TBytes) : String;
FUNCTION IPCCRC32(CONST Data : TBytes) : Cardinal;

IMPLEMENTATION

{$IFDEF HW }
USES HeartWare.CRC;
{$ENDIF }

FUNCTION ConvertStringSecurityDescriptorToSecurityDescriptor(StringSecurityDescriptor : LPCWSTR; StringSDRevision: DWORD; OUT SecurityDescriptor: PSECURITY_DESCRIPTOR; SecurityDescriptorSize: PULONG) : BOOL;
  BEGIN
    Result:=ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor,StringSDRevision,SecurityDescriptor,SecurityDescriptorSize)
  END;

CONST
  IPCPipePrefix='\\.\pipe\';

{$IF DECLARED(CRC32) }
FUNCTION IPCCRC32(CONST Data : TBytes) : Cardinal;
  BEGIN
    Result:=CRC32(Data)
  END;
{$ELSE }
VAR
  CRC32Table : ARRAY[0..255] OF Cardinal;

{ ========================================================================== }
{                                                                            }
{  CRC32                                                                     }
{                                                                            }
{ ========================================================================== }

PROCEDURE InitializeCRC32;
  VAR
    I,J : Integer;
    C   : Cardinal;

  BEGIN
    FOR I:=0 TO 255 DO BEGIN
      C:=Cardinal(I);
      FOR J:=0 TO 7 DO
        IF (C AND 1)<>0 THEN
          C:=(C SHR 1) XOR $EDB88320
        ELSE
          C:=C SHR 1;
      CRC32Table[I]:=C
    END
  END;

FUNCTION IPCCRC32(CONST Data : TBytes) : Cardinal;
  VAR
    I : Integer;
    C : Cardinal;

  BEGIN
    C:=$FFFFFFFF;
    FOR I:=0 TO HIGH(Data) DO
      C:=CRC32Table[BYTE(C XOR Data[I])] XOR (C SHR 8);
    Result:=C XOR $FFFFFFFF
  END;
{$ENDIF }

{ ========================================================================== }
{                                                                            }
{  UTF-8 helpers                                                             }
{                                                                            }
{ ========================================================================== }

FUNCTION IPCUTF8Encode(CONST S : String) : TBytes;
  BEGIN
    Result:=TEncoding.UTF8.GetBytes(S)
  END;

FUNCTION IPCUTF8Decode(CONST Data : TBytes) : String;
  BEGIN
    IF LENGTH(Data)=0 THEN
      Result:=''
    ELSE
      Result:=TEncoding.UTF8.GetString(Data)
  END;

{ ========================================================================== }
{                                                                            }
{  EIPCCodedError                                                            }
{                                                                            }
{ ========================================================================== }

CONSTRUCTOR EIPCCodedError.Create(ErrorCode : Integer ; CONST Msg : String);
  BEGIN
    INHERITED Create(Msg);
    FErrorCode:=ErrorCode; FData:=IPCUTF8Encode(Msg)
  END;

CONSTRUCTOR EIPCCodedError.Create(ErrorCode : Integer; CONST Data : TBytes);
  BEGIN
    INHERITED Create(IPCUTF8Decode(Data));
    FErrorCode:=ErrorCode; FData:=COPY(Data)
  END;

{ ========================================================================== }
{                                                                            }
{  Logon / pipe name                                                         }
{                                                                            }
{ ========================================================================== }

FUNCTION IPCLogonSID : String;
  VAR
    Token       : THandle;
    Size        : DWORD;
    Groups      : PTokenGroups;
    StringSID   : PChar;

  BEGIN
    Result:=''; Token:=0;
    IF NOT OpenProcessToken(GetCurrentProcess,TOKEN_QUERY,Token) THEN RaiseLastOSError;
    TRY
      Size:=0;
      GetTokenInformation(Token,TokenLogonSid,NIL,0,Size);
      IF Size=0 THEN RaiseLastOSError;
      GetMem(Groups,Size);
      TRY
        IF NOT GetTokenInformation(Token,TokenLogonSid,Groups,Size,Size) THEN RaiseLastOSError;
        IF Groups^.GroupCount=0 THEN RAISE EIPCError.Create('Windows returned no logon SID');
        StringSID:=NIL;
        IF NOT ConvertSidToStringSid(Groups^.Groups[0].Sid,StringSID) THEN RaiseLastOSError;
        TRY
          Result:=StringSID
        FINALLY
          LocalFree(HLOCAL(StringSID))
        END
      FINALLY
        FreeMem(Groups)
      END
    FINALLY
      CloseHandle(Token)
    END
  END;

FUNCTION IPCPipeName(CONST BaseName : String) : String;
  BEGIN
    IF BaseName.IsEmpty THEN RAISE EIPCError.Create('IPC pipe name may not be empty');
    IF POS('\',BaseName)>0 THEN RAISE EIPCError.Create('IPC pipe name must be a base name, not a path');
    Result:=IPCPipePrefix+BaseName+'.'+IPCLogonSID
  END;

{ ========================================================================== }
{                                                                            }
{  TIPCTransport                                                             }
{                                                                            }
{ ========================================================================== }

CONSTRUCTOR TIPCTransport.Create;
  BEGIN
    INHERITED Create;
    FPipe:=INVALID_HANDLE_VALUE;
    FMaxPacketSize:=IPC_DEFAULT_MAX_PACKET_SIZE
  END;

DESTRUCTOR TIPCTransport.Destroy;
  BEGIN
    ClosePipe;
    INHERITED
  END;

PROCEDURE TIPCTransport.SetMaxPacketSize(Value : Cardinal);
  BEGIN
    IF Value<SizeOf(Integer) THEN RAISE EIPCError.Create('Maximum IPC packet size must be at least '+IntToStr(SizeOf(Integer))+' bytes');
    FMaxPacketSize:=Value
  END;

PROCEDURE TIPCTransport.ClosePipe;
  BEGIN
    IF FPipe<>INVALID_HANDLE_VALUE THEN BEGIN
      CloseHandle(FPipe);
      FPipe:=INVALID_HANDLE_VALUE
    END
  END;

{ -------------------------------------------------------------------------- }
{  ReadExact                                                                 }
{ -------------------------------------------------------------------------- }

FUNCTION TIPCTransport.ReadExact(Buffer : POINTER ; Count : Cardinal ; AllowCleanDisconnect : BOOLEAN) : BOOLEAN;
  VAR
    P           : PBYTE;
    Remaining   : DWORD;
    BytesRead   : DWORD;
    TotalRead   : Cardinal;
    Error       : DWORD;

  BEGIN
    Result:=(Count=0);
    IF Result THEN EXIT;
    IF FPipe=INVALID_HANDLE_VALUE THEN RAISE EIPCError.Create('IPC pipe is not connected');
    P:=Buffer; Remaining:=Count; TotalRead:=0;
    WHILE Remaining>0 DO BEGIN
      BytesRead:=0;
      IF NOT ReadFile(FPipe,P^,Remaining,BytesRead,NIL) THEN BEGIN
        Error:=GetLastError;
        CASE Error OF
          ERROR_BROKEN_PIPE,
          ERROR_PIPE_NOT_CONNECTED,
          ERROR_NO_DATA,
          ERROR_OPERATION_ABORTED:
            BEGIN
              IF AllowCleanDisconnect AND (TotalRead=0) THEN EXIT;
              RAISE EIPCError.Create('IPC connection closed in the middle of a packet')
            END;
        ELSE // OTHERWISE //
          RaiseLastOSError(Error)
        END
      END;
      IF BytesRead=0 THEN BEGIN
        IF AllowCleanDisconnect AND (TotalRead=0) THEN EXIT;
        RAISE EIPCError.Create('IPC connection closed in the middle of a packet')
      END;
      INC(P,BytesRead);
      INC(TotalRead,BytesRead);
      DEC(Remaining,BytesRead)
    END;
    Result:=TRUE
  END;

{ -------------------------------------------------------------------------- }
{  WriteExact                                                                }
{ -------------------------------------------------------------------------- }

FUNCTION TIPCTransport.WriteExact(Buffer : POINTER ; Count : Cardinal) : BOOLEAN;
  VAR
    P                   : PBYTE;
    Remaining           : DWORD;
    BytesWritten        : DWORD;
    Error               : DWORD;

  BEGIN
    Result:=(Count=0);
    IF Result THEN EXIT;
    IF FPipe=INVALID_HANDLE_VALUE THEN RAISE EIPCError.Create('IPC pipe is not connected');
    P:=Buffer; Remaining:=Count;
    WHILE Remaining>0 DO BEGIN
      BytesWritten:=0;
      IF NOT WriteFile(FPipe,P^,Remaining,BytesWritten,NIL) THEN BEGIN
        Error:=GetLastError;
        CASE Error OF
          ERROR_BROKEN_PIPE,
          ERROR_PIPE_NOT_CONNECTED,
          ERROR_NO_DATA,
          ERROR_OPERATION_ABORTED:
            EXIT
        ELSE // OTHERWISE //
          RaiseLastOSError(Error)
        END
      END;
      IF BytesWritten=0 THEN EXIT;
      INC(P,BytesWritten);
      DEC(Remaining,BytesWritten)
    END;
    Result:=TRUE
  END;

{ -------------------------------------------------------------------------- }
{  Read                                                                      }
{ -------------------------------------------------------------------------- }

FUNCTION TIPCTransport.Read(OUT ErrorCode : Integer ; OUT Data : TBytes) : BOOLEAN;
  VAR
    PacketLength        : Cardinal;
    ReceivedCRC         : Cardinal;
    CalculatedCRC       : Cardinal;
    DataLength          : Cardinal;
    Payload             : TBytes;

  BEGIN
    Result:=FALSE; ErrorCode:=0;
    SetLength(Data,0);
    {
      A clean disconnect is only possible between complete packets.

      If the connection closes after any part of a packet has arrived,
      ReadExact raises a protocol error instead.
    }
    IF NOT ReadExact(@PacketLength,SizeOf(PacketLength),TRUE) THEN EXIT;
    IF PacketLength<SizeOf(Integer) THEN RAISE EIPCError.CreateFmt('Invalid IPC packet length: %d',[PacketLength]);
    IF PacketLength>FMaxPacketSize THEN RAISE EIPCError.CreateFmt('IPC packet is too large: %d bytes',[PacketLength]);
    SetLength(Payload,PacketLength);
    ReadExact(POINTER(Payload),PacketLength,FALSE);
    ReadExact(@ReceivedCRC,SizeOf(ReceivedCRC),FALSE);
    CalculatedCRC:=IPCCRC32(Payload);
    IF ReceivedCRC<>CalculatedCRC THEN RAISE EIPCError.CreateFmt('IPC packet CRC32 mismatch (received %.8X, expected %.8X)',[ReceivedCRC,CalculatedCRC]);
    MOVE(Payload[0],ErrorCode,SizeOf(ErrorCode));
    DataLength:=PacketLength-SizeOf(ErrorCode);
    SetLength(Data,DataLength);
    IF DataLength>0 THEN
      Move(Payload[SizeOf(ErrorCode)],Data[0],DataLength);
    Result:=TRUE
  END;

{ -------------------------------------------------------------------------- }
{  Write                                                                     }
{ -------------------------------------------------------------------------- }

FUNCTION TIPCTransport.Write(ErrorCode : Integer; CONST Data : TBytes) : BOOLEAN;
  VAR
    PacketLength        : Cardinal;
    CRC                 : Cardinal;
    Payload             : TBytes;

  BEGIN
    Result:=FALSE;
    IF UInt64(LENGTH(Data))+SizeOf(ErrorCode)>FMaxPacketSize THEN
      RAISE EIPCError.CreateFmt('IPC packet is too large: %d bytes',[UInt64(LENGTH(Data))+SizeOf(ErrorCode)]);
    PacketLength:=SizeOf(ErrorCode)+Cardinal(LENGTH(Data));
    SetLength(Payload,PacketLength);
    Move(ErrorCode,Payload[0],SizeOf(ErrorCode));
    IF LENGTH(Data)>0 THEN Move(Data[0],Payload[SizeOf(ErrorCode)],LENGTH(Data));
    CRC:=IPCCRC32(Payload);
    IF NOT WriteExact(@PacketLength,SizeOf(PacketLength)) THEN EXIT;
    IF NOT WriteExact(@Payload[0],PacketLength) THEN EXIT;
    IF NOT WriteExact(@CRC,SizeOf(CRC)) THEN EXIT;
    Result:=TRUE
  END;

{$IF NOT DECLARED(CRC32) }
INITIALIZATION
  InitializeCRC32;
{$ENDIF }

END.
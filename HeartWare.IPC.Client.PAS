{ ========================================================================== }
{                                                                            }
{  HeartWare.IPC.Client                                                      }
{                                                                            }
{  HeartWare.IPC is FreeWare. See README.MD for licensing and usage terms.   }
{                                                                            }
{  Synchronous client side of HeartWare.IPC. TIPCClient connects to the      }
{  SID-qualified local named pipe, sends one TBytes command, and waits for   }
{  one TBytes response.                                                      }
{                                                                            }
{  Connection API                                                            }
{  - Connect defaults to a 500 ms timeout and returns BOOLEAN.               }
{  - Timeout=0 is immediate; INFINITE waits while a busy pipe exists.        }
{  - Disconnect closes the pipe handle.                                      }
{  - Connected reports local handle state, not a round-trip health           }
{    test.                                                                   }
{  - ServerRunning probes for the server without taking its pipe slot.       }
{                                                                            }
{  Command API                                                               }
{  - Execute sends requests with protocol ErrorCode=0.                       }
{  - A successful response returns its TBytes payload directly.              }
{  - A non-zero remote ErrorCode raises EIPCRemoteError.                     }
{  - CRC/framing failures disconnect because the stream is                   }
{    untrustworthy.                                                          }
{                                                                            }
{  Naming                                                                    }
{  - BaseName is the caller-supplied application pipe name.                  }
{  - PipeName is the full local SID-qualified Windows named-pipe path.       }
{                                                                            }
{ ========================================================================== }
UNIT HeartWare.IPC.Client;

INTERFACE

USES
  WinAPI.Windows,
  System.SysUtils,
  HeartWare.IPC.Common;

TYPE
  EIPCError     = HeartWare.IPC.Common.EIPCError;
  EIPCCodedError= HeartWare.IPC.Common.EIPCCodedError;
  TIPCClient    = CLASS(TIPCTransport)
                  PRIVATE
                    FBaseName   : STRING;
                    FPipeName   : STRING;
                  PUBLIC
                    CONSTRUCTOR Create(CONST BaseName : STRING);
                    DESTRUCTOR  Destroy; OVERRIDE;
                  PUBLIC
                    FUNCTION    Connect(Timeout : DWORD = 500) : BOOLEAN;
                    PROCEDURE   Disconnect;
                    FUNCTION    Execute(CONST Command : TBytes) : TBytes;
                    FUNCTION Connected : BOOLEAN;
                  PUBLIC
                    CLASS FUNCTION ServerRunning(CONST BaseName : STRING) : BOOLEAN; static;
                    PROPERTY    BaseName : String Read FBaseName;
                    PROPERTY    PipeName : String Read FPipeName;
                  END;

IMPLEMENTATION

{ ========================================================================== }
{                                                                            }
{  TIPCClient                                                                }
{                                                                            }
{ ========================================================================== }

CONSTRUCTOR TIPCClient.Create(CONST BaseName : STRING);
  BEGIN
    INHERITED Create;
    FBaseName:=BaseName; FPipeName:=IPCPipeName(BaseName)
  END;

DESTRUCTOR TIPCClient.Destroy;
  BEGIN
    Disconnect;
    INHERITED
  END;

FUNCTION TIPCClient.Connected : BOOLEAN;
  BEGIN
    Result:=(FPipe<>INVALID_HANDLE_VALUE)
  END;

{ -------------------------------------------------------------------------- }
{  ServerRunning                                                             }
{ -------------------------------------------------------------------------- }

CLASS FUNCTION TIPCClient.ServerRunning(CONST BaseName : STRING) : BOOLEAN;
  VAR
    Name        : STRING;
    Error       : DWORD;

  BEGIN
    Name:=IPCPipeName(BaseName);
    {
      Do not actually connect merely to determine whether the server
      exists.

      If the server's single pipe instance is occupied, WaitNamedPipe
      will time out rather than report FILE_NOT_FOUND, which still tells
      us the server exists.
    }
    Result:=WaitNamedPipe(PChar(Name),1);
    IF NOT Result THEN BEGIN
      Error:=GetLastError;
      CASE Error OF
        ERROR_SEM_TIMEOUT,ERROR_PIPE_BUSY               : Result:=TRUE;
        ERROR_FILE_NOT_FOUND,ERROR_PATH_NOT_FOUND       : Result:=FALSE;
      ELSE // OTHERWISE //
        RaiseLastOSError(Error)
      END
    END
  END;

{ -------------------------------------------------------------------------- }
{  Connect                                                                   }
{ -------------------------------------------------------------------------- }

FUNCTION TIPCClient.Connect(Timeout : DWORD) : BOOLEAN;
  VAR
    StartTime   : UInt64;
    Elapsed     : UInt64;
    Remaining   : DWORD;
    Error       : DWORD;

  BEGIN
    IF Connected THEN EXIT(TRUE);
    StartTime:=GetTickCount64;
    REPEAT
      FPipe:=CreateFile(PChar(FPipeName),GENERIC_READ OR GENERIC_WRITE,0,NIL,OPEN_EXISTING,0,0);
      IF FPipe<>INVALID_HANDLE_VALUE THEN EXIT(TRUE);
      Error:=GetLastError;
      CASE Error OF
        ERROR_FILE_NOT_FOUND,ERROR_PATH_NOT_FOUND:
          {
            No server currently owns the pipe.
          }
          EXIT(FALSE);
        ERROR_PIPE_BUSY:
          BEGIN
            IF Timeout=0 THEN EXIT(FALSE);
            IF Timeout=INFINITE THEN
              Remaining:=NMPWAIT_WAIT_FOREVER
            ELSE BEGIN
              Elapsed:=GetTickCount64-StartTime;
              IF Elapsed>=Timeout THEN EXIT(FALSE);
              Remaining:=Timeout-DWORD(Elapsed)
            END;
            IF NOT WaitNamedPipe(PChar(FPipeName),Remaining) THEN BEGIN
              Error:=GetLastError;
              CASE Error OF
                ERROR_SEM_TIMEOUT:
                  EXIT(FALSE);
                ERROR_FILE_NOT_FOUND,
                ERROR_PATH_NOT_FOUND:
                  EXIT(FALSE);
              ELSE // ITHERWISE //
                RaiseLastOSError(Error)
              END
            END
          END
      ELSE // OTHERWISE //
        RaiseLastOSError(Error)
      END
      {
        WaitNamedPipe says an instance became available.

        Another process could theoretically grab it before this client,
        so retry CreateFile rather than assuming success.
      }
    UNTIL FALSE
  END;

{ -------------------------------------------------------------------------- }
{  Disconnect                                                                }
{ -------------------------------------------------------------------------- }

PROCEDURE TIPCClient.Disconnect;
  BEGIN
    ClosePipe
  END;

{ -------------------------------------------------------------------------- }
{  Execute                                                                   }
{ -------------------------------------------------------------------------- }

FUNCTION TIPCClient.Execute(CONST Command : TBytes) : TBytes;
  VAR
    ErrorCode   : INTEGER;
    ErrorData   : TBytes;

  BEGIN
    IF NOT Connected THEN RAISE EIPCError.Create('IPC client is not connected');
    {
      Requests use the same packet format as responses but always send
      ErrorCode=0.
    }
    IF NOT Write(0,Command) THEN BEGIN
      Disconnect;
      RAISE EIPCError.Create('IPC server disconnected while sending command')
    END;
    TRY
      IF NOT Read(ErrorCode,Result) THEN BEGIN
        Disconnect;
        RAISE EIPCError.Create('IPC server disconnected before returning a response')
      END
    EXCEPT
      {
        A CRC/framing failure makes the stream untrustworthy.

        Discard the connection rather than attempting another command
        on it.
      }
      Disconnect;
      RAISE
    END;
    {
      The general client consumes the protocol ErrorCode.

      Application code calling Execute therefore sees either:
          TBytes result
      or:
          EIPCRemoteError
    }

    IF ErrorCode<>0 THEN BEGIN
      ErrorData:=COPY(Result);
      SetLength(Result,0);
      RAISE EIPCRemoteError.Create(ErrorCode,ErrorData)
    END
  END;

END.
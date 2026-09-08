{ ========================================================================== }
{                                                                            }
{  HeartWare.IPC.Server                                                      }
{                                                                            }
{  HeartWare.IPC is FreeWare. See README.MD for licensing and usage terms.   }
{                                                                            }
{  Server side of HeartWare.IPC. TIPCServer owns one Windows named-pipe      }
{  instance and services one connected client at a time.                     }
{                                                                            }
{  Applications derive from TIPCSession to execute commands and from         }
{  TIPCServer to create the per-connection session object.                   }
{                                                                            }
{  Application API                                                           }
{  - Override TIPCSession.Execute to process one TBytes command.             }
{  - Override TIPCServer.CreateSession to create a session instance.         }
{  - Create the server with the base pipe name; destruction stops it.        }
{  - The server owns and frees the TIPCSession it creates.                   }
{                                                                            }
{  Threading model                                                           }
{  - A worker thread performs blocking named-pipe I/O.                       }
{  - CreateSession and TIPCSession.Execute run on the main thread.           }
{  - Normal session destruction is also synchronized to the main             }
{    thread.                                                                 }
{  - Long-running Execute methods can therefore block GUI processing.        }
{                                                                            }
{  Session and error behavior                                                }
{  - A session is created on the first valid command, not on connect.        }
{  - The session remains alive until that client disconnects.                }
{  - Raise EIPCReplyError for a deliberate application error response.       }
{  - Other exceptions become IPC_ERROR_EXCEPTION with UTF-8 text.            }
{  - Bad framing or CRC drops the client but leaves the server running.      }
{                                                                            }
{  Pipe security                                                             }
{  - Remote clients are rejected.                                            }
{  - Access is granted to the current logon SID and SYSTEM.                  }
{  - A medium integrity label permits normal/elevated same-logon IPC.        }
{                                                                            }
{ ========================================================================== }
UNIT HeartWare.IPC.Server;

INTERFACE

USES
  WinAPI.Windows,
  System.SysUtils, System.Classes,
  HeartWare.IPC.Common;

TYPE
  EIPCError             = HeartWare.IPC.Common.EIPCError;
  EIPCCodedError        = HeartWare.IPC.Common.EIPCCodedError;
  TIPCSession           = CLASS ABSTRACT
                          PUBLIC
                            FUNCTION Execute(CONST Command : TBytes) : TBytes; VIRTUAL; ABSTRACT;
                          END;
  TIPCServer            = CLASS ABSTRACT(TIPCTransport)
                          PRIVATE TYPE
                            TThread		   = CLASS(System.Classes.TThread);
                          PRIVATE
                            FBaseName      : String;
                            FPipeName      : String;
                            FThread        : TThread;
                            FThreadStarted : BOOLEAN;
                            FSession       : TIPCSession;
                          PRIVATE
                            FUNCTION       CreatePipe : THandle;
                            PROCEDURE      ServerLoop;
                            PROCEDURE      ExecuteCommand(CONST Command : TBytes ; OUT ErrorCode : Integer ; OUT Response : TBytes);
                            PROCEDURE      DestroySession;
                          PROTECTED
                            FUNCTION      CreateSession : TIPCSession; VIRTUAL; ABSTRACT;
                          PUBLIC
                            CONSTRUCTOR   Create(CONST BaseName : String);
                            PROCEDURE     AfterConstruction; OVERRIDE;
                            DESTRUCTOR    Destroy; OVERRIDE;
                          PUBLIC
                            PROPERTY BaseName : String Read FBaseName;
                            PROPERTY PipeName : String Read FPipeName;
                          END;

IMPLEMENTATION

CONST
  IPCPipeInBufferSize           = 65536;
  IPCPipeOutBufferSize          = 65536;
  {
    PIPE_REJECT_REMOTE_CLIENTS.

    Declared locally to avoid depending upon a particular Windows SDK
    declaration.
  }
  IPCPipeRejectRemoteClients    = $00000008;

{ ========================================================================== }
{                                                                            }
{  TIPCServer                                                                }
{                                                                            }
{ ========================================================================== }

CONSTRUCTOR TIPCServer.Create(CONST BaseName : String);
  BEGIN
    INHERITED Create;
    FBaseName:=BaseName;
    FPipeName:=IPCPipeName(BaseName);
    FThread:=NIL;
    FThreadStarted:=FALSE;
    FSession:=NIL;
    FPipe:=CreatePipe;
    {
      CreateAnonymousThread creates the worker suspended.

      Starting it in AfterConstruction prevents CreateSession from
      being called before a descendant server has completed its own
      construction.
    }
    FThread:=TThread(TThread.CreateAnonymousThread(PROCEDURE
                                                     BEGIN
                                                       ServerLoop
                                                     END));
    FThread.FreeOnTerminate:=FALSE
  END;

PROCEDURE TIPCServer.AfterConstruction;
  BEGIN
    INHERITED;
    IF Assigned(FThread) THEN BEGIN
      FThreadStarted:=TRUE;
      FThread.Start
    END
  END;

DESTRUCTOR TIPCServer.Destroy;
  BEGIN
    IF Assigned(FThread) THEN BEGIN
      FThread.Terminate;
      IF FThreadStarted THEN
        CancelSynchronousIo(FThread.Handle)
      ELSE BEGIN
        {
          Construction failed before AfterConstruction.

          Let the terminated worker start and immediately leave its
          server loop.
        }
        FThreadStarted:=TRUE;
        FThread.Start
      END;
      FThread.WaitFor;
      FreeAndNIL(FThread)
    END;
    {
      On ordinary disconnection DestroySession has already freed this
      on the main thread.

      During server destruction it is deliberately left for the
      destructor after the worker has stopped.
    }
    FreeAndNIL(FSession);
    INHERITED
  END;

{ -------------------------------------------------------------------------- }
{  CreatePipe                                                                }
{ -------------------------------------------------------------------------- }

FUNCTION TIPCServer.CreatePipe : THandle;
  VAR
    SecurityDescriptor  : PSECURITY_DESCRIPTOR;
    SecurityAttributes  : TSecurityAttributes;
    SDDL                : String;

  BEGIN
    {
      Permit this Windows logon session and SYSTEM.

      The Medium mandatory integrity label means a normal user process
      can communicate with an elevated instance belonging to the same
      logon session.
    }
    SDDL:='D:P'+
          '(A;;GA;;;'+IPCLogonSID+')'+
          '(A;;GA;;;SY)'+
          'S:(ML;;NW;;;ME)';
    SecurityDescriptor:=NIL;
    IF NOT ConvertStringSecurityDescriptorToSecurityDescriptor(PChar(SDDL),SDDL_REVISION_1,SecurityDescriptor,NIL) THEN RaiseLastOSError;

    TRY
      FillChar(SecurityAttributes,SizeOf(TSecurityAttributes),0);
      SecurityAttributes.nLength:=SizeOf(TSecurityAttributes);
      SecurityAttributes.lpSecurityDescriptor:=SecurityDescriptor;
      SecurityAttributes.bInheritHandle:=FALSE;
      Result:=CreateNamedPipe(PChar(FPipeName),PIPE_ACCESS_DUPLEX,PIPE_TYPE_BYTE OR PIPE_READMODE_BYTE OR PIPE_WAIT OR IPCPipeRejectRemoteClients,1,IPCPipeOutBufferSize,IPCPipeInBufferSize,0,@SecurityAttributes);
      IF Result=INVALID_HANDLE_VALUE THEN RaiseLastOSError
    FINALLY
      LocalFree(HLOCAL(SecurityDescriptor))
    END
  END;


{ -------------------------------------------------------------------------- }
{  ServerLoop                                                                }
{ -------------------------------------------------------------------------- }

PROCEDURE TIPCServer.ServerLoop;
  VAR
    Connected           : BOOLEAN;
    Error               : DWORD;
    RequestError        : Integer;
    ResponseError       : Integer;
    Command             : TBytes;
    Response            : TBytes;

  BEGIN
    WHILE NOT FThread.Terminated DO BEGIN
      Connected:=ConnectNamedPipe(FPipe,NIL);
      IF NOT Connected THEN BEGIN
        Error:=GetLastError;
        CASE Error OF
          ERROR_OPERATION_ABORTED:
            IF FThread.Terminated THEN EXIT;
          ERROR_PIPE_CONNECTED:
            {
              The client connected after CreateNamedPipe but before
              ConnectNamedPipe.

              This is success, despite the API returning FALSE.
            }
            Connected:=TRUE;
        ELSE // OTHERWISE //
          RaiseLastOSError(Error)
        END
      END;

      IF NOT Connected THEN CONTINUE;

      TRY
        TRY
          WHILE NOT FThread.Terminated DO BEGIN
            IF NOT Read(RequestError,Command) THEN BREAK;
            {
              Client requests always have ErrorCode=0.

              Using the identical packet format in both directions lets
              all actual transport logic remain in TIPCTransport.
            }
            IF RequestError=0 THEN
              ExecuteCommand(Command,ResponseError,Response)
            ELSE BEGIN
              Response:=IPCUTF8Encode('IPC request contains a non-zero ErrorCode');
              ResponseError:=RequestError
            END;
            IF NOT Write(ResponseError,Response) THEN BREAK
          END
        EXCEPT
          {
            A bad frame, truncated frame or CRC failure invalidates the
            current connection.

            Drop that client, but keep the IPC server itself alive for
            subsequent clients.
          }
          ON E:EIPCError DO // NOTHING //
        END
      FINALLY
        IF NOT FThread.Terminated THEN DestroySession;
        DisconnectNamedPipe(FPipe)
      END
    END
  END;

{ -------------------------------------------------------------------------- }
{  ExecuteCommand                                                            }
{ -------------------------------------------------------------------------- }

PROCEDURE TIPCServer.ExecuteCommand(CONST Command : TBytes ; OUT ErrorCode : Integer ; OUT Response  : TBytes);
  BEGIN
    ErrorCode:=0;
    SetLength(Response,0);
    {
      The session and Parse both live on the application's main thread.

      Synchronize intentionally blocks the worker until Parse has
      produced the response.

      Since OUT parameters can't be captured, we address them via
      a local pointer variable (which CAN be captured) instead

      There are no issues, since the destination variables will
      remain alive as long as this method executes, due to the
      blocking nature of TThread.Synchronize
    }

    VAR Error : PInteger := @ErrorCode;
    VAR Data : PBytes := @Response;

    TThread.Synchronize(FThread,PROCEDURE
                                  BEGIN
                                    TRY
                                      {
                                        Merely opening the pipe does not create a logical session.

                                        It begins when the first valid command packet arrives.
                                      }
                                      IF NOT Assigned(FSession) THEN BEGIN
                                        FSession:=CreateSession;
                                        IF NOT Assigned(FSession) THEN
                                          RAISE EIPCError.Create('CreateSession returned NIL')
                                      END;

                                      Data^:=FSession.Execute(Command);
                                      Error^:=0
                                    EXCEPT
                                      {
                                        An application may deliberately return a particular
                                        non-zero error code by raising EIPCReplyError.
                                      }
                                      ON E:EIPCReplyError DO BEGIN
                                        Error^:=E.ErrorCode;
                                        IF Error^=0 THEN
                                          Error^:=IPC_ERROR_EXCEPTION;

                                        Data^:=COPY(E.Data,0,LENGTH(E.Data))
                                      END;
                                      {
                                        Any ordinary unexpected exception is returned using the
                                        reserved general error number and its UTF-8 message.
                                      }
                                      ON E:Exception DO BEGIN
                                        Error^:=IPC_ERROR_EXCEPTION;
                                        Data^:=IPCUTF8Encode(E.Message)
                                      END
                                    END
      END
    )
  END;

{ -------------------------------------------------------------------------- }
{  DestroySession                                                            }
{ -------------------------------------------------------------------------- }

PROCEDURE TIPCServer.DestroySession;
  BEGIN
    IF Assigned(FSession) THEN
      TThread.Synchronize(FThread,PROCEDURE
                                    BEGIN
                                      FreeAndNIL(FSession)
                                    END)
  END;

END.
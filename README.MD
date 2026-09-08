Copyright © 2026 HeartWare. All rights reserved.

These UNITs are released under the **HeartWare FreeWare License**.

You may freely use, copy, modify, and redistribute this software and its
source code for private, hobby, educational, and other non-commercial
purposes.

You may not use, sell, distribute, include, publish, bundle, or otherwise
make this software, or any modified or derivative version of it, available
in any commercial context without prior permission from HeartWare. This
includes direct or indirect commercial use or distribution, including paid
download sites, subscription services, commercial software collections,
magazines, books, paid media, or products or services for which money is
charged.

If you redistribute a modified or derivative version, it must be released
under this **exact same license**. You may neither add nor remove
permissions, restrictions, or licensing terms.

The copyright notice and this license must remain with all redistributed
copies and derivative versions.

**Commercial use requires separate permission from HeartWare.**

The software is provided "as is", without warranty of any kind.

If you are not completely satisfied, return it to where you obtained it for
a full monetary refund of the price you paid for it.

# HeartWare.IPC

HeartWare.IPC is a small, Windows-only Delphi inter-process communication
library built on Windows named pipes. It provides a synchronous binary
request/response transport without imposing JSON, text, or any other
application-level data format.

The transport works entirely with `TBytes`. Applications may therefore send
arbitrary binary data directly, or layer their own encoding, serialization,
JSON, protocol buffers, text format, or command structure on top.

## Units

- `HeartWare.IPC.Common` contains packet framing, CRC32 validation, UTF-8
  helpers, pipe-name generation, the common transport class, and the IPC
  exception types.
- `HeartWare.IPC.Server` implements the named-pipe server, connection/session
  lifetime, worker-thread I/O, and main-thread execution of application
  commands.
- `HeartWare.IPC.Client` implements synchronous connection management, server
  presence detection, command execution, and conversion of remote error
  responses into exceptions.

## Design goals

- Use `TBytes` as the transport type so the IPC layer is not tied to JSON or
  any other serialization format.
- Keep packet framing and integrity checking in one common transport class
  shared by both client and server.
- Distinguish transport failures from application-level remote errors.
- Restrict the named pipe to the local machine and the current Windows logon
  session while still allowing normal and elevated processes in that logon
  session to communicate.

## Requirements

- Windows. The implementation uses Windows named pipes, access tokens, SIDs,
  security descriptors, and synchronous Win32 file I/O.
- A modern Delphi compiler with the standard RTL and Windows API units used by
  the source.
- No third-party library is required for the standalone build.
- If the `HW` conditional symbol is defined, then UNITs will use the
  `HeartWare.CRC`, UNIT and its `CRC32` will be used. Otherwise
  `HeartWare.IPC.Common` supplies its own CRC32 code.

## Quick start

The server is implemented by deriving one class from `TIPCSession` and one
from `TIPCServer`. The session receives binary commands and returns binary
responses.

```pascal
TYPE
  TMySession = CLASS(TIPCSession)
  PUBLIC
    FUNCTION Execute(CONST Command : TBytes) : TBytes; OVERRIDE;
  END;

  TMyServer = CLASS(TIPCServer)
  PROTECTED
    FUNCTION CreateSession : TIPCSession; OVERRIDE;
  END;

FUNCTION TMySession.Execute(CONST Command : TBytes) : TBytes;
  VAR
    S : STRING;
  BEGIN
    S:=IPCUTF8Decode(Command);
    IF S='PING' THEN
      Result:=IPCUTF8Encode('PONG')
    ELSE
      RAISE EIPCReplyError.Create(1,'Unknown command')
  END;

FUNCTION TMyServer.CreateSession : TIPCSession;
  BEGIN
    Result:=TMySession.Create
  END;
```

Creating the server starts its worker after construction has completed. The
server object must remain alive for as long as the service is required.

```pascal
Server:=TMyServer.Create('MyApplicationName');
TRY
  { Server is active here. }
FINALLY
  Server.Free
END;
```

A client uses the same base name. `Connect` returns `FALSE` if the server is
not available or the timeout expires.

```pascal
Client:=TIPCClient.Create('MyApplicationName');
TRY
  IF NOT Client.Connect THEN
    RAISE Exception.Create('IPC server is not available');

  TRY
    Reply:=Client.Execute(IPCUTF8Encode('PING'));
    S:=IPCUTF8Decode(Reply)
  EXCEPT
    ON E:EIPCRemoteError DO
      ShowMessage(Format('Remote error %d: %s',
                         [E.ErrorCode,E.Message]))
  END
FINALLY
  Client.Free
END;
```

## Wire format

Requests and responses use the same binary packet format. A request always
sets `ErrorCode` to zero.

```text
DWORD Length
LONG  ErrorCode
BYTE  Data[Length - 4]
DWORD CRC32
```

- `Length` is the number of bytes occupied by `ErrorCode` plus `Data`. It does
  not include the `Length` field itself or the trailing CRC32.
- `CRC32` is calculated over the complete payload consisting of `ErrorCode`
  followed by `Data`.
- The fields are written directly as native Windows 32-bit values. On
  supported Windows targets this means little-endian byte order.
- The default maximum value accepted for `Length` is 256 Mb. This can be
  changed through `TIPCTransport.MaxPacketSize`.
- A clean disconnect is valid only between complete packets. A truncated
  packet or CRC mismatch raises `EIPCError` and invalidates the connection.

## Error handling

The packet `ErrorCode` separates a successful binary response from an
application-level error response.

- Zero means success.
- Positive values are available to applications.
- Negative values are reserved by HeartWare.IPC.
- `IPC_ERROR_EXCEPTION` is `-1` and represents an unexpected exception
  returned by the server.
- `IPC_ERROR_PROTOCOL` is `-2` and is reserved for protocol-level use.

Server-side application code may deliberately reject a command by raising
`EIPCReplyError`. Its error code and data are returned to the client. If the
exception contains error code zero, the server substitutes
`IPC_ERROR_EXCEPTION`.

Any other exception escaping `TIPCSession.Execute` is converted into
`IPC_ERROR_EXCEPTION`, with the exception message encoded as UTF-8 data.

`TIPCClient.Execute` returns only successful response data. Any non-zero
remote error code causes `EIPCRemoteError` to be raised.
`EIPCCodedError.ErrorCode` contains the numeric code, `Data` contains the
original binary error payload, and `Message` is the UTF-8-decoded form of that
payload.

## Connection and session model

- The server creates one named-pipe instance and therefore services one
  connected client at a time.
- Opening the pipe does not create a logical application session.
  `CreateSession` is called when the first valid command arrives.
- The same `TIPCSession` object remains associated with that client connection
  until the client disconnects.
- The server frees the session when the connection ends.
- The pipe worker thread performs blocking connection, read, and write I/O.
- `CreateSession`, `TIPCSession.Execute`, and normal session destruction are
  synchronized onto the application's main thread.

Because command execution occurs on the main thread, a long-running
`TIPCSession.Execute` implementation can block a GUI application's message
processing. Applications that perform expensive work should hand that work off
appropriately rather than performing it synchronously in `Execute`.

## Pipe naming and security

`IPCPipeName` constructs the actual Windows pipe name from the caller's base
name and the current Windows logon SID. A base name must not be empty and must
not contain a backslash.

```text
\\.\pipe\<BaseName>.<LogonSID>
```

- Remote named-pipe clients are rejected.
- The pipe security descriptor grants access to the current Windows logon
  session and to `SYSTEM`.
- A medium mandatory integrity label allows a normal process and an elevated
  process belonging to the same logon session to communicate.
- The framing protocol provides CRC32 corruption detection, not encryption or
  cryptographic authentication.

## `HeartWare.IPC.Common`

- `TIPCTransport` is the abstract common transport ancestor. It owns the pipe
  handle, complete-packet read/write logic, CRC checking, and packet-size
  limit.
- `MaxPacketSize` defaults to `IPC_DEFAULT_MAX_PACKET_SIZE`, currently 256 Mb,
  and may not be set below the size of the 32-bit error code.
- `IPCCRC32` calculates the CRC32 used by the wire protocol.
- `IPCUTF8Encode` and `IPCUTF8Decode` provide optional string-to-byte helpers.
  They are conveniences only; the transport itself remains binary.
- `IPCLogonSID` returns the SID identifying the current Windows logon session.
- `IPCPipeName` converts an application base name into the actual pipe name.
- `EIPCError` represents IPC/transport failures.
- `EIPCCodedError` adds `ErrorCode` and binary `Data` to an IPC exception.
- `EIPCReplyError` is the server-side deliberate error-response exception.
- `EIPCRemoteError` is raised client-side for non-zero server responses.

## `HeartWare.IPC.Server`

- Derive a session class from `TIPCSession` and override
  `Execute(const Command: TBytes): TBytes`.
- Derive a server class from `TIPCServer` and override `CreateSession`.
- `TIPCServer.Create` accepts the application pipe base name.
- `BaseName` exposes the caller-supplied name and `PipeName` exposes the full
  SID-qualified Windows pipe name.
- The server owns each session returned by `CreateSession` and frees it when
  the client connection ends.

## `HeartWare.IPC.Client`

- `TIPCClient.Create` accepts the same base name used by the server.
- `Connect` has a default timeout of 500 ms. A timeout of zero performs an
  immediate attempt; `INFINITE` waits indefinitely while a server exists but
  its pipe is busy.
- `Disconnect` closes the local pipe handle.
- `Connected` reports whether the client currently owns a pipe handle. It is
  not an active round-trip health check.
- `Execute` synchronously sends one binary command and waits for one binary
  response.
- `ServerRunning` probes for the named pipe without taking ownership of the
  server's single connection slot.
- `BaseName` and `PipeName` expose the logical and full pipe names.

## Notes for application protocol designers

- HeartWare.IPC deliberately does not define command identifiers, request
  objects, JSON schemas, version negotiation, or application serialization.
- If commands can evolve independently between client and server, include an
  application protocol version or compatible command-level versioning in your
  own `TBytes` payload.
- Use positive remote error codes for stable application-level errors and
  reserve ordinary exceptions for unexpected failures.
- Do not treat CRC32 as a security mechanism. Its purpose here is detecting
  corruption or framing errors.

## License

HeartWare.IPC is distributed under the HeartWare FreeWare License stated
at the beginning of this README. Non-commercial use, modification, and
redistribution are permitted under those terms. Commercial use requires
separate permission from HeartWare.

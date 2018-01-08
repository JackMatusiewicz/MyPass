namespace MyPass

open System.IO

module Streams =

    type LeaveOpenStream(underlying : Stream) =
        inherit Stream()
        let underlyingStream = underlying

        override __.Flush() = underlyingStream.Flush()

        override __.Seek(offset, origin) = underlyingStream.Seek(offset, origin)

        override __.SetLength(value) = underlyingStream.SetLength(value)

        override __.Read(buffer, offset, count) = underlyingStream.Read(buffer, offset, count)

        override __.Write(buffer, offset, count) = underlyingStream.Write(buffer, offset, count)

        override __.Close() = ()

        override __.CanRead = underlyingStream.CanRead
        override __.CanSeek = underlyingStream.CanSeek
        override __.CanWrite = underlyingStream.CanWrite
        override __.Length = underlyingStream.Length

        override __.Position
            with get() = underlyingStream.Position
            and set value = underlyingStream.Position <- value
    
        interface System.IDisposable with
            member __.Dispose() = ()

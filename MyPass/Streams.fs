module Streams

open System.IO

type LeaveOpenStream(underlying : Stream) =
    inherit Stream()
    let underlyingStream = underlying

    override this.Flush() = underlyingStream.Flush()

    override this.Seek(offset, origin) = underlyingStream.Seek(offset, origin)

    override this.SetLength(value) = underlyingStream.SetLength(value)

    override this.Read(buffer, offset, count) = underlyingStream.Read(buffer, offset, count)

    override this.Write(buffer, offset, count) = underlyingStream.Write(buffer, offset, count)

    override this.Close() = ()

    override this.CanRead = underlyingStream.CanRead
    override this.CanSeek = underlyingStream.CanSeek
    override this.CanWrite = underlyingStream.CanWrite
    override this.Length = underlyingStream.Length

    override this.Position
        with get() = underlyingStream.Position
        and set value = underlyingStream.Position <- value
    
    interface System.IDisposable with
        member this.Dispose() = ()

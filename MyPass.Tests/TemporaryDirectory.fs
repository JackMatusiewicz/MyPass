namespace MyPass.Tests
open System
open System.IO

type TemporaryDirectory (path : string) =
    let dir = Directory.CreateDirectory (path)

    interface IDisposable with
        member __.Dispose () =
            Directory.Delete (path, true)
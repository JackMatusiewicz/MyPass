namespace MyPass

open System.IO
open System.IO.Abstractions

[<Struct>]
type FileKey = FileKey of string

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module FileKey =

    // Whilst we generate a random password from this set,
    // a user can provide their own custom fileKey, if they choose
    let availableCharacters = ['a' .. 'z'] @ ['A' .. 'Z'] @ ['0' .. '9'] |> Array.ofList

    let generateFileKey () : FileKey =
        Password.createWithCharacters 16u availableCharacters
        |> FileKey

    let read (fs : IFileSystem) (path : string) : Result<string, FileKey> =
        try
            path
            |> fs.File.ReadAllText
            |> FileKey
            |> Success
        with
        | ex ->
            ex.Message |> Failure

    let toBytes (FileKey fk) =
        System.Text.Encoding.UTF8.GetBytes fk

    let getKey (FileKey fk) = fk
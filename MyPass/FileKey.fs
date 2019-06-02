namespace MyPass

open System.IO.Abstractions
open MyPass.SecureString

[<Struct>]
type FileKey = internal FileKey of string

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module FileKey =

    // Whilst we generate a random password from this set,
    // a user can provide their own custom fileKey, if they choose
    let availableCharacters = ['a' .. 'z'] @ ['A' .. 'Z'] @ ['0' .. '9'] |> Array.ofList

    let generateFileKey () : FileKey =
        Password.createWithCharacters 16u availableCharacters
        |> fun p -> SecurePasswordHandler.Use (p, fun p -> p |> String.fromBytes |> FileKey)

    let read
        (fs : IFileSystem)
        (path : string)
        : Result<FailReason, FileKey> =
        try
            path
            |> fs.File.ReadAllText
            |> FileKey
            |> Success
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    let toBytes (FileKey fk) =
        String.toBytes fk

    let getKey (FileKey fk) = fk
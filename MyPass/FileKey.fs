namespace MyPass

open System.IO

type FileKey = FileKey of string

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module FileKey =

    // Whilst we generate a random password from this set,
    // a user can provide their own custom fileKey, if they choose
    let private availableCharacters = ['a' .. 'z'] @ ['A' .. 'Z'] @ ['0' .. '9'] |> Array.ofList

    let generateFileKey () : FileKey =
        Password.createWithCharacters availableCharacters 16u
        |> FileKey

    let read (path : string) : FileKey =
        path |> File.ReadAllText
             |> FileKey

    let toBytes (FileKey fk) =
        System.Text.Encoding.UTF8.GetBytes fk

    let getKey (FileKey fk) = fk
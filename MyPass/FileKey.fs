namespace MyPass

open System.Security.Cryptography

type FileKey = FileKey of string

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module FileKey =

    let availableCharacters = ['a' .. 'z'] @ ['A' .. 'Z'] @ ['0' .. '9'] |> Array.ofList

    let generateFileKey () : FileKey = Password.createWithCharacters availableCharacters 16u
                                       |> FileKey
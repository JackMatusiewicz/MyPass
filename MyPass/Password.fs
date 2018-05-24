﻿namespace MyPass

open System
open System.Security.Cryptography

[<RequireQualifiedAccess>]
module Password =

    let availableCharacters =
        ['a'..'z'] @ ['A'..'Z'] @ ['0'..'9'] @ ['!'; '?'; '_'] |> Array.ofList

    let createWithCharacters (length : uint32) (availableCharacters : char[]) =
        use rng = new RNGCryptoServiceProvider()
        let randomBytes = Array.create 4 (byte 0)

        let findIndex (len : int) =
            let rec findLargerPowerOfTwo len (acc : int) =
                match acc > len with
                | true -> acc
                | false -> findLargerPowerOfTwo len (acc <<< 1)

            let poolSize = findLargerPowerOfTwo len 1

            let rec calculate () =
                rng.GetBytes(randomBytes)
                let randomInt = BitConverter.ToInt32(randomBytes, 0)
                let index = (randomInt &&& (~~~(1 <<< 31))) % poolSize
                match index < len with
                | true -> index
                | false -> calculate ()

            calculate ()

        let rec create (acc : char list) (current : uint32) =
            match current with
            | _ when current = length -> acc |> String.ofList
            | _ ->
                let index = findIndex (availableCharacters.Length)
                create (availableCharacters.[index] :: acc) (current + 1u)
        create [] 0u

    let createPassword = fun len -> createWithCharacters len availableCharacters

    ///Uses the default set, along with any extra you pass in.
    let createWithExtraCharacters (chars : char[]) =
        fun len ->
            chars
            |> fun c -> Array.concat [|chars; availableCharacters|]
            |> Array.distinct
            |> createWithCharacters len

    let private xor (keyOne : byte[]) (keyTwo : byte[]) =
        keyOne
        |> Array.zip keyTwo
        |> Array.map (fun (a,b) -> a ^^^ b)

    let createMasterPassword
        (versionId : string)
        (masterPassphrase : string)
        (secretKey : byte[])
        (userId : string)
        =
        let userIdBytes = userId |> System.Text.Encoding.UTF8.GetBytes
        let versionIdBytes = versionId |> System.Text.Encoding.UTF8.GetBytes
        let expandedSalt = Hkdf.expand userIdBytes versionIdBytes [||] 32
        let pbkdf2 = new Rfc2898DeriveBytes(masterPassphrase, expandedSalt, 10000)
        let masterKey = pbkdf2.GetBytes(32)
    
        Hkdf.expand secretKey userIdBytes [||] (masterKey.Length)
        |> xor masterKey
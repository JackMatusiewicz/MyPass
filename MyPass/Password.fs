namespace MyPass

open System
open System.Security.Cryptography
open System.Security
open Microsoft.AspNetCore.Cryptography.KeyDerivation;

open MyPass.SecureString

[<RequireQualifiedAccess>]
module Password =

    let alphanumericCharacters =
        ['a'..'z'] @ ['A'..'Z'] @ ['0'..'9'] |> Array.ofList

    //TODO: Now that this uses a secure string, we need to dispose!
    let createWithCharacters (length : uint32) (availableCharacters : char[]) : SecureString =
        use rng = new RNGCryptoServiceProvider()
        let randomBytes = Array.create 4 (byte 0)
        let pw = new SecureString ()

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
            | _ when current = length -> acc
            | _ ->
                let index = findIndex (availableCharacters.Length)
                create (availableCharacters.[index] :: acc) (current + 1u)
        create [] 0u
        |> List.iter (pw.AppendChar)
        pw

    let createPassword = fun len -> createWithCharacters len alphanumericCharacters

    ///Uses the default set, along with any extra you pass in.
    let createWithExtraCharacters (chars : char[]) =
        fun len ->
            chars
            |> fun c -> Array.concat [|c; alphanumericCharacters|]
            |> Array.distinct
            |> createWithCharacters len

    let private xor (keyOne : byte[]) (keyTwo : byte[]) =
        keyOne
        |> Array.zip keyTwo
        |> Array.map (fun (a,b) -> a ^^^ b)

    // TODO - look at moving elsewhere.
    // TODO - look at making the AesKey constructor validate the bytes.
    let createMasterKey
        (versionId : string)
        (secretKey : byte[])
        (userId : string)
        (masterPassphrase : SecureString)
        : AesKey
        =
        let getKey (salt : byte[]) (passwordBytes : byte[]) =
            KeyDerivation.Pbkdf2(
                String.fromBytes passwordBytes,
                salt,
                KeyDerivationPrf.HMACSHA512,
                100000,
                Aes.keySizeBytes)

        let userIdBytes = userId |> System.Text.Encoding.UTF8.GetBytes
        let versionIdBytes = versionId |> System.Text.Encoding.UTF8.GetBytes
        let expandedSalt = Hkdf.expand userIdBytes versionIdBytes [||] 32
        let masterKey =
            SecurePasswordHandler.Use(masterPassphrase, System.Func<byte[], byte[]> (getKey expandedSalt))
    
        Hkdf.expand secretKey userIdBytes [||] (masterKey.Length)
        |> xor masterKey
        |> Aes.fromBytes
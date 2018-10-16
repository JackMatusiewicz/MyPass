namespace MyPass

open System.Security
open Microsoft.AspNetCore.Cryptography.KeyDerivation;
open MyPass.SecureString

[<RequireQualifiedAccess>]
module MasterKey =

    let private xor (keyOne : byte[]) (keyTwo : byte[]) =
        keyOne
        |> Array.zip keyTwo
        |> Array.map (fun (a,b) -> a ^^^ b)

    let make
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

        let userIdBytes = userId |> String.toBytes
        let versionIdBytes = versionId |> String.toBytes
        let expandedSalt = Hkdf.expand userIdBytes versionIdBytes [||] 32
        let masterKey =
            SecurePasswordHandler.Use(masterPassphrase, System.Func<byte[], byte[]> (getKey expandedSalt))
    
        Hkdf.expand secretKey userIdBytes [||] (masterKey.Length)
        |> xor masterKey
        |> Aes.fromBytes


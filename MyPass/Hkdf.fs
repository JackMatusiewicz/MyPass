namespace MyPass

open System.Security.Cryptography
open System

[<RequireQualifiedAccess>]
module Hkdf =

    let expand
        (initialKeyData : byte[])
        (salt : byte[])
        (info : byte[])
        (length : int) : byte[]
        =
        use hmac = new HMACSHA256(salt)
        let hmacKey = hmac.ComputeHash(initialKeyData)
        use hmac = new HMACSHA256(hmacKey)

        let rec expandKey
            (result : byte[])
            (previousResultBlock : byte[])
            (remainingBytes : int)
            (i : int)
            =
            match remainingBytes with
            | _ when remainingBytes <= 0 -> result
            | _ ->
                let newLength = (previousResultBlock.Length + info.Length + 1)
                let ci = Array.create newLength (byte 0)
                System.Array.Copy(
                    previousResultBlock,
                    0,
                    ci,
                    0,
                    previousResultBlock.Length)
                System.Array.Copy(
                    info,
                    0,
                    ci,
                    previousResultBlock.Length,
                    info.Length)
                ci.[ci.Length - 1] <- (byte i)

                let resultBlock = hmac.ComputeHash(ci);
                Array.Copy(
                    resultBlock,
                    0,
                    result,
                    length - remainingBytes,
                    Math.Min(remainingBytes, resultBlock.Length))
                let newRemaining = remainingBytes - resultBlock.Length
                expandKey result resultBlock newRemaining (i+1)

        let result = Array.create length (byte 0)
        let prev = Array.create 0 (byte 0)
        expandKey result prev length 1
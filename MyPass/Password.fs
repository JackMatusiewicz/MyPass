module Password

open System
open System.Security.Cryptography

let availableCharacters = ['a'..'z'] @ ['A'..'Z'] @ ['0'..'9'] @ ['!'; '?'; '_'] |> Array.ofList

let private charsToString (data : char[]) =
    new string(data)

let create (length : uint32) =
    use rng = new RNGCryptoServiceProvider()
    let randomBytes = Array.create 4 (byte 0)

    let rec create (acc : char list) (current : uint32) =
        match current with
        | _ when current = length -> acc |> Array.ofList |> charsToString
        | _ ->
            rng.GetBytes(randomBytes)
            let randomInt = BitConverter.ToInt32(randomBytes, 0)
            let index = (randomInt &&& (~~~(1 <<< 31))) % availableCharacters.Length
            create (availableCharacters.[index] :: acc) (current + 1u)
    create [] 0u
namespace MyPass

open System
open System.Security.Cryptography
open System.Security

[<RequireQualifiedAccess>]
module Password =

    let vowels =
        ['a'; 'e'; 'i'; 'o'; 'u']
        |> List.toArray

    let consonants =
        ['a' .. 'z']
        |> Set.ofList
        |> fun cons -> Set.difference cons (Set.ofArray vowels)
        |> Set.toArray

    let alphanumericCharacters =
        ['a' .. 'z'] @ ['A' .. 'Z'] @ ['0'..'9'] |> Array.ofList

    /// Picks a random element between [0, len)
    let private findIndex (len : int) =
        use rng = new RNGCryptoServiceProvider()
        let randomBytes = Array.create 4 (byte 0)

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

    // TODO: Now that this uses a secure string, we need to dispose!
    let createWithCharacters (length : uint32) (availableCharacters : char[]) : SecureString =
        let pw = new SecureString ()

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

    /// Uses the default set, along with any extra you pass in.
    let createWithExtraCharacters (chars : char[]) =
        fun len ->
            chars
            |> fun c -> Array.concat [|c; alphanumericCharacters|]
            |> Array.distinct
            |> createWithCharacters len

    /// Generates a password from lowercase consonant-vowel-consonant triplets
    /// The aim here is to make a more memorable password so you can, in theory,
    /// memorise it if you need to for a particular event where you can't access
    /// your password manager.
    let createMemorablePassword (length : uint32) =
        let largerMultipleOfThree (v : uint32) =
            let rem = v % 3u
            if rem = 0u then v else (v - rem + 3u)

        let constructTriplet () =
            let startCons = findIndex consonants.Length
            let vowel = findIndex vowels.Length
            let endCons = findIndex consonants.Length
            consonants.[startCons],
            vowels.[vowel],
            consonants.[endCons]

        let pw = new SecureString ()
        let newLength = largerMultipleOfThree length
        let numberOfTriples = newLength / 3u
        [0u .. (numberOfTriples - 1u)]
        |> List.map (fun _ -> constructTriplet ())
        |> List.iter
            (fun (a,b,c) ->
                pw.AppendChar a
                pw.AppendChar b
                pw.AppendChar c
                pw.AppendChar ' ')
        pw.RemoveAt (pw.Length - 1)
        pw
    
open Aes
open Password
open System.Text
open PasswordManager
open Result

let stupidTest () =
    let testKey = Aes.newKey ()
    let password = Password.create 12u
    let desc = BasicDescription ("Google", "Mainly for gmail")
    let entry = PasswordManager.createEntry desc password
    let store = {passwords = Map.empty}
    let updatedStore = PasswordManager.storePassword entry store
    let result = (updatedStore >>= (PasswordManager.encryptManager testKey))
                               >>= (PasswordManager.decryptManager testKey)
    match result with
    | Success manager -> 
        let entry = PasswordManager.getPassword "Google" manager
        let decryptedPassword = entry >>= (PasswordManager.decryptPassword)
        fmap (printfn "%s") decryptedPassword |> ignore
    | Failure f -> printfn "%s" f

[<EntryPoint>]
let main argv =
    let salt = Salt "testSalt"
    let pw = PassPhrase "password"
    let key = Aes.generateFromPassPhrase salt pw

    let data = Encoding.UTF8.GetBytes("Hot potato is hot. I wonder why this is? Who knows!");
    let encryptedBytes = Aes.encrypt key data
    let decryptedBytes = Aes.decrypt key encryptedBytes
    let resultString = Encoding.UTF8.GetString(decryptedBytes);

    stupidTest ()

    printfn "%s" resultString
    0

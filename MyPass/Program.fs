open Aes
open Password
open System.Text
open PasswordManager
open ManagerModes
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
    let mutable result = createPasswordStore ()
    fmap (printfn "%s") result |> ignore

    result <- addPassword ()
    fmap (printfn "%s") result |> ignore

    result <- showPassword ()
    fmap (printfn "%s") result |> ignore
    0

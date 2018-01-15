namespace MyPass

open Aes
open Password
open System.Text
open Vault
open ConsoleUi
open Result

module Main =

    [<EntryPoint>]
    let main _ =
        ConsoleUi.createNewVault ()
        ConsoleUi.addSecret ()
        ConsoleUi.listSecrets () |> ignore
        0

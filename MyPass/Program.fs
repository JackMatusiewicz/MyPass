namespace MyPass

open Aes
open Password
open System.Text
open Vault
open ManagerModes
open Result

module Main =

    [<EntryPoint>]
    let main argv =
        ManagerModes.createNewVault ()
        ManagerModes.addSecret ()
        5

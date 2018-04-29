namespace MyPass

open Argu
open Aes
open Password
open System.Text
open Vault
open ConsoleUi
open Result
open System

type Arguments =
    | Mode of mode : string
    interface IArgParserTemplate with
        member x.Usage =
            match x with
            | Mode _ -> "Specify the mode you wish to run, choose from: CREATE|ADD|LIST|GET"

module Main =

    let printError (result : Result<string, 'a>) =
        match result with
        | Failure f -> printfn "%s" f
        | _ -> printfn "Operation completed."

    [<EntryPoint; STAThread>]
    let main args =
        let argsParser = ArgumentParser.Create<Arguments>(programName = "MyPass")
        let helpSpecified =
            args
            |> Array.toList
            |> List.map (fun s -> s.ToLower())
            |> List.filter (fun s -> s = "--help")
            |> List.length
            |> fun len -> len > 0

        match helpSpecified with
        | true -> argsParser.PrintUsage () |> printfn "%s"
        | false ->
            let parsedArgs : ParseResults<Arguments> = argsParser.Parse args
            match parsedArgs.Contains Mode with
            | false -> argsParser.PrintUsage () |> printfn "%s"
            | true ->
                let mode = (parsedArgs.GetResult Mode).ToLower()
                match mode with
                | "create" -> ConsoleUi.createNewVault ()
                | "add" -> ConsoleUi.addSecret () |> printError
                | "list" -> ConsoleUi.listSecrets () |> printError
                | "get" -> ConsoleUi.printPassword () |> printError
                | _ -> argsParser.PrintUsage () |> printfn "%s"
        0
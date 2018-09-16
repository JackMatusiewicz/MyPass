namespace MyPass.Console

open Argu
open MyPass
open System

type Arguments =
    | Mode of mode : string
    interface IArgParserTemplate with
        member x.Usage =
            match x with
            | Mode _ -> "Specify the mode you wish to run, choose from: CREATE|ADD|LIST|GET|UPDATE|PWNED"

module Main =

    let private printError (result : MyPass.Result<FailReason, 'a>) =
        match result with
        | MyPass.Result.Failure f ->
            FailReason.toString f
            |> printfn "%s"
        | _ -> printfn "Operation completed."

    let runApp (argsParser : ArgumentParser<Arguments>) (mode : string) =
        match mode with
        | "create" ->
            ConsoleUi.createNewVault ()
        | "add" ->
            ConsoleUi.addSecret ()
        | "list" ->
            ConsoleUi.listSecrets ()
        | "get" ->
            ConsoleUi.printPassword ()
        | "update" ->
            ConsoleUi.updatePassword ()
        | "pwned" ->
            ConsoleUi.checkForCompromisedPasswords ()
        | _ ->
            argsParser.PrintUsage ()
            |> sprintf "%s"
            |> InvalidCommand
            |> MyPass.Result.Failure
        |> printError

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
            | false ->
                printfn "Please enter a mode (choices are: CREATE | ADD | LIST | GET | UPDATE | PWNED)"
                Console.ReadLine ()
                |> runApp argsParser
            | true ->
                let mode = (parsedArgs.GetResult Mode).ToLower()
                runApp argsParser mode
        0
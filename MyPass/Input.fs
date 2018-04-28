namespace MyPass

open System
open System.Text

module SecureInput =

    let private altOrCtrlPressed keyModifiers : bool =
        [ConsoleModifiers.Control; ConsoleModifiers.Alt]
        |> List.map (fun x -> (int x))
        |> List.map (fun a -> a &&& (int keyModifiers))
        |> List.map (fun a -> a = 0)
        |> List.fold (fun s a -> s && a) true

    //TODO - add checks for valid character, via a regex.
    let private isValidKeyPress (key : ConsoleKeyInfo) =
        let pressModifier = (int key.Modifiers)
        if altOrCtrlPressed (key.Modifiers) then
            false
        else
            true

    let get () : string =
        let rec getInput (acc : StringBuilder) =
            let key = Console.ReadKey()
            if key.Key = ConsoleKey.Enter then
                acc.ToString()
                |> (fun s -> s.ToCharArray())
                |> Array.rev
                |> (fun cs -> new string(cs))
            else if not (isValidKeyPress key) then
                Console.Write("\b \b")
                getInput acc
            else
                Console.Write("\b \b")
                Console.Write("*")
                getInput (acc.Append(key.KeyChar))
        getInput (StringBuilder ())
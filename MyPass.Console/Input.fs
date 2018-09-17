namespace MyPass.Console

open System
open System.Security

module SecureInput =

    let private altOrCtrlPressed keyModifiers : bool =
        [ConsoleModifiers.Control; ConsoleModifiers.Alt]
        |> List.map (fun x -> (int x))
        |> List.map (fun a -> a &&& (int keyModifiers))
        |> List.map (fun a -> a <> 0)
        |> List.fold (fun s a -> s || a) false

    //TODO - find a better place for this.
    let private isValidPasswordCharacter =
        let chars =
            ['a'..'z']
            @ ['A'..'Z']
            @ ['0'..'9']
            @ ['_';'!';'@';'#';'$';'%';'^';'&';'*';'(';')';',';'.';'?';'"';':';'{';'}';'|';'<';'>'; ' '; '+'; '~']
        fun c -> List.contains c chars

    let private isValidKeyPress (key : ConsoleKeyInfo) =
        let pressModifier = (int key.Modifiers)
        if altOrCtrlPressed (key.Modifiers) then
            false
        else if not (isValidPasswordCharacter key.KeyChar) then
            false
        else
            true

    let get () : SecureString =
        let rec getInput (acc : SecureString) =
            let key = Console.ReadKey(true)
            if key.Key = ConsoleKey.Enter then
                printfn ""
                acc
            else if key.Key = ConsoleKey.Backspace then
                match acc.Length with
                | l when l > 0 ->
                    printf "\b \b"
                    acc.RemoveAt(acc.Length - 1)
                    getInput acc
                | _ -> getInput acc
            else if not (isValidKeyPress key) then
                getInput acc
            else
                printf "*"
                acc.AppendChar(key.KeyChar)
                getInput (acc)
        getInput (new SecureString ())
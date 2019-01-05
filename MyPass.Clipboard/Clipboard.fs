namespace MyPass.Clipboard

open System
open System.Windows.Forms

module Clipboard =

    let rec private attemptToClearClipboard attempt =
        if attempt > 2 then
            printfn "Unable to clear the clipboard!"
        else
            try
                Clipboard.Clear ()
            with
            | _ ->
                printfn "Attempt #%d to clear the clipboard failed, retrying" (attempt + 1)
                attemptToClearClipboard (attempt + 1)

    [<STAThread>]
    let timedStore (durationMs : int) (data : string) =
        Clipboard.SetText(data)
        System.Threading.Thread.Sleep(durationMs)
        attemptToClearClipboard 0
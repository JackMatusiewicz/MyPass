namespace MyPass.Clipboard

open System
open System.Windows.Forms

module Clipboard =

    let rec private attemptToClearClipboard onClearFail attempt =
        if attempt > 2 then
            printfn "Unable to clear the clipboard!"
        else
            try
                Clipboard.Clear ()
            with
            | _ ->
                onClearFail (attempt + 1)
                attemptToClearClipboard onClearFail (attempt + 1)

    [<STAThread>]
    let timedStore (durationMs : int) (data : string) (onClearFail : int -> unit) =
        Clipboard.SetText(data)
        System.Threading.Thread.Sleep(durationMs)
        attemptToClearClipboard onClearFail 0
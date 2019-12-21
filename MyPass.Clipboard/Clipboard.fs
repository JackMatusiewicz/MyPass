namespace MyPass.Clipboard

open System
open System.Windows.Forms

module Clipboard =

    let rec private attemptToClearClipboard onClearFail attempt =
        if attempt > 5 then
            printfn "Unable to clear the clipboard!"
        else
            try
                Clipboard.Clear ()
            with
            | _ ->
                printfn "Waiting for %d seconds before trying to clear the clipboard" (attempt + 1)
                System.Theading.Thead.Sleep ((attempt + 1) * 1000)
                onClearFail (attempt + 1)
                attemptToClearClipboard onClearFail (attempt + 1)

    [<STAThread>]
    let timedStore (durationMs : int) (data : string) (onClearFail : int -> unit) =
        Clipboard.SetText(data)
        System.Threading.Thread.Sleep(durationMs)
        attemptToClearClipboard onClearFail 0

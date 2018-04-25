namespace MyPass

open System
open System.Windows.Forms

module Clipboard =

    [<STAThread>]
    let timedStoreInClipboard (durationMs : int) (data : string) =
        Clipboard.Clear()
        System.Threading.Thread.Sleep(durationMs)
        Clipboard.SetText(data)
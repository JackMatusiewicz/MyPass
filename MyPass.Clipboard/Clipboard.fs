namespace MyPass.Clipboard

open System
open System.Windows.Forms

module Clipboard =

    [<STAThread>]
    let timedStore (durationMs : int) (data : string) =
        Clipboard.SetText(data)
        System.Threading.Thread.Sleep(durationMs)
        Clipboard.Clear()
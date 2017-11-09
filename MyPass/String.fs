namespace MyPass

open System.Text

module String =

    let ofList (data : char list) =
        data
        |> List.fold
            (fun (sb : StringBuilder) (c : char) -> sb.Append(c))
            (new StringBuilder())
        |> (fun sb -> sb.ToString())
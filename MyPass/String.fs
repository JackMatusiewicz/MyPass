namespace MyPass

open System.Text

[<RequireQualifiedAccess>]
module String =

    let ofList (data : char list) =
        data
        |> List.fold
            (fun (sb : StringBuilder) (c : char) -> sb.Append(c))
            (new StringBuilder())
        |> (fun sb -> sb.ToString())

    let fromBytes (bs : byte[]) =
        Encoding.UTF8.GetString bs

    let toBytes (s : string) =
        Encoding.UTF8.GetBytes s
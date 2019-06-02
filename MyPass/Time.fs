namespace MyPass

[<RequireQualifiedAccess>]
module Time =

    let get () = System.DateTime.UtcNow

namespace MyPass

open MyPass.Result.Operators

[<RequireQualifiedAccess>]
module List =

    let private append x xs = x :: xs

    let rec private traverseCps (f : 'a -> Result<'c, 'b>) (xs : 'a list) (cont : Result<'c, 'b list> -> 'k) : 'k =
        match xs with
        | [] ->
            Result.lift []
            |> cont
        | x :: xs ->
            traverseCps f xs (fun c -> append <!> (f x) <*> c |> cont)

    let traverse (f : 'a -> Result<'c, 'b>) (xs : 'a list) : Result<'c, 'b list> =
        traverseCps f xs id
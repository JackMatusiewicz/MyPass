namespace MyPass

open MyPass.Result.Operators

module ListExt =

    let private append x xs = x :: xs

    let rec traverse (f : 'a -> Result<'c, 'b>) (xs : 'a list) : Result<'c, 'b list> =
        match xs with
        | [] -> Result.lift []
        | x::xs ->
            append <!> (f x) <*> (traverse f xs)
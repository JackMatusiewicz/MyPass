namespace MyPass

module Tuple =

    let lmap (f : 'a -> 'b) ((a,c) : 'a * 'c) =
        (f a, c)

    let map (f : 'a -> 'b) ((c,a) : 'c * 'a) =
        (c, f a)

    let traverse (f : 'a -> Result<'c, 'b>) (x,a) =
        match f a with
        | Failure f -> Failure f
        | Success s -> Success (x,s)

    let sequence ((a,b) as x : 'a * Result<'c,'b>) : Result<'c, 'a * 'b> =
        match b with
        | Failure f -> Failure f
        | Success b -> Success (a,b)

    let leftSequence ((a,b) as x : Result<'c,'a> * 'b) : Result<'c, 'a * 'b> =
        match a with
        | Failure f -> Failure f
        | Success a -> Success (a,b)
namespace MyPass

module Tuple =

    let map (f : 'a -> 'b) ((c,a) : 'c * 'a) =
        (c, f a)

    let traverse (f : 'a -> Result<'c, 'b>) (x,a) =
        match f a with
        | Failure f -> Failure f
        | Success s -> Success (x,s)
namespace MyPass

module Tuple =

    let bimap (f : 'a -> 'b) (g : 'c -> 'd) (a,c) =
        (f a, g c)

    let map (f : 'a -> 'b) ((c,a) : 'c * 'a) =
        (c, f a)

    let leftMap (f : 'a -> 'b) ((a,c) : 'a * 'c) =
        (f a, c)
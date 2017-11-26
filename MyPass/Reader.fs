namespace MyPass

module Reader =

    let map (f : 'a -> 'b) (func : 'r -> 'a) : 'r -> 'b =
        func >> f
    let (<-|) = map

    let apply (f : 'r -> 'a -> 'b) (func : 'r -> 'a) : 'r -> 'b =
        fun x -> f x (func x)
    let (<~|) = apply

    let lift x = fun r -> x
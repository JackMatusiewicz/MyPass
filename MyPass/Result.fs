namespace MyPass

[<Struct>]
type Result<'a, 'b> =
    | Failure of ErrorValue : 'a
    | Success of SuccessValue : 'b

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module Result =

    let map (f : 'a -> 'b) (input : Result<'c, 'a>) : Result<'c, 'b> =
        match input with
        | Failure f -> Failure f
        | Success s -> Success <| f s

    let apply (f : Result<'c, 'a -> 'b>) (input : Result<'c, 'a>) : Result<'c, 'b> =
        match f,input with
        | (Success func), (Success d) -> Success <| func d
        | Failure f, _ -> Failure f
        | _, Failure f -> Failure f

    let lift (x : 'a) : Result<'c, 'a> = Success x

    let bind (data : Result<'c, 'a>) (f : 'a -> Result<'c, 'b>) : Result<'c, 'b> =
        match data with
        | Success s -> f s
        | Failure f -> Failure f

    let join (a : Result<'c, Result<'c, 'a>>) : Result<'c, 'a> =
        bind a id

    let bind2 (a : Result<'c, 'a>) (b : Result<'c, 'b>) (f : 'a -> 'b -> Result<'c, 'd>) =
        join (apply (map f a) b)

    let iter (f : 'a -> unit) (a : Result<'f, 'a>) : unit =
        match a with
        | Failure f -> ()
        | Success s -> f s

    module Operators =

        let (<!>) = map

        let (<*>) = apply

        let (>>=) = bind

        let (=<<) (f : 'a -> Result<'c, 'b>) (data : Result<'c, 'a>) =
            bind data f

        let (>=>) (f : 'a -> Result<'c,'b>) (g : 'b -> Result<'c,'d>) : 'a -> Result<'c,'d> =
            fun a -> f a >>= g
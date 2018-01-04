namespace MyPass

type Result<'a, 'b> = Failure of 'a
                    | Success of 'b

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module Result =

    let map (f : 'a -> 'b) (input : Result<'c, 'a>) : Result<'c, 'b> =
        match input with
        | Failure f -> Failure f
        | Success s -> Success <| f s
    let (<!>) = map
    let (<?>) (input : Result<'c, 'a>) (f : 'a -> 'b) : Result<'c, 'b> = map f input

    let apply (f : Result<'c, 'a -> 'b>) (input : Result<'c, 'a>) : Result<'c, 'b> =
        match f,input with
        | (Success func), (Success d) -> Success <| func d
        | Failure f, _ -> Failure f
        | _, Failure f -> Failure f
    let (<*>) = apply

    let lift (x : 'a) : Result<'c, 'a> = Success x

    let bind (data : Result<'c, 'a>) (f : 'a -> Result<'c, 'b>) : Result<'c, 'b> =
        match data with
        | Success s -> f s
        | Failure f -> Failure f
    let (>>=) = bind
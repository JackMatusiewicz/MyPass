namespace MyPass

/// Head always points at the next free slot
type 'a AppendOnlyRingBuffer = {
    Buffer : 'a option []
    Head : int
}

module AppendOnlyRingBuffer =

    let make<'a> (capacity : int) =
        let (buffer : 'a option []) = Array.init capacity (fun i -> None)

        {
            Buffer = buffer
            Head = 0
        }

    let add (item : 'a) (buffer : 'a AppendOnlyRingBuffer) : 'a AppendOnlyRingBuffer =
        buffer.Buffer.[buffer.Head] <- Some item

        {
            Buffer = buffer.Buffer
            Head = if buffer.Head = buffer.Buffer.Length - 1 then 0 else buffer.Head + 1
        }

    let get (buffer : 'a AppendOnlyRingBuffer) : 'a [] =
        let rec fill (oldBuffer : 'a option []) (currentIndex : int) (accIndex : int) (acc : 'a []) : 'a [] =
            match accIndex with
            | _ when accIndex < 0 ->
                acc
            | _ ->
                match oldBuffer.[currentIndex] with
                | None -> failwith "impossible"
                | Some v ->
                    acc.[accIndex] <- v
                    let nextIndex = if currentIndex - 1 < 0 then oldBuffer.Length - 1 else currentIndex - 1
                    fill oldBuffer nextIndex (accIndex - 1) acc

        let filled = Array.sumBy (function | None -> 0 | Some _ -> 1) buffer.Buffer
        let returnBuffer = Array.init filled (fun _ -> Unchecked.defaultof<'a>)
        let startIndex = if buffer.Head - 1 < 0 then buffer.Buffer.Length - 1 else buffer.Head - 1
        fill buffer.Buffer startIndex (returnBuffer.Length-1) returnBuffer
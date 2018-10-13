namespace MyPass

open System

[<Struct>]
type Description = Description of string

[<Struct>]
[<CustomEquality; CustomComparison>]
type Name =
    | Name of string

    override this.Equals (o) =
        match o with
        | :? Name as n ->
            let (Name s) = n
            let (Name m) = this
            s.Equals(m, StringComparison.InvariantCultureIgnoreCase)
        | _ -> false

    override this.GetHashCode () =
        let (Name s) = this
        s.ToLower().GetHashCode()

    member __.Compare x y =
        let (Name a) = x
        let (Name b) = y
        String.Compare(a,b, StringComparison.InvariantCultureIgnoreCase)

    interface System.IComparable with
       member this.CompareTo y =
          match y with
          | :? Name as y -> this.Compare this y
          | _ -> invalidArg "y" "cannot compare value of different types"

    interface System.IComparable<Name> with
        member this.CompareTo(y) =
            this.Compare this y

type Activity =
    | Add of Name
    | Delete of Name
    | Update of Name
    | Get of Name
    | DupeCheck
    | BreachCheck

type UserActivity =
    {
        Activity : Activity
        Date : DateTime
    }

type History = UserActivity AppendOnlyRingBuffer

[<Struct>]
type EncryptedData = EncryptedData of byte[]

// The rationale behind this being private is that we can expose the data inside without the key.
// However, if we have a public function that gives the data and the key, we have no control
// over when it is decrypted.
// It also means we can guarantee that a user hasn't created a securedSecret with a bad key.
type SecuredSecret =
    private
        {
            Data : EncryptedData
            Key : AesKey
        }

type WebLogin =
    {
        SecuredData : SecuredSecret
        Url : Url
        UserName : Name
    }

[<Struct>]
type Secret =
    | Secret of Secret : SecuredSecret
    | WebLogin of Login : WebLogin

type PasswordEntry =
    {
        Secret : Secret
        Description : Description
        Name : Name
    }

type Vault =
    {
        Passwords : Map<Name, PasswordEntry>
        History : History
    }

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module Name =

    let toString (Name n) = n

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module Description =

    let toString (Description n) = n

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module UserActivity =

    let make (date : System.DateTime) (a : Activity) =
        {
            Activity = a
            Date = date
        }

    let toString (ua : UserActivity) =
        let activityString (a : Activity) =
            match a with
            | Add n -> sprintf "Added %s to the vault." <| Name.toString n
            | Delete n -> sprintf "Deleted %s from the vault." <| Name.toString n
            | Update n -> sprintf "Updated %s in the vault." <| Name.toString n
            | Get n -> sprintf "Got the secret of %s." <| Name.toString n
            | DupeCheck -> "Performed a secret reuse check."
            | BreachCheck -> "Performed a breach check with HaveIBeenPwned."
        sprintf "%s - %s" (ua.Date.ToString("G")) (activityString ua.Activity)

module VaultDomain =

    let makeWebLogin (url : Url) (name : Name) (secret : SecuredSecret) =
        {
            Url = url
            UserName = name
            SecuredData = secret
        } |> WebLogin

    let internal updateSecret (newSecret : SecuredSecret) (secret : Secret) =
        match secret with
        | Secret s -> Secret newSecret
        | WebLogin l ->
            WebLogin { l with SecuredData = newSecret }
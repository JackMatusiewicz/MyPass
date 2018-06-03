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

[<Struct>]
type EncryptedData = EncryptedData of byte[]

// The rationale behind this being private is that we can expose the data inside without the key.
// However, if we have a public function that gives the data and the key, we have no control
// over when it is decrypted.
// It also means we can guarantee that a user hasn't created a securedSecret with a bad key.
type SecuredSecret = private {
    Data : EncryptedData
    Key : AesKey }

type WebLogin = {
    SecuredData : SecuredSecret
    Url : Url
    UserName : Name }

[<Struct>]
type Secret =
    | Secret of Secret : SecuredSecret
    | WebLogin of Login : WebLogin

type PasswordEntry = {
    Secret : Secret
    Description : Description
    Name : Name
}

type Vault = { passwords : Map<Name, PasswordEntry> }

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
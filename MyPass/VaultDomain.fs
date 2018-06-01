namespace MyPass

[<Struct>]
type Description = Description of string

[<Struct>]
type Name = Name of string

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
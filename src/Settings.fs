module Settings

open System.IO
open Serilog
open YamlDotNet.Serialization
open YamlDotNet.Serialization.NamingConventions

type Settings = {
    gitlabApi: string
    group: string
    epicId: string
    aliases: Map<string, int>
}

[<CLIMutable>]
type GlabHost = { token: string }

[<CLIMutable>]
type GlabConfig = { hosts: System.Collections.Generic.Dictionary<string, GlabHost> }

let tryGetEnv =
    System.Environment.GetEnvironmentVariable
    >> function
        | null
        | "" -> None
        | x -> Some x

let private parseAliases (str: string option) : Map<string, int> =
    str
    |> Option.map (fun y ->
        y.Split ":"
        |> Array.map (fun s -> s.Split "=" |> fun t -> t[0], int t[1])
        |> Map.ofArray
    )
    |> Option.defaultValue Map.empty

let useGlab host () =
    let home =
        System.Environment.GetFolderPath System.Environment.SpecialFolder.UserProfile
    let config = Path.GetFullPath (Path.Join [| home; ".config/glab-cli/config.yml" |])
    if File.Exists config then
        let yaml = File.ReadAllText config |> fun y -> y.Replace ("!!null", "")
        let deserializer =
            DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build ()
        let conf = deserializer.Deserialize<GlabConfig> yaml
        conf.hosts[host].token
    else
        Log.Error $"No access token configured"
        exit 1

let private gitlab = tryGetEnv "SPENT_GITLAB" |> Option.defaultValue "gitlab.com"
let private token =
    tryGetEnv "SPENT_ACCESS_TOKEN" |> Option.defaultWith (useGlab gitlab)

let settings = {
    gitlabApi = $"https://{gitlab}/api/graphql?access_token={token}"
    group = tryGetEnv "SPENT_GROUP" |> Option.defaultValue "oceanbox"
    epicId = tryGetEnv "SPENT_EPIC" |> Option.defaultValue ""
    aliases = tryGetEnv "SPENT_ALIASES" |> parseAliases
}
module Settings

open System.IO
open Serilog
open YamlDotNet.Serialization
open YamlDotNet.Serialization.NamingConventions

type Settings = {
    gitlab: string
    group: string
    epicId: int
    aliases: Map<string, int>
    token: string
}

[<CLIMutable>]
type GlabConfig = { Hosts: System.Collections.Generic.Dictionary<string, {| token: string |}> }

let tryGetEnv =
    System.Environment.GetEnvironmentVariable
    >> function
        | null
        | "" -> None
        | x -> Some x

let private parseAliases (str: string) : Map<string, int> =
    str.Split ":"
    |> Array.map (fun s -> s.Split "=" |> fun t -> t[0], int t[1])
    |> Map.ofArray

let useGlab host () =
    let config = "~/.config/glab-cli/config.yml"
    if File.Exists config then
        let yaml = File.ReadAllText config
        let deserializer =
            DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).Build ()
        let conf = deserializer.Deserialize<GlabConfig> yaml
        conf.Hosts[host].token
    else
        Log.Error $"No access token configured"
        exit 1

let private gitlab = tryGetEnv "SPENT_GITLAB" |> Option.defaultValue "gitlab.com"

let settings = {
    gitlab = gitlab
    group = tryGetEnv "SPENT_GROUP" |> Option.defaultValue "oceanbox"
    epicId = tryGetEnv "SPENT_EPIC" |> Option.defaultValue "0" |> int
    aliases = tryGetEnv "SPENT_ALIASES" |> Option.defaultValue "" |> parseAliases
    token = tryGetEnv "SPENT_ACCESS_TOKEN" |> Option.defaultWith (useGlab gitlab)
}
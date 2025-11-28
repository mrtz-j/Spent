module Settings

open System.IO
open Serilog

type Settings =
    { gitlabUrl: string
      group: string
      epicId: int
      aliases: Map<string, int> }

let tryGetEnv =
    System.Environment.GetEnvironmentVariable
    >> function
        | null
        | "" -> None
        | x -> Some x

let settings = tryGetEnv "GITLAB_URL"
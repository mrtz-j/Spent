module Main

open System
open Serilog
open Serilog.Events
open Fargo
open Fargo.Operators

open Settings

type ListArgs = { Epic: string option }

type SpentArgs = { Time: string; When: DateTime option; Summary: string option }

[<RequireQualifiedAccess>]
type private Cmd =
    | List
    | Spent

type Command =
    | List of ListArgs
    | Spent of SpentArgs

let configureSerilog n =
    LoggerConfiguration().MinimumLevel.Is(n).WriteTo.Console().CreateLogger()

let argParser: Arg<Command> =
    fargo {
        let! mainCommand =
            cmd "list" "ls" "List epics" |>> Cmd.List
            <|> (cmd "time" "t" "Log spent time" |>> Cmd.Spent)
            <|> (error "Invalid or missing command")

        match mainCommand with
        | Cmd.List ->
            let! name = opt "name" "n" "filter" "Epic match filter"
            return List { Epic = name }

        | Cmd.Spent ->
            let! date =
                opt "at" "a" "datetime" "When"
                |> optParse (fun a -> Ok(DateTime.Parse a))
            and! summary =
                opt "summary" "s" "string" "Summary"
                |> optParse Ok
            and! time = arg "time" "GitLab time string" |> reqArg
            return Spent { Time = time; When = date; Summary = summary }
    }

let executeCommand (_: Threading.CancellationToken) (command: Command) =
    task {
        Log.Logger <- configureSerilog LogEventLevel.Warning

        match command with
        | List args -> return 0
        | Spent args -> return 0
    }

[<EntryPoint>]
let main argv =
    run "spent" argParser argv executeCommand
    0
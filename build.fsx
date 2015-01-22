// ----------------------------------------------------------------------------
// This file is subject to the terms and conditions defined in
// file 'LICENSE.txt', which is part of this source code package.
// ----------------------------------------------------------------------------

(*
    This file handles the complete build process of RazorEngine

    The first step is handled in build.sh and build.cmd by bootstrapping a NuGet.exe and 
    executing NuGet to resolve all build dependencies (dependencies required for the build to work, for example FAKE)

    The secound step is executing this file which resolves all dependencies, builds the solution and executes all unit tests
*)


// Supended until FAKE supports custom mono parameters
#I @".nuget/Build/FAKE/tools/" // FAKE
#r @"FakeLib.dll"  //FAKE
#load @"buildConfig.fsx"
open BuildConfig

open System.Collections.Generic
open System.IO

open Fake
open Fake.Git
open Fake.FSharpFormatting
open AssemblyInfoFile

if use_nuget then
    // Ensure the ./src/.nuget/NuGet.exe file exists (required by xbuild)
    let nuget = findToolInSubPath "NuGet.exe" "./.nuget/Build/NuGet.CommandLine/tools/NuGet.exe"
    System.IO.File.Copy(nuget, "./src/.nuget/NuGet.exe", true)

let buildWithFiles msg dir projectFileFinder (buildParams:BuildParams) =
    let buildDir = dir @@ buildParams.CustomBuildName
    CleanDirs [ buildDir ]
    // build app
    projectFileFinder buildParams
        |> MSBuild buildDir "Build"
            [   "Configuration", buildMode
                "CustomBuildName", buildParams.CustomBuildName ]
        |> Log msg

let buildApp = buildWithFiles "AppBuild-Output: " buildDir findProjectFiles
let buildTests = buildWithFiles "TestBuild-Output: " testDir findTestFiles

let runTests (buildParams:BuildParams) =
    let testDir = testDir @@ buildParams.CustomBuildName
    let logs = System.IO.Path.Combine(testDir, "logs")
    System.IO.Directory.CreateDirectory(logs) |> ignore
    let files =
        !! (testDir + "/Test.*.dll")
    if files |> Seq.isEmpty then
      traceError (sprintf "NO test found in %s" testDir)
    else
      files
        |> NUnit (fun p ->
            {p with
                //NUnitParams.WorkingDir = working
                //ExcludeCategory = if isMono then "VBNET" else ""
                ProcessModel =
                    // Because the default nunit-console.exe.config doesn't use .net 4...
                    if isMono then NUnitProcessModel.SingleProcessModel else NUnitProcessModel.DefaultProcessModel
                WorkingDir = testDir
                StopOnError = true
                TimeOut = System.TimeSpan.FromMinutes 30.0
                Framework = "4.0"
                DisableShadowCopy = true;
                OutputFile = "logs/TestResults.xml" })

let buildAll (buildParams:BuildParams) =
    buildApp buildParams
    buildTests buildParams
    runTests buildParams

// Documentation
let buildDocumentationTarget target =
    trace (sprintf "Building documentation (%s), this could take some time, please wait..." target)
    let b, s = executeFSI "." "generateDocs.fsx" ["target", target]
    for l in s do
        (if l.IsError then traceError else trace) (sprintf "DOCS: %s" l.Message)
    if not b then
        failwith "documentation failed"
    ()

let MyTarget name body =
    Target name (fun _ -> body false)
    let single = (sprintf "%s_single" name)
    Target single (fun _ -> body true)

// Targets
MyTarget "Clean" (fun _ ->
    CleanDirs [ buildDir; testDir; releaseDir ]
)

MyTarget "CleanAll" (fun _ ->
    // Only done when we want to redownload all.
    Directory.EnumerateDirectories BuildConfig.nugetDir
    |> Seq.collect (fun dir -> 
        let name = Path.GetFileName dir
        if name = "Build" then
            Directory.EnumerateDirectories dir
            |> Seq.filter (fun buildDepDir ->
                let buildDepName = Path.GetFileName buildDepDir
                // We can't delete the FAKE directory (as it is used currently)
                buildDepName <> "FAKE")
        else
            Seq.singleton dir)
    |> Seq.iter (fun dir ->
        try
            DeleteDir dir
        with exn ->
            traceError (sprintf "Unable to delete %s: %O" dir exn))
)

MyTarget "RestorePackages" (fun _ -> 
    // will catch src/targetsDependencies
    !! "./src/**/packages.config"
    |> Seq.iter 
        (RestorePackage (fun param ->
            { param with    
                // ToolPath = ""
                OutputPath = BuildConfig.packageDir }))
)

MyTarget "SetVersions" (fun _ -> 
    let info =
        [Attribute.Company projectName
         Attribute.Product projectName
         Attribute.Copyright copyrightNotice
         Attribute.Version version
         Attribute.FileVersion version
         Attribute.InformationalVersion version_nuget]
    CreateFSharpAssemblyInfo "./src/SharedAssemblyInfo.fs" info
    let info =
        [Attribute.Company projectName_ldap
         Attribute.Product projectName_ldap
         Attribute.Copyright copyrightNotice
         Attribute.Version version_ldap
         Attribute.FileVersion version_ldap
         Attribute.InformationalVersion version_nuget_ldap]
    CreateFSharpAssemblyInfo "./src/SharedAssemblyInfo.Ldap.fs" info
)

allParams
    |> Seq.iter (fun buildParam -> 
        MyTarget (sprintf "Build_%s" buildParam.SimpleBuildName) (fun _ -> buildAll buildParam))

MyTarget "CopyToRelease" (fun _ ->
    trace "Copying to release because test was OK."
    CleanDirs [ outLibDir ]
    System.IO.Directory.CreateDirectory(outLibDir) |> ignore

    // Copy RazorEngine.dll to release directory
    allParams 
        |> Seq.map (fun buildParam -> buildParam.CustomBuildName)
        |> Seq.map (fun t -> buildDir @@ t, t)
        |> Seq.filter (fun (p, t) -> Directory.Exists p)
        |> Seq.iter (fun (source, target) ->
            let outDir = outLibDir @@ target 
            ensureDirectory outDir
            generated_file_list
            |> Seq.filter (fun (file) -> File.Exists (source @@ file))
            |> Seq.iter (fun (file) ->
                let newfile = outDir @@ Path.GetFileName file
                File.Copy(source @@ file, newfile))
        )
)

MyTarget "NuGet" (fun _ ->
    let outDir = releaseDir @@ "nuget"
    ensureDirectory outDir
    for (nuspecFile, settingsFunc) in nugetPackages do
      NuGet (fun p ->
        { p with   
            WorkingDir = "."
            OutputPath = outDir
            AccessKey = getBuildParamOrDefault "nugetkey" ""
            Publish = hasBuildParam "nugetkey"
            Dependencies = [ ] } |> settingsFunc)
        (sprintf "nuget/%s" nuspecFile)
)

// Documentation 

MyTarget "GithubDoc" (fun _ -> buildDocumentationTarget "GithubDoc")

MyTarget "LocalDoc" (fun _ -> 
    buildDocumentationTarget "LocalDoc"
    trace (sprintf "Local documentation has been finished, you can view it by opening %s in your browser!" (Path.GetFullPath (outDocDir @@ "local" @@ "html" @@ "index.html")))
)


MyTarget "ReleaseGithubDoc" (fun isSingle ->
    let repro = (sprintf "git@github.com:%s/%s.git" github_user github_project)  
    let doAction =
        if isSingle then true
        else
            printf "update github docs to %s? (y,n): " repro
            let line = System.Console.ReadLine()
            line = "y"
    if doAction then
        CleanDir "gh-pages"
        cloneSingleBranch "" repro "gh-pages" "gh-pages"
        fullclean "gh-pages"
        CopyRecursive ("release"@@"documentation"@@(sprintf "%s.github.io" github_user)@@"html") "gh-pages" true |> printfn "%A"
        StageAll "gh-pages"
        Commit "gh-pages" (sprintf "Update generated documentation %s" release.NugetVersion)
        printf "gh-pages branch updated in the gh-pages directory, push that branch to %s now? (y,n): " repro
        let line = System.Console.ReadLine()
        if line = "y" then
            Branches.pushBranch "gh-pages" "origin" "gh-pages"
)

Target "All" (fun _ ->
    trace "All finished!"
)

MyTarget "VersionBump" (fun _ ->
    // Build updates the SharedAssemblyInfo.cs files.
    let changedFiles = Fake.Git.FileStatus.getChangedFilesInWorkingCopy "" "HEAD" |> Seq.toList
    if changedFiles |> Seq.isEmpty |> not then
        for (status, file) in changedFiles do
            printfn "File %s changed (%A)" file status

        printf "version bump commit? (y,n): "
        let line = System.Console.ReadLine()
        if line = "y" then
            StageAll ""
            Commit "" (sprintf "Bump version to %s" release.NugetVersion)
        
            printf "create tags? (y,n): "
            let line = System.Console.ReadLine()
            if line = "y" then
                let doSafe msg f =
                    try
                        f()
                    with exn -> 
                        trace (sprintf "Error (%s): %A" msg exn)

                doSafe "delete_tag version_nuget" 
                    (fun () -> Branches.deleteTag "" version_nuget)
                
                doSafe "create_tag version_nuget" 
                    (fun () -> Branches.tag "" version_nuget)

                printf "push tags? (y,n): "
                let line = System.Console.ReadLine()
                if line = "y" then
                    Branches.pushTag "" "origin" version_nuget

            printf "push branch? (y,n): "
            let line = System.Console.ReadLine()
            if line = "y" then
                Branches.push ""
)

Target "Release" (fun _ ->
    trace "All released!"
)

// Clean all
"Clean" 
  ==> "CleanAll"
"Clean_single" 
  ==> "CleanAll_single"

"Clean"
  ==> "RestorePackages"
  ==> "SetVersions" 
  
allParams
    |> Seq.iter (fun buildParam ->
        let buildName = sprintf "Build_%s" buildParam.SimpleBuildName 
        "SetVersions"
          ==> buildName
          |> ignore
        buildName
          ==> "All"
          |> ignore
    )

// Dependencies
"Clean" 
  ==> "CopyToRelease"
  ==> "LocalDoc"
  ==> "All"
 
"All" 
  ==> "VersionBump"
  ==> "NuGet"
  ==> "GithubDoc"
  ==> "ReleaseGithubDoc"
  ==> "Release"

// start build
RunTargetOrDefault "All"

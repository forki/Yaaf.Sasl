// ----------------------------------------------------------------------------
// This file is subject to the terms and conditions defined in
// file 'LICENSE.txt', which is part of this source code package.
// ----------------------------------------------------------------------------

namespace Yaaf.Sasl.Plain
open Yaaf.Sasl
open System

type Authzid = string
type Authcid = string
type Passwd = string
type IUserSource =    
    abstract member Authenticate : Authcid * Passwd -> bool
    abstract member DeriveAuthzid : Authcid -> Authzid option
    abstract member Authorize : Authcid * Authzid -> bool

module DefaultUserSources =
    let SingleUserSource isAdmin username password = 
        { new IUserSource with
              member x.Authenticate(user, pass) = user = username && pass = password
              
              member x.Authorize(user, entity) = 
                  if isAdmin then true
                  else user = entity
              
              member x.DeriveAuthzid(user) = Some user }

type PlainContextInfo = {
    Authorization : Authzid
    Authentication : Authcid
    Password : Passwd
    }
type Context = Context<PlainContextInfo>
type PlainServer(source:IUserSource) =
    let name = "PLAIN"
    let initResponse data =
        let seperators =
            data // .FindAllIndices(fun item -> item = 0uy)
                |> Seq.mapi (fun i item -> i,item)
                |> Seq.filter (fun (i,item) -> item = 0uy)
                |> Seq.map (fun (i,_) -> i)
                |> Seq.toArray
        assert (seperators.Length = 2)
        let authzidData = System.Text.Encoding.UTF8.GetString(data, 0, seperators.[0])
        let authcid = System.Text.Encoding.UTF8.GetString(data, seperators.[0] + 1, seperators.[1] - (seperators.[0] + 1))
        let passwd = System.Text.Encoding.UTF8.GetString(data, seperators.[1] + 1, data.Length -  (seperators.[1] + 1))
        let authOk = source.Authenticate(authcid, passwd)
        let authzid = 
            if authzidData = "" then
                source.DeriveAuthzid authcid
            else Some authzidData
        let authorizedOk =
            match authzid with
            | Some auth -> source.Authorize(authcid, auth)
            | None -> false
        
        if authOk && authorizedOk then
            let context = {
                Authorization = authzid.Value
                Authentication = authcid
                Password = passwd }
            { RawContext = Some context } :> IContext, Success None
        else
            if authOk && not authorizedOk then
                Context<_>.Empty, Failure (SaslFailure.InvalidAuthzid, None)
            else
                Context<_>.Empty, Failure (SaslFailure.NotAuthorized, None)
                
        
    interface IServerMechanism with
        member x.GetNextMessage (context, clientMessage) =
            match clientMessage with
            | Abort -> Context.Empty, Failure(SaslFailure.Aborted, None)
            | Auth (plain, initData) -> 
                assert (plain = name)
                match initData with
                | Some data -> initResponse data
                | None ->
                    // empty challenge to get initial data
                    Context.Empty, Challenge [||]
            | Response data -> 
                match context with
                | None -> failwith "Use auth messagefirst"
                | Some context -> 
                    initResponse data
            
        member x.UpdateStream context oldStream = 
            oldStream // No stream changes in PLAIN mech
        member x.GetAuthorizeId context = 
            let con = context :?> Context
            match con.RawContext with
            | Some c -> c.Authorization
            | None -> failwith "not authorized"

        member x.Name with get () = name
type PlainClient (authzid:string, authcid:string, passwd:string) =
    let authData = 
        let zidBytes = System.Text.Encoding.UTF8.GetBytes authzid
        let cidBytes = System.Text.Encoding.UTF8.GetBytes authcid
        let pwBytes = System.Text.Encoding.UTF8.GetBytes passwd
        let mem = new System.IO.MemoryStream()
        mem.Write(zidBytes, 0, zidBytes.Length)
        mem.WriteByte 0uy
        mem.Write(cidBytes, 0, cidBytes.Length)
        mem.WriteByte 0uy
        mem.Write(pwBytes, 0, pwBytes.Length)
        mem.ToArray()

    let name = "PLAIN"
    interface IClientMechanism with            
        member x.GetNextMessage oldData =
            match oldData with
            | None ->
                Context.Empty, Auth(name, Some authData)
            | Some (context, server) ->
                failwith "should not happen (success or failure expected)"
        member x.UpdateStream (context, data) stream = 
            stream // No stream changes in PLAIN mech
        member x.Name with get() = name













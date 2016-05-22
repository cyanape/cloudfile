%%% -*- erlang -*-
%%%-------------------------------------------------------------------
%%% @author Evangelos Pappas <epappas@evalonlabs.com>
%%% @copyright (C) 2014, evalonlabs
%%% Copyright 2015, evalonlabs
%%%
%%% Licensed under the Apache License, Version 2.0 (the 'License');
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an 'AS IS' BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(oukey).
-author("epappas").

-export([
    generate/1,
    fetch/2,
    get/2,
    store/3
]).

-include("cfuser.hrl").

%%%===================================================================
%%% API
%%%===================================================================

generate({ukey, UKey}) ->
    generate(#oukey_generate{ukey = UKey,
        userPrimeBytes = ?User_Prime_Bytes,
        userGenerator = ?User_Generator, factor = ?Factor,
        version = ?User_SRP_Version, userRSABits = ?User_RSA_Bits
    });

generate(#oukey_generate{ukey = UKey,
    userPrimeBytes = UserPrimeBytes, userGenerator = UserGenerator,
    factor = Factor, version = Version, userRSABits = UserRSABits
}) ->

    SrpSalt = srp:new_salt(),
    OSalt = srp:new_salt(),
    OUKey = srp:new_salt(),
    Secret = ds_util:hashPass(srp:new_salt(), OSalt, 2),

    [OPrime, OGenerator] = srp:prime(UserPrimeBytes, UserGenerator),
    ODerivedKey = srp:derived_key(OSalt, OUKey, Secret, Factor),
    OVerifier = srp:verifier(OGenerator, ODerivedKey, OPrime),
    {_, OPrivKey} = crypto:generate_key(srp, {user, [OGenerator, OPrime, Version]}),

    {privKey, ORsaPrivKey} = sign:generate_rsa(private, UserRSABits),

    % ?couch_oukeys
    OUKeyDoc = {[
        {<<"_id">>, list_to_binary(OUKey)},
        {<<"key">>, UKey},
        {<<"openkey">>, list_to_binary(OUKey)},
        {<<"scope">>, jiffy:encode(?Scope_all)}
    ]},

    % ?couch_salts
    SaltDoc = {[
        {<<"_id">>, list_to_binary(OUKey)},
        {<<"key">>, list_to_binary(OUKey)},
        {<<"salt">>, list_to_binary(OSalt)}
    ]},

    % ?couch_secrets
    SecretDoc = {[
        {<<"_id">>, list_to_binary(OUKey)},
        {<<"key">>, list_to_binary(OUKey)},
        {<<"srpsalt">>, base64:encode(SrpSalt)},
        {<<"verifier">>, base64:encode(OVerifier)},
        {<<"prime">>, base64:encode(OPrime)},
        {<<"generator">>, OGenerator},
        {<<"userPrimeBytes">>, UserPrimeBytes},
        {<<"userGenerator">>, UserGenerator},
        {<<"version">>, Version},
        {<<"privKey">>, base64:encode(OPrivKey)},
        {<<"factor">>, Factor}
    ]},

    % ?couch_rsa
    RSADoc = {[
        {<<"_id">>, list_to_binary(OUKey)},
        {<<"key">>, list_to_binary(OUKey)},
        {<<"rsaPrivKey">>, base64:encode(ORsaPrivKey)},
        {<<"rsaBits">>, UserRSABits}
    ]},

    {ok, #oukey_generate_rsp{
        oukey = list_to_binary(OUKey), secret = list_to_binary(Secret),
        oukey_doc = OUKeyDoc, salt_doc = SaltDoc, secret_doc = SecretDoc,
        rsa_doc = RSADoc
    }}.

fetch(oukey, {ukey, UKey}) ->
    case cfstore:fetch(?couch_oukeys, {?couch_oukeys_design, ?couch_oukeys_design_view}, [{key, UKey}]) of
        {ok, OUKeyDocList} -> {ok, OUKeyDocList};
        {error, Error} -> {error, Error}
    end.

get(oukey, {oukey, OUKey}) ->
    case cfstore:get(?couch_oukeys, OUKey) of
        {ok, OUKeyDoc} -> {ok, OUKeyDoc};
        {error, Error} -> {error, Error}
    end;
get(user, {oukey, OUKey}) ->
    {ok, {OUKeyKVList}} = get(oukey, {oukey, OUKey}),
    UKey = proplists:get_value(<<"key">>, OUKeyKVList),
    ukey:get(user, {ukey, UKey});
get(salt, {oukey, OUKey}) ->
    case cfstore:get(?couch_salts, OUKey) of
        {ok, SaltDoc} -> {ok, SaltDoc};
        {error, Error} -> {error, Error}
    end;
get(secrets, {oukey, OUKey}) ->
    case cfstore:get(?couch_secrets, OUKey) of
        {ok, SecretDoc} -> {ok, SecretDoc};
        {error, Error} -> {error, Error}
    end;
get(rsa, {oukey, OUKey}) ->
    case cfstore:get(?couch_rsa, OUKey) of
        {ok, RSADoc} -> {ok, RSADoc};
        {error, Error} -> {error, Error}
    end.

store(oukey, _Id, Doc) -> cfstore:save(?couch_oukeys, Doc);
store(salt, _Id, Doc) -> cfstore:save(?couch_salts, Doc);
store(secrets, _Id, Doc) -> cfstore:save(?couch_secrets, Doc);
store(rsa, _Id, Doc) -> cfstore:save(?couch_rsa, Doc).

%%%===================================================================
%%% Internal functions
%%%===================================================================

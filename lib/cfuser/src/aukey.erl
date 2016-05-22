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
-module(aukey).
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

generate({oukey, OUKey}) ->
    generate(#aukey_generate{oukey = OUKey,
        userPrimeBytes = ?User_Prime_Bytes,
        userGenerator = ?User_Generator, factor = ?Factor,
        version = ?User_SRP_Version, userRSABits = ?User_RSA_Bits
    });

generate(#aukey_generate{oukey = OUKey,
    userPrimeBytes = UserPrimeBytes,
    userGenerator = UserGenerator, factor = Factor,
    version = Version, userRSABits = UserRSABits
}) ->

    SrpSalt = srp:new_salt(),
    ASalt = srp:new_salt(),
    AUKey = srp:new_salt(),
    ASecret = ds_util:hashPass(srp:new_salt(), ASalt, 2),

    [APrime, AGenerator] = srp:prime(UserPrimeBytes, UserGenerator),
    ADerivedKey = srp:derived_key(ASalt, AUKey, ASecret, Factor),
    AVerifier = srp:verifier(AGenerator, ADerivedKey, APrime),
    {_, APrivKey} = crypto:generate_key(srp, {user, [AGenerator, APrime, Version]}),

    {privKey, ARsaPrivKey} = sign:generate_rsa(private, UserRSABits),

    % ?couch_aukeys
    AUKeyDoc = {[
        {<<"_id">>, list_to_binary(AUKey)},
        {<<"key">>, OUKey},
        {<<"accesskey">>, list_to_binary(AUKey)},
        {<<"scope">>, jiffy:encode(?Scope_all)}
    ]},

    % ?couch_salts
    SaltDoc = {[
        {<<"_id">>, list_to_binary(AUKey)},
        {<<"key">>, list_to_binary(AUKey)},
        {<<"salt">>, list_to_binary(ASalt)}
    ]},

    % ?couch_secrets
    SecretDoc = {[
        {<<"_id">>, list_to_binary(AUKey)},
        {<<"key">>, list_to_binary(AUKey)},
        {<<"srpsalt">>, base64:encode(SrpSalt)},
        {<<"verifier">>, base64:encode(AVerifier)},
        {<<"prime">>, base64:encode(APrime)},
        {<<"generator">>, AGenerator},
        {<<"userPrimeBytes">>, UserPrimeBytes},
        {<<"userGenerator">>, UserGenerator},
        {<<"version">>, Version},
        {<<"privKey">>, base64:encode(APrivKey)},
        {<<"factor">>, Factor}
    ]},

    % ?couch_rsa
    RSADoc = {[
        {<<"_id">>, list_to_binary(AUKey)},
        {<<"key">>, list_to_binary(AUKey)},
        {<<"rsaPrivKey">>, base64:encode(ARsaPrivKey)},
        {<<"rsaBits">>, UserRSABits}
    ]},

    {ok, #aukey_generate_rsp{
        aukey = list_to_binary(AUKey), asecret = list_to_binary(ASecret),
        aukey_doc = AUKeyDoc, salt_doc = SaltDoc, secret_doc = SecretDoc,
        rsa_doc = RSADoc
    }}.


fetch(aukey, {oukey, OUKey}) ->
    case cfstore:fetch(?couch_aukeys, {?couch_aukeys_design, ?couch_aukeys_design_view}, [{key, OUKey}]) of
        {ok, AUKeyDocList} -> {ok, AUKeyDocList};
        {error, Error} -> {error, Error}
    end.

get(aukey, {aukey, AUKey}) ->
    case cfstore:get(?couch_aukeys, AUKey) of
        {ok, AUKeyDoc} -> {ok, AUKeyDoc};
        {error, Error} -> {error, Error}
    end;
get(user, {aukey, AUKey}) ->
    {ok, {AUKeyKVList}} = get(aukey, {aukey, AUKey}),
    OUKey = proplists:get_value(<<"key">>, AUKeyKVList),
    {ok, {OUKeyKVList}} = oukey:get(oukey, {oukey, OUKey}),
    UKey = proplists:get_value(<<"key">>, OUKeyKVList),
    ukey:get(user, {ukey, UKey});
get(salt, {aukey, AUKey}) ->
    case cfstore:get(?couch_salts, AUKey) of
        {ok, SaltDoc} -> {ok, SaltDoc};
        {error, Error} -> {error, Error}
    end;
get(secrets, {aukey, AUKey}) ->
    case cfstore:get(?couch_secrets, AUKey) of
        {ok, SecretDoc} -> {ok, SecretDoc};
        {error, Error} -> {error, Error}
    end;
get(rsa, {aukey, AUKey}) ->
    case cfstore:get(?couch_rsa, AUKey) of
        {ok, RSADoc} -> {ok, RSADoc};
        {error, Error} -> {error, Error}
    end.

store(aukey, _Id, Doc) -> cfstore:save(?couch_aukeys, Doc);
store(salt, _Id, Doc) -> cfstore:save(?couch_salts, Doc);
store(secrets, _Id, Doc) -> cfstore:save(?couch_secrets, Doc);
store(rsa, _Id, Doc) -> cfstore:save(?couch_rsa, Doc).

%%%===================================================================
%%% Internal functions
%%%===================================================================

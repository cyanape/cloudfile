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
    get_aukey/1,
    srp_essentials/1
]).

-include("cfuser.hrl").

%%%===================================================================
%%% API
%%%===================================================================

generate(#aukey_generate{oukey = OUKey,
    userPrimeBytes = UserPrimeBytes,
    userGenerator = UserGenerator, factor = Factor,
    version = Version, userRSABits = UserRSABits
}) ->

    SrpSalt = srp_server:new_salt(),
    ASalt = srp_server:new_salt(),
    AUKey = srp_server:new_salt(),
    ASecret = ds_util:hashPass(srp_server:new_salt(), ASalt, 2),

    [APrime, AGenerator] = srp_server:prime(UserPrimeBytes, UserGenerator),
    ADerivedKey = srp_server:derived_key(ASalt, AUKey, ASecret, Factor),
    AVerifier = srp_server:verifier(AGenerator, ADerivedKey, APrime),
    {_, APrivKey} = crypto:generate_key(srp, {user, [AGenerator, APrime, Version]}),

    {privKey, ARsaPrivKey} = sign_server:generate_rsa(private, UserRSABits),

    cfstore:save(?couch_aukeys, {[
        {<<"_id">>, list_to_binary(AUKey)},
        {<<"key">>, OUKey},
        {<<"accesskey">>, list_to_binary(AUKey)},
        {<<"scope">>, jiffy:encode(?Scope_all)}
    ]}),
    cfstore:save(?couch_salts, {[
        {<<"_id">>, list_to_binary(AUKey)},
        {<<"key">>, list_to_binary(AUKey)},
        {<<"salt">>, list_to_binary(ASalt)}
        ]}),
    cfstore:save(?couch_secrets, {[
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
    ]}),
    cfstore:save(?couch_rsa, {[
        {<<"_id">>, list_to_binary(AUKey)},
        {<<"key">>, list_to_binary(AUKey)},
        {<<"rsaPrivKey">>, base64:encode(ARsaPrivKey)},
        {<<"rsaBits">>, UserRSABits}
    ]}),

    {ok, #aukey_generate_rsp{aukey = list_to_binary(AUKey), asecret = list_to_binary(ASecret)}}.

get_aukey({aukey, AUkey}) ->
    case cfstore:get(?couch_aukeys, AUkey) of
        {error, Error} -> {error, Error};
        {ok, DocJson} ->
            {DocKVList} = DocJson,
            {ok, [
                {aukey, proplists:get_value(<<"accesskey">>, DocKVList)},
                {oukey, proplists:get_value(<<"key">>, DocKVList)},
                {scope, proplists:get_value(<<"scope">>, DocKVList)}
            ]};
        Error -> {error, Error}
  end.

srp_essentials(Key) ->
    case cfstore:get(?couch_secrets, Key) of
        {error, Error} -> {error, Error};
        {ok, EssentialsJson} ->
            {EssentialsKVList} = EssentialsJson,
            {ok, EssentialsKVList};
        Error -> {error, Error}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

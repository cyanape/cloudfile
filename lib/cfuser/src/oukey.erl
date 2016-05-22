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
    get_ukey/1,
    srp_essentials/1
]).

-include("cfuser.hrl").

%%%===================================================================
%%% API
%%%===================================================================

generate(#oukey_generate{ukey = UKey,
    email = Email, userPrimeBytes = UserPrimeBytes,
    userGenerator = UserGenerator, factor = Factor,
    version = Version, userRSABits = UserRSABits
}) ->

    SrpSalt = srp_server:new_salt(),
    OSalt = srp_server:new_salt(),
    OUKey = srp_server:new_salt(),
    Secret = ds_util:hashPass(srp_server:new_salt(), OSalt, 2),

    [OPrime, OGenerator] = srp_server:prime(UserPrimeBytes, UserGenerator),
    ODerivedKey = srp_server:derived_key(OSalt, OUKey, Secret, Factor),
    OVerifier = srp_server:verifier(OGenerator, ODerivedKey, OPrime),
    {_, OPrivKey} = crypto:generate_key(srp, {user, [OGenerator, OPrime, Version]}),

    {privKey, ORsaPrivKey} = sign_server:generate_rsa(private, UserRSABits),

    cfstore:save(?couch_oukeys, {[
        {<<"_id">>, list_to_binary(OUKey)},
        {<<"key">>, UKey},
        {<<"email">>, Email},
        {<<"openkey">>, list_to_binary(OUKey)},
        {<<"scope">>, jiffy:encode(?Scope_all)}
    ]}),
    cfstore:save(?couch_salts, {[
        {<<"_id">>, list_to_binary(OUKey)},
        {<<"key">>, list_to_binary(OUKey)},
        {<<"salt">>, list_to_binary(OSalt)}
    ]}),
    cfstore:save(?couch_secrets, {[
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
    ]}),
    cfstore:save(?couch_rsa, {[
        {<<"_id">>, list_to_binary(OUKey)},
        {<<"key">>, list_to_binary(OUKey)},
        {<<"rsaPrivKey">>, base64:encode(ORsaPrivKey)},
        {<<"rsaBits">>, UserRSABits}
    ]}),

  {ok, #oukey_generate_rsp{oukey = list_to_binary(OUKey), secret = list_to_binary(Secret)}}.

get_ukey({oukey, OUkey}) ->
    case cfstore:get(?couch_oukeys, OUkey) of
        {error, _Error} -> {error, "Uknown Key"};
        {ok, OUKeyJson} ->
            {OUKeyKVList} = OUKeyJson,
            Ukey = proplists:get_value(<<"key">>, OUKeyKVList),
            {ok, Ukey};
        _ -> {error, "Uknown Key"}
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

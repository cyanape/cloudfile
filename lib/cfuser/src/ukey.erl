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
-module(ukey).
-author("epappas").

-export([
    generate/1,
    check/1,
    get_ukey/1,
    srp_essentials/1
]).

-include("cfuser.hrl").

%%%===================================================================
%%% API
%%%===================================================================

generate(#ukey_generate{email = Email,
    userPrimeBytes = UserPrimeBytes,
    userGenerator = UserGenerator, factor = Factor,
    version = Version, userRSABits = UserRSABits
}) ->

    MD5Key = hash_md5:build(Email),

    SrpSalt = srp_server:new_salt(),
    UKey = srp_server:new_salt(),
    Salt = srp_server:new_salt(),
    Password = srp_server:new_salt(), %% noone will know this password

    [Prime, Generator] = srp_server:prime(UserPrimeBytes, UserGenerator),
    DerivedKey = srp_server:derived_key(Salt, Email, Password, Factor),
    Verifier = srp_server:verifier(Generator, DerivedKey, Prime),
    {_, PrivKey} = crypto:generate_key(srp, {user, [Generator, Prime, Version]}),

    {privKey, RsaPrivKey} = sign_server:generate_rsa(private, UserRSABits),

    cfstore:save(?couch_users, {[
        {<<"_id">>, list_to_binary(UKey)},
        {<<"key">>, list_to_binary(UKey)},
        {<<"email">>, list_to_binary(Email)},
        {<<"alias">>, [list_to_binary(Email)]}
    ]}),

    cfstore:save(?couch_salts, {[
        {<<"_id">>, list_to_binary(UKey)},
        {<<"key">>, list_to_binary(UKey)},
        {<<"salt">>, list_to_binary(Salt)}
    ]}),

    cfstore:save(?couch_secrets, {[
        {<<"_id">>, list_to_binary(UKey)},
        {<<"key">>, list_to_binary(UKey)},
        {<<"srpsalt">>, base64:encode(SrpSalt)},
        {<<"verifier">>, base64:encode(Verifier)},
        {<<"prime">>, base64:encode(Prime)},
        {<<"generator">>, Generator},
        {<<"userPrimeBytes">>, UserPrimeBytes},
        {<<"userGenerator">>, UserGenerator},
        {<<"version">>, Version},
        {<<"privKey">>, base64:encode(PrivKey)},
        {<<"factor">>, Factor}
    ]}),

    cfstore:save(?couch_rsa, {[
        {<<"_id">>, list_to_binary(UKey)},
        {<<"key">>, list_to_binary(UKey)},
        {<<"rsaPrivKey">>, base64:encode(RsaPrivKey)},
        {<<"rsaBits">>, UserRSABits}
    ]}),

    cfstore:save(?couch_md5keys, {[
        {<<"_id">>, list_to_binary(MD5Key)},
        {<<"key">>, list_to_binary(UKey)}
    ]}),

    {ok, #ukey_generate_rsp{email = list_to_binary(Email), ukey = list_to_binary(UKey)}}.

check(Email) ->
    MD5Key = hash_md5:build(Email),
    %% TODO implement HEAD req instead of GET
    case cfstore:get(?couch_md5keys, MD5Key) of
        {error, _Error} -> %% User Should not exist
            {ok, {nonexist, {key, MD5Key}}};
        _ ->
            {ok, {exist, {key, MD5Key}}}
  end.

get_ukey({email, Email}) ->
    MD5Key = hash_md5:build(Email),

    case cfstore:get(?couch_md5keys, MD5Key) of
        {ok, DocJson} ->
            {DocKVList} = DocJson,
            UKey = proplists:get_value(<<"key">>, DocKVList),
            {ok, UKey};
        {error, Error} ->
            {error, Error}
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

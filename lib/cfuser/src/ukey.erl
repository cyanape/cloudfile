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
    get/2,
    store/3
]).

-include("cfuser.hrl").

%%%===================================================================
%%% API
%%%===================================================================

generate({email, Email}) ->
    generate(#ukey_generate{email = Email,
        userPrimeBytes = ?User_Prime_Bytes,
        userGenerator = ?User_Generator, factor = ?Factor,
        version = ?User_SRP_Version, userRSABits = ?User_RSA_Bits
    });

generate(#ukey_generate{email = Email,
    userPrimeBytes = UserPrimeBytes,
    userGenerator = UserGenerator, factor = Factor,
    version = Version, userRSABits = UserRSABits
}) ->

    % hushkie -> woof woof!
    HashKey = crypto_util:hash_mail(Email),

    SrpSalt = srp:new_salt(),
    UKey = srp:new_salt(),
    Salt = srp:new_salt(),
    Password = srp:new_salt(), %% noone will know this password

    [Prime, Generator] = srp:prime(UserPrimeBytes, UserGenerator),
    DerivedKey = srp:derived_key(Salt, Email, Password, Factor),
    Verifier = srp:verifier(Generator, DerivedKey, Prime),
    {_, PrivKey} = crypto:generate_key(srp, {user, [Generator, Prime, Version]}),

    {privKey, RsaPrivKey} = sign:generate_rsa(private, UserRSABits),

    % ?couch_users
    UserDoc = {[
        {<<"_id">>, list_to_binary(UKey)},
        {<<"key">>, list_to_binary(UKey)},
        {<<"email">>, list_to_binary(Email)},
        {<<"alias">>, [list_to_binary(Email)]}
    ]},

    % ?couch_salts
    SaltDoc = {[
        {<<"_id">>, list_to_binary(UKey)},
        {<<"key">>, list_to_binary(UKey)},
        {<<"salt">>, list_to_binary(Salt)}
    ]},

    % ?couch_secrets
    SecretDoc = {[
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
    ]},

    % ?couch_rsa
    RSADoc = {[
        {<<"_id">>, list_to_binary(UKey)},
        {<<"key">>, list_to_binary(UKey)},
        {<<"rsaPrivKey">>, base64:encode(RsaPrivKey)},
        {<<"rsaBits">>, UserRSABits}
    ]},

    % ?couch_md5keys
    MD5Doc = {[
        {<<"_id">>, list_to_binary(HashKey)},
        {<<"key">>, list_to_binary(UKey)}
    ]},

    {ok, #ukey_generate_rsp{
        email = list_to_binary(Email), ukey = list_to_binary(UKey),
        hash_key = list_to_binary(HashKey),
        user_doc = UserDoc, salt_doc = SaltDoc, secret_doc = SecretDoc,
        rsa_doc = RSADoc, md5_doc = MD5Doc
    }}.

get(email, {email, Email}) -> {ok, crypto_util:hash_mail(Email)};
get(salt, {ukey, UKey}) ->
    case cfstore:get(?couch_salts, UKey) of
        {ok, SaltDoc} -> {ok, SaltDoc};
        {error, Error} -> {error, Error}
    end;
get(secrets, {ukey, UKey}) ->
    case cfstore:get(?couch_secrets, UKey) of
        {ok, SecretDoc} -> {ok, SecretDoc};
        {error, Error} -> {error, Error}
    end;
get(rsa, {ukey, UKey}) ->
    case cfstore:get(?couch_rsa, UKey) of
        {ok, RSADoc} -> {ok, RSADoc};
        {error, Error} -> {error, Error}
    end;
get(user, {ukey, UKey}) ->
    case cfstore:get(?couch_users, UKey) of
        {ok, UserDoc} -> {ok, UserDoc};
        {error, Error} -> {error, Error}
    end;
get(ukey, {email, Email}) ->
    {ok, HashKey} = get(email, {email, Email}),

    case cfstore:get(?couch_md5keys, HashKey) of
        {ok, MD5Doc} -> {ok, MD5Doc};
        {error, Error} -> {error, Error}
    end.

store(user, _Id, UserDoc) -> cfstore:save(?couch_users, UserDoc);
store(salt, _Id, SaltDoc) -> cfstore:save(?couch_salts, SaltDoc);
store(secrets, _Id, SecretDoc) -> cfstore:save(?couch_secrets, SecretDoc);
store(rsa, _Id, RSADoc) -> cfstore:save(?couch_rsa, RSADoc);
store(ukey, _Id, MD5Doc) -> cfstore:couch_md5keys(?couch_md5keys, MD5Doc).

%%%===================================================================
%%% Internal functions
%%%===================================================================
